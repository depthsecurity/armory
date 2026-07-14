from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from armory2.armory_main.models import Port, Domain, IPAddress, Vulnerability, Tag, VirtualHost
from django.db.models import Q
from django.template.defaulttags import register
import os
from base64 import b64encode
import json
import uuid
import re
from armory2.armory2.settings import ARMORY_CONFIG


@register.filter
def get_item(dictionary, key):
    if dictionary is None:
        return None
    return dictionary.get(key)


@register.filter
def file_exists(file_name):
    return os.path.exists(file_name)


@register.filter
def get_file_data(file_name):
    return "data:image/png;base64," + b64encode(open(file_name, 'rb').read()).decode()


@register.filter
def unique_ffuf(l):
    res = []
    endpoints = []
    for item in l:
        endpoint = item['input']['FUZZ'] if type(item['input']) == dict else item['input']
        if endpoint not in endpoints:
            res.append(item)
            endpoints.append(endpoint)
    return res


NMAP_FAILED_STRINGS = frozenset([
    "Couldn't find any comments.",
    "Couldn't find any CSRF vulnerabilities.",
    "Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.",
    "Couldn't find any DOM based XSS.",
    "ERROR: Script execution failed (use -d to debug)",
    "Couldn't find any feeds.",
    "Please enter the complete path of the directory to save data in.",
    "No mobile version detected.",
    "Couldn't find any cross-domain scripts.",
    "false",
    "Couldn't find any stored XSS vulnerabilities.",
    "No previously reported XSS vuln.",
    "No reply from server (TIMEOUT)",
    "Failed to specify credentials and command to run.",
    "FAILED: No domain specified (use ntdomain argument)",
    'Path "/" does not require authentication',
    "Couldn't find any error pages.",
])

_NUCLEI_SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical']
_NUCLEI_SEV_SORT  = ['critical', 'high', 'medium', 'low', 'info']
_NUCLEI_SEV_STYLES = {
    'critical': 'nuclei-critical',
    'high':     'nuclei-high',
    'medium':   'nuclei-medium',
    'low':      'nuclei-low',
    'info':     'nuclei-info',
}


def _process_nuclei(nuclei_meta):
    raw = sorted(
        nuclei_meta.items(),
        key=lambda x: _NUCLEI_SEV_SORT.index(x[1].get('info', {}).get('severity', 'info').lower())
        if x[1].get('info', {}).get('severity', 'info').lower() in _NUCLEI_SEV_SORT else len(_NUCLEI_SEV_SORT)
    )
    findings = []
    for name, f in raw:
        info = f.get('info', {})
        sev = info.get('severity', 'info').lower()
        classification = info.get('classification', {}) or {}
        refs = info.get('reference', []) or []
        if isinstance(refs, str):
            refs = [refs]
        tags = info.get('tags', '') or ''
        if isinstance(tags, list):
            tags = ', '.join(tags)
        findings.append({
            'name': name,
            'severity': sev,
            'style': _NUCLEI_SEV_STYLES.get(sev, _NUCLEI_SEV_STYLES['info']),
            'description': info.get('description', ''),
            'remediation': info.get('remediation', ''),
            'tags': tags,
            'references': refs,
            'cvss_score': classification.get('cvss-score', ''),
            'cvss_metrics': classification.get('cvss-metrics', ''),
            'cve_id': classification.get('cve-id', ''),
            'cwe_id': classification.get('cwe-id', ''),
            'matched_at': f.get('matched-at', ''),
            'template_id': f.get('template-id', ''),
            'type': f.get('type', ''),
            'matcher_name': f.get('matcher-name', ''),
            'extracted_results': f.get('extracted-results', []) or [],
            'curl_command': f.get('curl-command', ''),
            'request': f.get('request', ''),
            'response': f.get('response', ''),
            'id': str(uuid.uuid1()),
        })
    return findings


@register.filter
def tool_base_name(tool_name):
    """Normalize tool name: strip severity suffix, map FFuF-empty → FFuF."""
    if tool_name.startswith('Nuclei'):
        return 'Nuclei'
    if tool_name == 'FFuF-empty':
        return 'FFuF'
    if tool_name and tool_name[-1] in '01234':
        return tool_name[:-1]
    return tool_name


@register.filter
def is_vuln_source(d):
    """True for {Source}{0-4} items from vulnerability_set (not Nuclei)."""
    if not d or d[-1] not in '01234':
        return False
    return not d[:-1].startswith('Nuclei')


@register.filter
def vuln_source_name(d):
    """'Nessus3' → 'Nessus'"""
    return d[:-1] if d else d


@register.filter
def vuln_source_lower(d):
    """'Nessus3' → 'nessus'"""
    return d[:-1].lower() if d else d


@register.filter
def vuln_source_sev(d):
    """'Nessus3' → 3"""
    try:
        return int(d[-1])
    except (ValueError, IndexError):
        return 0


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def index(request):
    tags = Tag.objects.all().order_by('name')
    vuln_sources = list(
        Vulnerability.objects.values_list('source', flat=True).distinct().order_by('source')
    )
    return render(request, 'host_summary/index.html', {
        'title': 'Host Summary',
        'tags': tags,
        'vuln_sources': vuln_sources,
    })


def _build_port_data(ip, display_zero, nessus, gowitness, ffuf):
    """Collect tool button data for all ports on one IP. Returns (has_ports, data, nmap, nuclei).

    Multiple Port objects may share port_number=0 (e.g. tcp/0 and udp/0 for PTR records).
    All port-0 data is merged into a single canonical entry (the first port-0 port's id) so
    the template renders exactly one set of header buttons regardless of how many port-0 rows exist.
    """
    data = {}
    nmap_inline = {}
    nuclei_inline = {}
    has_ports = False
    canonical_port0_id = None  # first port-0 port's id; subsequent port-0 ports merge here

    for p in ip.port_set.all():
        if p.port_number > 0 or display_zero:
            has_ports = True

        if p.port_number == 0:
            if canonical_port0_id is None:
                canonical_port0_id = p.id
                data[p.id] = []
            target_id = canonical_port0_id
        else:
            data[p.id] = []
            target_id = p.id

        if nessus:
            source_max = {}
            for v in p.vulnerability_set.all():
                src = v.source.lower()
                if src not in source_max or v.severity > source_max[src]:
                    source_max[src] = v.severity
            for src, max_sev in source_max.items():
                cap = src.capitalize()
                new_entry = f'{cap}{max_sev}'
                replaced = False
                for i, t in enumerate(data[target_id]):
                    if t[:-1].lower() == src and t[-1] in '01234':
                        if max_sev > int(t[-1]):
                            data[target_id][i] = new_entry
                        replaced = True
                        break
                if not replaced:
                    data[target_id].append(new_entry)

        if p.meta.get('nmap_scripts'):
            if 'Nmap' not in data[target_id]:
                data[target_id].append('Nmap')
            if target_id not in nmap_inline:
                nmap_inline[target_id] = {}
            nmap_inline[target_id].update({
                d: {'text': v, 'id': str(uuid.uuid1())}
                for d, v in p.meta['nmap_scripts'].items()
                if v and v.strip() not in NMAP_FAILED_STRINGS
            })

        if p.meta.get('nuclei'):
            existing_nuclei_idx = next(
                (i for i, t in enumerate(data[target_id]) if t.startswith('Nuclei')), None
            )
            highest = 0
            for finding in p.meta['nuclei'].values():
                sev = finding.get('info', {}).get('severity', 'info').lower()
                idx = _NUCLEI_SEV_ORDER.index(sev) if sev in _NUCLEI_SEV_ORDER else 0
                if idx > highest:
                    highest = idx
            if existing_nuclei_idx is not None:
                if highest > int(data[target_id][existing_nuclei_idx][-1]):
                    data[target_id][existing_nuclei_idx] = f'Nuclei{highest}'
            else:
                data[target_id].append(f'Nuclei{highest}')
                nuclei_inline[target_id] = _process_nuclei(p.meta['nuclei'])

        if p.meta.get('Nikto') and 'Nikto' not in data[target_id]:
            data[target_id].append('Nikto')
        if gowitness and p.meta.get('Gowitness') and 'Gowitness' not in data[target_id]:
            data[target_id].append('Gowitness')
        if p.meta.get('Xsscrapy') and 'Xsscrapy' not in data[target_id]:
            data[target_id].append('Xsscrapy')
        if p.meta.get('Xsstrike') and 'Xsstrike' not in data[target_id]:
            data[target_id].append('Xsstrike')
        if ffuf and p.meta.get('FFuF'):
            if 'FFuF' not in data[target_id] and 'FFuF-empty' not in data[target_id]:
                ffuf_good = False
                for f in p.meta['FFuF']:
                    rel = f.split('armory2/')[1]
                    abs_path = os.path.join(ARMORY_CONFIG['ARMORY_BASE_PATH'], rel)
                    if os.path.exists(abs_path):
                        res = json.load(open(abs_path))
                        if res['results']:
                            ffuf_good = True
                data[target_id].append('FFuF' if ffuf_good else 'FFuF-empty')

    return has_ports, data, nmap_inline, nuclei_inline


def _make_page_data(page, total, entries):
    total_pages = max(1, (total - 1) // entries + 1) if total > 0 else 1
    return {
        'prev': page > 1,
        'next': page < total_pages,
        'pages_high': [i for i in range(page + 1, page + 6) if i <= total_pages],
        'pages_low': [i for i in range(page - 5, page) if i >= 1],
        'current_page': page,
        'last_page': total_pages,
        'prev_page': page - 1 if page > 1 else 1,
        'next_page': page + 1 if page < total_pages else total_pages,
    }


def get_hosts(request):
    scope_type = request.POST.get('scope', 'active')
    search = request.POST.get('search')
    tag_filter = request.POST.get('tag_filter') or None
    vuln_source = request.POST.get('vuln_source') or None
    page = int(request.POST.get('page', '1'))
    entries = int(request.POST.get('entries', '50'))
    group_by = request.POST.get('group_by', 'ip')

    display_notes = request.POST.get('display_notes')
    display_all = request.POST.get('display_all')
    display_zero = request.POST.get('display_zero')
    display_complete = request.POST.get('display_completed')

    ffuf = display_all or request.POST.get('display_ffuf')
    gowitness = display_all or request.POST.get('display_gowitness')
    nessus = display_all or request.POST.get('display_nessus')

    if group_by == 'domain':
        return _get_hosts_by_domain(
            request, scope_type, search, page, entries,
            display_notes, display_zero, display_complete, ffuf, gowitness, nessus,
            tag_filter=tag_filter, vuln_source=vuln_source,
        )

    ips, total = IPAddress.get_sorted(
        scope_type=scope_type, search=search,
        display_zero=display_zero, page_num=page, entries=entries,
        tag_filter=tag_filter, vuln_source=vuln_source,
    )

    page_data = _make_page_data(page, total, entries)

    data = {}
    nmap_inline = {}
    nuclei_inline = {}
    good_ips = []

    for ip in ips:
        if display_complete or not ip.completed:
            has_ports, pd, nm, nu = _build_port_data(ip, display_zero, nessus, gowitness, ffuf)
            if has_ports:
                good_ips.append(ip)
                data.update(pd)
                nmap_inline.update(nm)
                nuclei_inline.update(nu)

    return render(request, 'host_summary/host_results.html', {
        'ips': good_ips,
        'data': data,
        'nmap_inline': nmap_inline,
        'nuclei_inline': nuclei_inline,
        'display_notes': display_notes,
        'display_zero': display_zero,
        'page_data': page_data,
    })


def _get_hosts_by_domain(request, scope_type, search, page, entries,
                          display_notes, display_zero, display_complete,
                          ffuf, gowitness, nessus, tag_filter=None, vuln_source=None):
    qry = Domain.objects.filter(is_ptr=False)

    if scope_type == 'active':
        qry = qry.filter(active_scope=True)
    elif scope_type == 'passive':
        qry = qry.filter(passive_scope=True)

    if display_zero:
        qry = qry.filter(ip_addresses__isnull=False).distinct()
    else:
        qry = qry.filter(ip_addresses__port__port_number__gt=0).distinct()

    if search:
        qry = qry.filter(
            Q(name__icontains=search) | Q(ip_addresses__ip_address__icontains=search)
        ).distinct()

    if tag_filter:
        qry = qry.filter(tags__name=tag_filter).distinct()

    if vuln_source:
        qry = qry.filter(
            ip_addresses__port__vulnerability__source__iexact=vuln_source
        ).distinct()

    total = qry.count()
    page_data = _make_page_data(page, total, entries)
    domains = list(qry.order_by('name')[(page - 1) * entries: page * entries])

    data = {}
    nmap_inline = {}
    nuclei_inline = {}

    domain_ip_map = {}
    for domain in domains:
        good_ips = []
        for ip in domain.ip_addresses.all():
            if display_complete or not ip.completed:
                has_ports, pd, nm, nu = _build_port_data(ip, display_zero, nessus, gowitness, ffuf)
                if has_ports:
                    good_ips.append(ip)
                    data.update(pd)
                    nmap_inline.update(nm)
                    nuclei_inline.update(nu)
        domain_ip_map[domain.id] = good_ips

    active_entries = [
        {'domain': d, 'ips': domain_ip_map[d.id]}
        for d in domains if d.active_scope and domain_ip_map[d.id]
    ]
    passive_entries = [
        {'domain': d, 'ips': domain_ip_map[d.id]}
        for d in domains if not d.active_scope and d.passive_scope and domain_ip_map[d.id]
    ]

    groups = []
    if active_entries:
        groups.append({'label': 'Active', 'entries': active_entries})
    if passive_entries:
        groups.append({'label': 'Passive', 'entries': passive_entries})

    return render(request, 'host_summary/domain_results.html', {
        'groups': groups,
        'data': data,
        'nmap_inline': nmap_inline,
        'nuclei_inline': nuclei_inline,
        'display_notes': display_notes,
        'display_zero': display_zero,
        'page_data': page_data,
    })


def get_ip_card(request, ip_id):
    ip = get_object_or_404(IPAddress, pk=ip_id)
    display_notes = request.POST.get('display_notes')
    display_zero = request.POST.get('display_zero')
    display_all = request.POST.get('display_all')
    ffuf = display_all or request.POST.get('display_ffuf')
    gowitness = display_all or request.POST.get('display_gowitness')
    nessus = display_all or request.POST.get('display_nessus')
    _, pd, nm, nu = _build_port_data(ip, display_zero, nessus, gowitness, ffuf)
    return render(request, 'host_summary/_ip_card.html', {
        'ip': ip,
        'data': pd,
        'nmap_inline': nm,
        'nuclei_inline': nu,
        'display_notes': display_notes,
        'display_zero': display_zero,
    })


def toggle_completed(request, ip_id):
    ip = get_object_or_404(IPAddress, pk=ip_id)
    ip.completed = not ip.completed
    ip.save()
    if ip.completed:
        cls = "px-3 py-1 rounded text-xs font-medium transition-colors shrink-0 bg-green-600 hover:bg-green-500 dark:bg-green-700 dark:hover:bg-green-600 text-white"
        label = "Unmark Done"
    else:
        cls = "px-3 py-1 rounded text-xs font-medium transition-colors shrink-0 bg-slate-200 dark:bg-slate-600 hover:bg-slate-300 dark:hover:bg-slate-500 text-slate-700 dark:text-slate-200"
        label = "Mark Done"
    return HttpResponse(
        f'<button class="{cls}" '
        f'hx-get="/host_summary/toggle_completed/{ip.id}" '
        f'hx-swap="outerHTML" hx-target="this">{label}</button>'
    )


def toggle_cloud(request, ip_id):
    ip = get_object_or_404(IPAddress, pk=ip_id)
    ip.cloud = not ip.cloud
    ip.save()
    return render(request, 'host_summary/_cloud_toggle.html', {'ip': ip})


def save_notes(request, ip_id):
    ip = get_object_or_404(IPAddress, pk=ip_id)
    ip.notes = request.POST.get('data', '')
    ip.save()
    return HttpResponse('<span class="text-green-400 text-xs">Saved ✓</span>')


def save_service_name(request, port_id):
    if request.method != 'POST':
        return HttpResponse('Method not allowed', status=405)
    service_name = request.POST.get('service_name', '').strip()
    port = get_object_or_404(Port, pk=port_id)
    port.service_name = service_name
    port.save()
    return render(request, 'host_summary/service_name_widget.html', {'port': port})


def get_nmap(request, port_id):
    port_db = get_object_or_404(Port, pk=port_id)
    data = {
        d: {'text': v, 'id': str(uuid.uuid1())}
        for d, v in port_db.meta['nmap_scripts'].items()
        if v and v.strip() not in NMAP_FAILED_STRINGS
    }
    return render(request, 'host_summary/nmap.html', {'data': data})


def get_nuclei(request, port_id):
    port = get_object_or_404(Port, pk=port_id)
    findings = _process_nuclei(port.meta.get('nuclei', {}))
    return render(request, 'host_summary/nuclei.html', {'findings': findings})


def get_vulns(request, source, port_id):
    vulns = Vulnerability.objects.filter(ports__id=port_id, source__iexact=source).order_by('severity')[::-1]
    vulns_obj = {}
    for v in vulns:
        vulns_obj[v.name] = {
            'id': v.id,
            'severity': v.severity,
            'description': v.description,
        }
        vuln_output = v.vulnoutput_set.filter(port_id=port_id)
        vulns_obj[v.name]['detail'] = vuln_output[0].data if vuln_output else ''
    sev_map = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
    return render(request, 'host_summary/nessus.html', {
        'vulns': vulns_obj,
        'sev_map': sev_map,
        'source_title': source.capitalize(),
    })


def get_nessus(request, port_id):
    return get_vulns(request, 'nessus', port_id)


def get_gowitness(request, port_id):
    port = get_object_or_404(Port, pk=port_id)
    return render(request, 'host_summary/gowitness.html', {'port': port})


def get_nikto(request, port_id):
    port = get_object_or_404(Port, pk=port_id)
    data = {}
    for f, v in port.meta['Nikto'].items():
        text = ''
        for fl in v:
            if os.path.exists(fl):
                text += open(fl).read() + '\n'
        data[f] = {'text': text, 'id': str(uuid.uuid1())}
    return render(request, 'host_summary/nikto.html', {'data': data})


def get_xsstrike(request, port_id):
    port = get_object_or_404(Port, pk=port_id)
    data = {}
    for f, v in port.meta['Xsstrike'].items():
        text = ''
        for fl in v:
            if os.path.exists(fl):
                text += escape_ansi(open(fl).read()) + '\n'
        data[f] = {'text': text, 'id': str(uuid.uuid1())}
    return render(request, 'host_summary/xsstrike.html', {'data': data})


def get_xsscrapy(request, port_id):
    port = get_object_or_404(Port, pk=port_id)
    data = {}
    for f, v in port.meta['Xsscrapy'].items():
        text = ''
        for fl in v:
            if os.path.exists(fl):
                text += open(fl).read() + '\n'
        data[f] = {'text': text, 'id': str(uuid.uuid1())}
    return render(request, 'host_summary/xsscrapy.html', {'data': data})


def get_ffuf(request, port_id):
    max_status = 10
    port = get_object_or_404(Port, pk=port_id)
    ffuf_data = {}

    for f in port.meta['FFuF']:
        rel = f.split('armory2/')[1]
        abs_path = os.path.join(ARMORY_CONFIG['ARMORY_BASE_PATH'], rel)
        if not os.path.exists(abs_path):
            continue
        data = json.loads(open(abs_path).read())

        if data.get('config'):
            url = data['config']['url']
        else:
            url = data['commandline'].split(' -u ')[1].split(' ')[0]
            if 'FUZZ' in url:
                url = url.replace('FUZZ', '')

        for r in data['results']:
            url_orig = r['url'] if r.get('url') else os.path.join(url, r['input'])
            host = url_orig.split('/')[2].split(':')[0]

            ffuf_data.setdefault(host, {}).setdefault(url, {})

            if r['status'] not in ffuf_data[host][url]:
                ffuf_data[host][url][r['status']] = []

            bucket = ffuf_data[host][url][r['status']]
            if len(bucket) < max_status and r not in bucket:
                input_val = r['input']['FUZZ'] if type(r['input']) == dict else r['input']
                bucket.append({'url': url_orig, 'input': input_val, 'length': r['length']})

    return render(request, 'host_summary/ffuf.html', {'ffuf_data': ffuf_data})


def _tag_modal_context(obj_type, obj_id):
    if obj_type == 'ip':
        obj = get_object_or_404(IPAddress, pk=obj_id)
        label = obj.ip_address
        tag_types = ['ip', 'any']
    elif obj_type == 'port':
        obj = get_object_or_404(Port, pk=obj_id)
        label = f"{obj.port_number}/{obj.proto}"
        tag_types = ['ip', 'any']
    elif obj_type == 'domain':
        obj = get_object_or_404(Domain, pk=obj_id)
        label = obj.name
        tag_types = ['domain', 'any']
    else:
        return None, None
    current_tags = obj.tags.all()
    available_tags = Tag.objects.filter(type__in=tag_types).exclude(pk__in=current_tags)
    return obj, {
        'obj_type': obj_type,
        'obj_id': obj_id,
        'label': label,
        'current_tags': current_tags,
        'available_tags': available_tags,
    }


def get_tag_modal(request, obj_type, obj_id):
    _, ctx = _tag_modal_context(obj_type, obj_id)
    if ctx is None:
        return HttpResponse('Invalid type', status=400)
    return render(request, 'host_summary/tag_modal.html', ctx)


def add_tag(request, obj_type, obj_id):
    tag_name = request.POST.get('tag_name', '').strip()
    if tag_name:
        tag, _ = Tag.objects.get_or_create(name=tag_name, defaults={'type': Tag.TYPE_ANY})
        if obj_type == 'ip':
            get_object_or_404(IPAddress, pk=obj_id).tags.add(tag)
        elif obj_type == 'port':
            get_object_or_404(Port, pk=obj_id).tags.add(tag)
        elif obj_type == 'domain':
            get_object_or_404(Domain, pk=obj_id).tags.add(tag)
    _, ctx = _tag_modal_context(obj_type, obj_id)
    if ctx is None:
        return HttpResponse('Invalid type', status=400)
    return render(request, 'host_summary/tag_modal.html', ctx)


def _vhost_group(ip, name):
    """Active VirtualHost rows for one hostname on one IP (one row per port)."""
    return VirtualHost.objects.filter(ip_address=ip, name=name, active=True)


def _vhost_group_scope(vhosts):
    """Collapse scope across a virtualhost group: in-scope if any row is."""
    return (
        any(v.active_scope for v in vhosts),
        any(v.passive_scope for v in vhosts),
    )


def _vhost_group_dict(ip, name):
    """Row-template dict for a virtualhost group (matches get_virtualhost_groups items)."""
    active, passive = _vhost_group_scope(_vhost_group(ip, name))
    return {'name': name, 'active_scope': active, 'passive_scope': passive}


def _ensure_domain(name, active_scope, passive_scope):
    """Return the Domain named `name`, creating it if absent.

    A new Domain is created with the offlinedns marker so its post_save signal
    skips DNS resolution — a rename must not trigger network lookups or pull in
    unrelated IPs.
    """
    domain = Domain.objects.filter(name__iexact=name).first()
    if domain:
        return domain
    d = Domain(
        name=name, whois="", active_scope=active_scope,
        passive_scope=passive_scope, meta={'offlinedns': True},
    )
    d.save()
    return Domain.objects.filter(name=name).first()


def _row_response(request, template, ctx, error=None):
    resp = render(request, template, ctx)
    if error:
        resp['HX-Trigger'] = json.dumps({'hsError': error})
    return resp


def edit_obj(request, obj_type, ident):
    if request.method != 'POST':
        return HttpResponse('Method not allowed', status=405)
    new_name = request.POST.get('new_name', '').strip()

    if obj_type == 'domain':
        domain = get_object_or_404(Domain, pk=ident)
        ip = get_object_or_404(IPAddress, pk=request.POST.get('ip_id'))
        if not new_name or new_name.lower() == domain.name.lower():
            return _row_response(request, 'host_summary/_domain_row.html',
                                 {'domain': domain, 'ip': ip})
        if ip.domain_set.filter(name__iexact=new_name).exists():
            return _row_response(request, 'host_summary/_domain_row.html',
                                 {'domain': domain, 'ip': ip},
                                 error=f'{new_name} is already on {ip.ip_address}.')
        active_scope, passive_scope = domain.active_scope, domain.passive_scope
        domain.delete()
        new_domain = _ensure_domain(new_name, active_scope, passive_scope)
        new_domain.ip_addresses.add(ip)
        return _row_response(request, 'host_summary/_domain_row.html',
                             {'domain': new_domain, 'ip': ip})

    if obj_type == 'vhost':
        ip = get_object_or_404(IPAddress, pk=ident)
        old_name = request.POST.get('name', '')
        group = list(VirtualHost.objects.filter(ip_address=ip, name=old_name))
        if not group:
            return HttpResponse('Not found', status=404)
        if not new_name or new_name.lower() == old_name.lower():
            return _row_response(request, 'host_summary/_vhost_row.html',
                                 {'vh': _vhost_group_dict(ip, old_name), 'ip': ip})
        if VirtualHost.objects.filter(ip_address=ip, name__iexact=new_name).exists():
            return _row_response(request, 'host_summary/_vhost_row.html',
                                 {'vh': _vhost_group_dict(ip, old_name), 'ip': ip},
                                 error=f'{new_name} is already on {ip.ip_address}.')
        active_scope, passive_scope = _vhost_group_scope(group)
        # Pre-create the domain offline so VirtualHost.save() links to it without DNS.
        _ensure_domain(new_name, active_scope, passive_scope)
        for v in group:
            VirtualHost.objects.create(
                ip_address=ip, name=new_name, port=v.port, active=v.active,
                active_scope=active_scope, passive_scope=passive_scope,
            )
        VirtualHost.objects.filter(ip_address=ip, name=old_name).delete()
        return _row_response(request, 'host_summary/_vhost_row.html',
                             {'vh': _vhost_group_dict(ip, new_name), 'ip': ip})

    return HttpResponse('Invalid type', status=400)


def toggle_scope(request, obj_type, ident, scope):
    if request.method != 'POST':
        return HttpResponse('Method not allowed', status=405)
    if scope not in ('active', 'passive'):
        return HttpResponse('Invalid scope', status=400)
    field = 'active_scope' if scope == 'active' else 'passive_scope'

    if obj_type == 'ip':
        ip = get_object_or_404(IPAddress, pk=ident)
        setattr(ip, field, not getattr(ip, field))
        ip.save()
        ctx = {
            'obj_type': 'ip', 'ident': ip.id, 'name': '',
            'active_scope': ip.active_scope, 'passive_scope': ip.passive_scope,
        }
    elif obj_type == 'domain':
        domain = get_object_or_404(Domain, pk=ident)
        setattr(domain, field, not getattr(domain, field))
        domain.save()
        ctx = {
            'obj_type': 'domain', 'ident': domain.id, 'name': '',
            'active_scope': domain.active_scope, 'passive_scope': domain.passive_scope,
        }
    elif obj_type == 'vhost':
        ip = get_object_or_404(IPAddress, pk=ident)
        name = request.POST.get('name', '')
        vhosts = list(_vhost_group(ip, name))
        if not vhosts:
            return HttpResponse('Not found', status=404)
        cur_active, cur_passive = _vhost_group_scope(vhosts)
        new_val = not (cur_active if scope == 'active' else cur_passive)
        for v in vhosts:
            setattr(v, field, new_val)
            v.save()
        active_scope, passive_scope = _vhost_group_scope(_vhost_group(ip, name))
        ctx = {
            'obj_type': 'vhost', 'ident': ip.id, 'name': name,
            'active_scope': active_scope, 'passive_scope': passive_scope,
        }
    else:
        return HttpResponse('Invalid type', status=400)

    return render(request, 'host_summary/_scope_controls.html', ctx)


def delete_obj(request, obj_type, ident):
    if request.method != 'POST':
        return HttpResponse('Method not allowed', status=405)
    if obj_type == 'domain':
        get_object_or_404(Domain, pk=ident).delete()
    elif obj_type == 'vhost':
        ip = get_object_or_404(IPAddress, pk=ident)
        VirtualHost.objects.filter(ip_address=ip, name=request.POST.get('name', '')).delete()
    else:
        return HttpResponse('Invalid type', status=400)
    return HttpResponse('')


def create_obj(request, obj_type, ident):
    if request.method != 'POST':
        return HttpResponse('Method not allowed', status=405)
    if obj_type != 'vhost':
        return HttpResponse('Invalid type', status=400)

    ip = get_object_or_404(IPAddress, pk=ident)
    name = request.POST.get('name', '').strip()
    if not name:
        return HttpResponse('', status=204)
    if VirtualHost.objects.filter(ip_address=ip, name__iexact=name).exists():
        resp = HttpResponse('')
        resp['HX-Trigger'] = json.dumps({'hsError': f'{name} is already on {ip.ip_address}.'})
        return resp

    # Inherit the IP's scope; pre-create the domain offline so the vhost links
    # to it without triggering DNS. Mirror the http ports so the vhost shows up
    # in the per-port HTTP links, matching how vhosts are normally created.
    _ensure_domain(name, ip.active_scope, ip.passive_scope)
    VirtualHost.objects.create(
        ip_address=ip, name=name, port=None, active=True,
        active_scope=ip.active_scope, passive_scope=ip.passive_scope,
    )
    for p in ip.port_set.filter(service_name__icontains='http'):
        VirtualHost.objects.create(
            ip_address=ip, name=name, port=p, active=True,
            active_scope=ip.active_scope, passive_scope=ip.passive_scope,
        )
    return render(request, 'host_summary/_vhost_row.html',
                  {'vh': _vhost_group_dict(ip, name), 'ip': ip})


def remove_tag(request, obj_type, obj_id, tag_id):
    if obj_type == 'ip':
        get_object_or_404(IPAddress, pk=obj_id).tags.remove(tag_id)
    elif obj_type == 'port':
        get_object_or_404(Port, pk=obj_id).tags.remove(tag_id)
    elif obj_type == 'domain':
        get_object_or_404(Domain, pk=obj_id).tags.remove(tag_id)
    _, ctx = _tag_modal_context(obj_type, obj_id)
    if ctx is None:
        return HttpResponse('Invalid type', status=400)
    return render(request, 'host_summary/tag_modal.html', ctx)
