from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from armory2.armory_main.models import Port, Domain, IPAddress, Vulnerability
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
    'critical': 'bg-red-900/50 text-red-200 border-red-700',
    'high':     'bg-orange-900/50 text-orange-200 border-orange-700',
    'medium':   'bg-yellow-900/50 text-yellow-200 border-yellow-700',
    'low':      'bg-blue-900/50 text-blue-200 border-blue-700',
    'info':     'bg-gray-700/50 text-gray-300 border-gray-600',
}


def _process_nuclei(nuclei_meta):
    raw = sorted(
        nuclei_meta.items(),
        key=lambda x: _NUCLEI_SEV_SORT.index(x[1].get('info', {}).get('severity', 'info').lower())
        if x[1].get('info', {}).get('severity', 'info').lower() in _NUCLEI_SEV_SORT else len(_NUCLEI_SEV_SORT)
    )
    findings = []
    for name, f in raw:
        sev = f.get('info', {}).get('severity', 'info').lower()
        findings.append({
            'name': name,
            'severity': sev,
            'style': _NUCLEI_SEV_STYLES.get(sev, _NUCLEI_SEV_STYLES['info']),
            'description': f.get('info', {}).get('description', ''),
            'matched_at': f.get('matched-at', ''),
            'extracted_results': f.get('extracted-results', []),
            'id': str(uuid.uuid1()),
        })
    return findings


@register.filter
def tool_base_name(tool_name):
    """Normalize tool name: strip Nessus/Nuclei severity suffix, map FFuF-empty → FFuF."""
    if tool_name.startswith('Nessus'):
        return 'Nessus'
    if tool_name.startswith('Nuclei'):
        return 'Nuclei'
    if tool_name == 'FFuF-empty':
        return 'FFuF'
    return tool_name


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def index(request):
    return render(request, 'host_summary/index.html', {'title': 'Host Summary'})


def get_hosts(request):
    scope_type = request.POST.get('scope', 'active')
    search = request.POST.get('search')
    page = int(request.POST.get('page', '1'))
    entries = int(request.POST.get('entries', '50'))

    display_notes = request.POST.get('display_notes')
    display_all = request.POST.get('display_all')
    display_zero = request.POST.get('display_zero')
    display_complete = request.POST.get('display_completed')

    ffuf = display_all or request.POST.get('display_ffuf')
    gowitness = display_all or request.POST.get('display_gowitness')
    nessus = display_all or request.POST.get('display_nessus')

    ips, total = IPAddress.get_sorted(
        scope_type=scope_type, search=search,
        display_zero=display_zero, page_num=page, entries=entries
    )

    total_pages = max(1, int((total - 1) / entries) + 1) if total > 0 else 1

    page_data = {
        'prev': page > 1,
        'next': page < total_pages,
        'pages_high': [i for i in range(page + 1, page + 6) if i <= total_pages],
        'pages_low': [i for i in range(page - 5, page) if i >= 1],
        'current_page': page,
        'last_page': total_pages,
        'prev_page': page - 1 if page > 1 else 1,
        'next_page': page + 1 if page < total_pages else total_pages,
    }

    data = {}
    nmap_inline = {}
    nuclei_inline = {}
    good_ips = []

    for ip in ips:
        if display_complete or not ip.completed:
            for p in ip.port_set.all():
                if p.port_number > 0 or display_zero:
                    if ip not in good_ips:
                        good_ips.append(ip)
                    data[p.id] = []

                    if nessus and p.vulnerability_set.exists():
                        highest_severity = max(v.severity for v in p.vulnerability_set.all())
                        data[p.id].append(f'Nessus{highest_severity}')

                    if p.meta.get('nmap_scripts'):
                        data[p.id].append('Nmap')
                        nmap_inline[p.id] = {
                            d: {'text': v, 'id': str(uuid.uuid1())}
                            for d, v in p.meta['nmap_scripts'].items()
                            if v and v.strip() not in NMAP_FAILED_STRINGS
                        }

                    if p.meta.get('nuclei'):
                        highest = 0
                        for finding in p.meta['nuclei'].values():
                            sev = finding.get('info', {}).get('severity', 'info').lower()
                            idx = _NUCLEI_SEV_ORDER.index(sev) if sev in _NUCLEI_SEV_ORDER else 0
                            if idx > highest:
                                highest = idx
                        data[p.id].append(f'Nuclei{highest}')
                        nuclei_inline[p.id] = _process_nuclei(p.meta['nuclei'])

                    if p.meta.get('Nikto'):
                        data[p.id].append('Nikto')
                    if gowitness and p.meta.get('Gowitness'):
                        data[p.id].append('Gowitness')
                    if p.meta.get('Xsscrapy'):
                        data[p.id].append('Xsscrapy')
                    if p.meta.get('Xsstrike'):
                        data[p.id].append('Xsstrike')
                    if ffuf and p.meta.get('FFuF'):
                        ffuf_good = False
                        for f in p.meta.get('FFuF'):
                            rel = f.split('armory2/')[1]
                            abs_path = os.path.join(ARMORY_CONFIG['ARMORY_BASE_PATH'], rel)
                            if os.path.exists(abs_path):
                                res = json.load(open(abs_path))
                                if len(res['results']) > 0:
                                    ffuf_good = True
                        data[p.id].append('FFuF' if ffuf_good else 'FFuF-empty')

    return render(request, 'host_summary/host_results.html', {
        'ips': good_ips,
        'data': data,
        'nmap_inline': nmap_inline,
        'nuclei_inline': nuclei_inline,
        'display_notes': display_notes,
        'display_zero': display_zero,
        'page_data': page_data,
    })


def toggle_completed(request, ip_id):
    ip = get_object_or_404(IPAddress, pk=ip_id)
    ip.completed = not ip.completed
    ip.save()
    if ip.completed:
        cls = "px-3 py-1 rounded text-sm font-medium bg-green-700 hover:bg-green-600 text-white"
        label = "Unmark Done"
    else:
        cls = "px-3 py-1 rounded text-sm font-medium bg-gray-600 hover:bg-gray-500 text-gray-200"
        label = "Mark Done"
    return HttpResponse(
        f'<button class="{cls}" '
        f'hx-get="/host_summary/toggle_completed/{ip.id}" '
        f'hx-swap="outerHTML" hx-target="this">{label}</button>'
    )


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


def get_nessus(request, port_id):
    vulns = Vulnerability.objects.filter(ports__id=port_id).order_by('severity')[::-1]
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
    return render(request, 'host_summary/nessus.html', {'vulns': vulns_obj, 'sev_map': sev_map})


def get_nessus_detail(request, vuln_id):
    pass


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
