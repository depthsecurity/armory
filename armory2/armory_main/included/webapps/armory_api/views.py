"""
Armory REST API — JSON endpoints designed for MCP tool integration.

All endpoints return JSON. PATCH /hosts/<id> accepts a JSON body.
No authentication is enforced; deploy behind a network boundary or add
Django middleware if public exposure is needed.
"""

import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db.models import Q
from armory2.armory_main.models import (
    IPAddress, Port, Domain, CIDR,
    Vulnerability, VulnOutput,
)

# ── Constants ─────────────────────────────────────────────────────────────────

SEV_LABELS = {0: 'informational', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

ENDPOINTS = {
    'GET  /armory_api/':                  'API root — this document',
    'GET  /armory_api/hosts':             'List IPs. Params: scope, search, page, per_page, completed',
    'GET  /armory_api/hosts/<id>':        'Full IP detail with ports, domains, and virtualhosts',
    'PATCH /armory_api/hosts/<id>':       'Update IP. JSON body: {notes?, completed?}',
    'GET  /armory_api/ports/<id>':        'Port detail with vulns, nmap, and gowitness data',
    'GET  /armory_api/vulns':             'List vulns. Params: severity_min, severity_max, search, ip, exploitable, page, per_page',
    'GET  /armory_api/vulns/<id>':        'Vuln detail with all affected ports',
    'GET  /armory_api/domains':           'List domains. Params: scope, search, page, per_page',
    'GET  /armory_api/cidrs':             'List CIDRs. Params: scope, search, page, per_page',
    'GET  /armory_api/stats':             'Aggregate counts across all entity types',
    'GET  /armory_api/search':            'Cross-entity search. Params: q (required)',
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _paginate(request, default=50, maximum=500):
    try:
        page = max(1, int(request.GET.get('page', 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(maximum, max(1, int(request.GET.get('per_page', default))))
    except (ValueError, TypeError):
        per_page = default
    return page, per_page


def _scope_label(obj):
    if obj.active_scope:
        return 'active'
    if obj.passive_scope:
        return 'passive'
    return 'none'


def _bool_param(request, name):
    """Parse a query param as a boolean. Returns True/False/None."""
    val = request.GET.get(name)
    if val is None:
        return None
    return val.lower() in ('true', '1', 'yes')


def _err(message, status=400):
    return JsonResponse({'error': message}, status=status)


# ── Serializers ───────────────────────────────────────────────────────────────

def _serialize_ip_summary(ip):
    return {
        'id': ip.id,
        'ip_address': ip.ip_address,
        'scope': _scope_label(ip),
        'completed': bool(ip.completed),
        'notes': ip.notes or '',
        'os': ip.os or '',
        'port_count': ip.port_set.count(),
        'domain_count': ip.domain_set.count(),
    }


def _serialize_ip_detail(ip):
    ports = []
    for p in ip.port_set.all():
        vuln_sevs = list(p.vulnerability_set.values_list('severity', flat=True))
        ports.append({
            'id': p.id,
            'port_number': p.port_number,
            'proto': p.proto,
            'service_name': p.service_name,
            'status': p.status,
            'vulnerability_count': len(vuln_sevs),
            'highest_severity': max(vuln_sevs) if vuln_sevs else None,
            'highest_severity_label': SEV_LABELS.get(max(vuln_sevs)) if vuln_sevs else None,
            'tools': _port_tools(p),
        })

    return {
        'id': ip.id,
        'ip_address': ip.ip_address,
        'scope': _scope_label(ip),
        'completed': bool(ip.completed),
        'notes': ip.notes or '',
        'os': ip.os or '',
        'cidr': ip.cidr.name if ip.cidr_id else None,
        'domains': list(ip.domain_set.values_list('name', flat=True)),
        'virtualhosts': ip.get_virtualhosts(),
        'ports': ports,
    }


def _port_tools(port):
    return {
        'nmap':      bool(port.meta.get('nmap_scripts')),
        'nikto':     bool(port.meta.get('Nikto')),
        'gowitness': bool(port.meta.get('Gowitness')),
        'ffuf':      bool(port.meta.get('FFuF')),
        'xsscrapy':  bool(port.meta.get('Xsscrapy')),
        'xsstrike':  bool(port.meta.get('Xsstrike')),
    }


def _serialize_port_detail(port):
    ip = port.ip_address  # FK — always present

    vulns = []
    for v in port.vulnerability_set.all().order_by('-severity'):
        vo = VulnOutput.objects.filter(port=port, vulnerability=v).first()
        vulns.append({
            'id': v.id,
            'name': v.name,
            'severity': v.severity,
            'severity_label': SEV_LABELS.get(v.severity, 'unknown'),
            'exploitable': v.exploitable,
            'description': v.description,
            'remediation': v.remediation,
            'output': vo.data if vo else None,
        })

    # Gowitness: strip screenshot binary path, keep everything else
    gowitness_entries = []
    for gw in (port.meta.get('Gowitness') or []):
        entry = {k: v for k, v in gw.items() if k != 'screenshot_file'}
        gowitness_entries.append(entry)

    return {
        'id': port.id,
        'port_number': port.port_number,
        'proto': port.proto,
        'service_name': port.service_name,
        'status': port.status,
        'ip_address': ip.ip_address,
        'ip_id': ip.id,
        'tools': _port_tools(port),
        'vulnerabilities': vulns,
        'nmap_scripts': port.meta.get('nmap_scripts') or {},
        'gowitness': gowitness_entries,
    }


def _serialize_vuln_summary(v):
    return {
        'id': v.id,
        'name': v.name,
        'severity': v.severity,
        'severity_label': SEV_LABELS.get(v.severity, 'unknown'),
        'exploitable': v.exploitable,
        'affected_port_count': v.ports.count(),
    }


def _serialize_vuln_detail(v):
    affected = []
    for p in v.ports.all():
        ip = p.ip_address
        vo = VulnOutput.objects.filter(port=p, vulnerability=v).first()
        affected.append({
            'port_id': p.id,
            'port_number': p.port_number,
            'proto': p.proto,
            'service_name': p.service_name,
            'ip_address': ip.ip_address,
            'ip_id': ip.id,
            'output': vo.data if vo else None,
        })

    return {
        'id': v.id,
        'name': v.name,
        'severity': v.severity,
        'severity_label': SEV_LABELS.get(v.severity, 'unknown'),
        'exploitable': v.exploitable,
        'description': v.description,
        'remediation': v.remediation,
        'cves': list(v.cves.values_list('name', flat=True)),
        'affected_ports': affected,
    }


def _serialize_domain(d):
    return {
        'id': d.id,
        'name': d.name,
        'scope': _scope_label(d),
        'base_domain': d.basedomain.name if d.basedomain_id else None,
        'ip_addresses': list(d.ip_addresses.values_list('ip_address', flat=True)),
    }


def _serialize_cidr(c):
    return {
        'id': c.id,
        'cidr': c.name,
        'org_name': c.org_name or '',
        'scope': _scope_label(c),
        'size': c.size,
        'cloud': c.cloud,
    }


def _paginated_response(qs, serializer, page, per_page):
    total = qs.count()
    offset = (page - 1) * per_page
    results = [serializer(obj) for obj in qs[offset:offset + per_page]]
    return JsonResponse({
        'results': results,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, (total + per_page - 1) // per_page),
    })


# ── Views ─────────────────────────────────────────────────────────────────────

@csrf_exempt
def api_root(request):
    return JsonResponse({
        'name': 'Armory REST API',
        'version': '1.0',
        'description': 'JSON REST API for Armory security data, designed for MCP tool integration.',
        'severity_scale': SEV_LABELS,
        'endpoints': ENDPOINTS,
    })


@csrf_exempt
def hosts(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    scope = request.GET.get('scope', 'active')
    search = request.GET.get('search', '').strip() or None
    completed = _bool_param(request, 'completed')
    page, per_page = _paginate(request)

    ips, total = IPAddress.get_sorted(
        scope_type=scope,
        search=search,
        display_zero=False,
        page_num=page,
        entries=per_page,
    )

    results = []
    for ip in ips:
        if completed is not None and bool(ip.completed) != completed:
            continue
        results.append(_serialize_ip_summary(ip))

    return JsonResponse({
        'results': results,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, (total + per_page - 1) // per_page),
    })


@csrf_exempt
def host_detail(request, ip_id):
    ip = get_object_or_404(IPAddress, pk=ip_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_ip_detail(ip))

    if request.method == 'PATCH':
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return _err('Request body must be valid JSON')
        if not isinstance(body, dict):
            return _err('Request body must be a JSON object')

        if 'notes' in body:
            ip.notes = str(body['notes'])
        if 'completed' in body:
            ip.completed = bool(body['completed'])
        ip.save()
        return JsonResponse(_serialize_ip_detail(ip))

    return _err('Method not allowed', 405)


@csrf_exempt
def port_detail(request, port_id):
    if request.method != 'GET':
        return _err('Method not allowed', 405)
    port = get_object_or_404(Port, pk=port_id)
    return JsonResponse(_serialize_port_detail(port))


@csrf_exempt
def vulns(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    page, per_page = _paginate(request)
    qs = Vulnerability.objects.all()

    sev_min = request.GET.get('severity_min')
    if sev_min is not None:
        try:
            qs = qs.filter(severity__gte=int(sev_min))
        except ValueError:
            return _err('severity_min must be an integer 0–4')

    sev_max = request.GET.get('severity_max')
    if sev_max is not None:
        try:
            qs = qs.filter(severity__lte=int(sev_max))
        except ValueError:
            return _err('severity_max must be an integer 0–4')

    search = request.GET.get('search', '').strip()
    if search:
        qs = qs.filter(name__icontains=search)

    ip_filter = request.GET.get('ip', '').strip()
    if ip_filter:
        qs = qs.filter(ports__ip_address__ip_address__icontains=ip_filter)

    exploitable = _bool_param(request, 'exploitable')
    if exploitable is not None:
        qs = qs.filter(exploitable=exploitable)

    qs = qs.order_by('-severity', 'name').distinct()
    return _paginated_response(qs, _serialize_vuln_summary, page, per_page)


@csrf_exempt
def vuln_detail(request, vuln_id):
    if request.method != 'GET':
        return _err('Method not allowed', 405)
    v = get_object_or_404(Vulnerability, pk=vuln_id)
    return JsonResponse(_serialize_vuln_detail(v))


@csrf_exempt
def domains(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    page, per_page = _paginate(request)
    scope = request.GET.get('scope', 'all')
    search = request.GET.get('search', '').strip()

    qs = Domain.objects.all()
    if scope == 'active':
        qs = qs.filter(active_scope=True)
    elif scope == 'passive':
        qs = qs.filter(passive_scope=True)
    if search:
        qs = qs.filter(name__icontains=search)

    qs = qs.order_by('name')
    return _paginated_response(qs, _serialize_domain, page, per_page)


@csrf_exempt
def cidrs(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    page, per_page = _paginate(request)
    scope = request.GET.get('scope', 'all')
    search = request.GET.get('search', '').strip()

    qs = CIDR.objects.all()
    if scope == 'active':
        qs = qs.filter(active_scope=True)
    elif scope == 'passive':
        qs = qs.filter(passive_scope=True)
    if search:
        qs = qs.filter(Q(name__icontains=search) | Q(org_name__icontains=search))

    qs = qs.order_by('name')
    return _paginated_response(qs, _serialize_cidr, page, per_page)


@csrf_exempt
def stats(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    ip_qs = IPAddress.objects.all()
    port_qs = Port.objects.all()
    vuln_qs = Vulnerability.objects.all()
    domain_qs = Domain.objects.all()
    cidr_qs = CIDR.objects.all()

    vuln_by_severity = {
        label: vuln_qs.filter(severity=sev).count()
        for sev, label in SEV_LABELS.items()
    }

    return JsonResponse({
        'hosts': {
            'total':     ip_qs.count(),
            'active':    ip_qs.filter(active_scope=True).count(),
            'passive':   ip_qs.filter(passive_scope=True).count(),
            'completed': ip_qs.filter(completed=True).count(),
        },
        'ports': {
            'total':          port_qs.count(),
            'http':           port_qs.filter(service_name='http').count(),
            'https':          port_qs.filter(service_name='https').count(),
            'unique_services': port_qs.values('service_name').distinct().count(),
        },
        'vulnerabilities': {
            'total':       vuln_qs.count(),
            'exploitable': vuln_qs.filter(exploitable=True).count(),
            **vuln_by_severity,
        },
        'domains': {
            'total':   domain_qs.count(),
            'active':  domain_qs.filter(active_scope=True).count(),
            'passive': domain_qs.filter(passive_scope=True).count(),
        },
        'cidrs': {
            'total':  cidr_qs.count(),
            'active': cidr_qs.filter(active_scope=True).count(),
        },
    })


@csrf_exempt
def search(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    q = request.GET.get('q', '').strip()
    if not q:
        return _err("Query parameter 'q' is required")

    limit = 20

    matched_ips = IPAddress.objects.filter(
        Q(ip_address__icontains=q) | Q(domain__name__icontains=q)
    ).distinct()[:limit]

    matched_domains = Domain.objects.filter(name__icontains=q)[:limit]

    matched_vulns = Vulnerability.objects.filter(name__icontains=q)[:limit]

    matched_ports = Port.objects.filter(service_name__icontains=q)[:limit]

    return JsonResponse({
        'query': q,
        'hosts': [_serialize_ip_summary(ip) for ip in matched_ips],
        'domains': [_serialize_domain(d) for d in matched_domains],
        'vulnerabilities': [_serialize_vuln_summary(v) for v in matched_vulns],
        'ports': [
            {
                'id': p.id,
                'port_number': p.port_number,
                'proto': p.proto,
                'service_name': p.service_name,
                'ip_address': p.ip_address.ip_address,
                'ip_id': p.ip_address_id,
            }
            for p in matched_ports
        ],
    })
