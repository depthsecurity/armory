"""
Armory REST API — full CRUD JSON endpoints designed for MCP tool integration.

All endpoints return JSON. POST and PATCH accept a JSON body.
DELETE cascades through Django foreign keys (deleting a host removes its
ports, virtualhosts, and vulnerability links).

Severity scale: 0=informational, 1=low, 2=medium, 3=high, 4=critical.

No authentication is enforced; deploy behind a network boundary or add
Django middleware if public exposure is needed.
"""

import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.db import IntegrityError
from armory2.armory_main.models import (
    IPAddress, Port, Domain, CIDR,
    Vulnerability, VulnOutput,
)

# ── Constants ─────────────────────────────────────────────────────────────────

SEV_LABELS = {0: 'informational', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

ENDPOINTS = {
    'GET    /armory_api/':              'API root — this document',
    'GET    /armory_api/hosts':         'List IPs. Params: scope, search, page, per_page, completed',
    'POST   /armory_api/hosts':         'Create IP. JSON: {ip_address, os?, notes?, ai_notes?, completed?, active_scope?, passive_scope?, whois?}',
    'GET    /armory_api/hosts/<id>':    'Full IP detail',
    'PATCH  /armory_api/hosts/<id>':    'Update IP. Any of: ip_address, os, notes, ai_notes, completed, active_scope, passive_scope, whois',
    'DELETE /armory_api/hosts/<id>':    'Delete IP (cascades to ports, virtualhosts, vuln links)',
    'GET    /armory_api/ports':         'List ports. Params: search, ip, service, page, per_page',
    'POST   /armory_api/ports':         'Create port. JSON: {port_number, proto, ip_id, status?, service_name?, cert?, ai_notes?, active_scope?, passive_scope?}',
    'GET    /armory_api/ports/<id>':    'Port detail with vulns, nmap, and gowitness data',
    'PATCH  /armory_api/ports/<id>':    'Update port. Any of: port_number, proto, ip_id, status, service_name, cert, ai_notes, active_scope, passive_scope',
    'DELETE /armory_api/ports/<id>':    'Delete port',
    'GET    /armory_api/vulns':         'List vulns. Params: severity_min, severity_max, search, ip, exploitable, page, per_page',
    'POST   /armory_api/vulns':         'Create vuln. JSON: {name, severity, description?, remediation?, exploitable?, source?, port_ids?}',
    'GET    /armory_api/vulns/<id>':    'Vuln detail with all affected ports',
    'PATCH  /armory_api/vulns/<id>':    'Update vuln. Any of: name, severity, description, remediation, exploitable, source, port_ids',
    'DELETE /armory_api/vulns/<id>':    'Delete vuln',
    'GET    /armory_api/domains':       'List domains. Params: scope, search, page, per_page',
    'POST   /armory_api/domains':       'Create domain. JSON: {name, whois?, ai_notes?, dynamic_ip?, active_scope?, passive_scope?, ip_ids?}',
    'GET    /armory_api/domains/<id>':  'Domain detail',
    'PATCH  /armory_api/domains/<id>':  'Update domain. Any of: name, whois, ai_notes, dynamic_ip, active_scope, passive_scope, ip_ids',
    'DELETE /armory_api/domains/<id>':  'Delete domain',
    'GET    /armory_api/cidrs':         'List CIDRs. Params: scope, search, page, per_page',
    'POST   /armory_api/cidrs':         'Create CIDR. JSON: {name, org_name?, size?, cloud?, active_scope?, passive_scope?}',
    'GET    /armory_api/cidrs/<id>':    'CIDR detail',
    'PATCH  /armory_api/cidrs/<id>':    'Update CIDR. Any of: name, org_name, size, cloud, active_scope, passive_scope',
    'DELETE /armory_api/cidrs/<id>':    'Delete CIDR (cascades to all child IPs)',
    'GET    /armory_api/stats':         'Aggregate counts across all entity types',
    'GET    /armory_api/search':        'Cross-entity search. Params: q (required)',
}

# Field type maps used for create/update body parsing.
IP_FIELDS = {
    'ip_address': str, 'os': str, 'notes': str, 'ai_notes': str, 'whois': str,
    'completed': bool, 'active_scope': bool, 'passive_scope': bool,
}
PORT_FIELDS = {
    'port_number': int, 'proto': str, 'status': str, 'service_name': str,
    'cert': str, 'ai_notes': str, 'active_scope': bool, 'passive_scope': bool,
}
VULN_FIELDS = {
    'name': str, 'description': str, 'remediation': str, 'source': str,
    'severity': int, 'exploitable': bool,
}
DOMAIN_FIELDS = {
    'name': str, 'whois': str, 'ai_notes': str,
    'dynamic_ip': bool, 'active_scope': bool, 'passive_scope': bool,
}
CIDR_FIELDS = {
    'name': str, 'org_name': str, 'size': int,
    'cloud': bool, 'active_scope': bool, 'passive_scope': bool,
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


def _parse_body(request):
    """Returns (body_dict, error_response). On success error_response is None."""
    if not request.body:
        return None, _err('Request body required')
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return None, _err('Request body must be valid JSON')
    if not isinstance(body, dict):
        return None, _err('Request body must be a JSON object')
    return body, None


def _coerce(val, target):
    """Coerce a JSON value into the target type. Accepts string forms of bools."""
    if target is bool:
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.strip().lower() in ('true', '1', 'yes')
        return bool(val)
    if target is int:
        return int(val)
    return str(val) if val is not None else ''


def _build_update_dict(body, field_map):
    """Return (update_dict, error_message)."""
    out = {}
    for field, target in field_map.items():
        if field in body:
            try:
                out[field] = _coerce(body[field], target)
            except (ValueError, TypeError):
                return None, f"Invalid value for '{field}'"
    return out, None


def _apply_fields(obj, body, field_map):
    """Set body[field] on obj for each field in field_map.

    Returns an error message string on failure, or None on success.
    """
    updates, err = _build_update_dict(body, field_map)
    if err:
        return err
    for field, val in updates.items():
        setattr(obj, field, val)
    return None


def _validate_severity(body):
    if 'severity' in body:
        try:
            sev = int(body['severity'])
        except (ValueError, TypeError):
            return "'severity' must be an integer 0–4"
        if sev not in SEV_LABELS:
            return "'severity' must be 0, 1, 2, 3, or 4"
    return None


def _validate_port_number(body):
    if 'port_number' in body:
        try:
            n = int(body['port_number'])
        except (ValueError, TypeError):
            return "'port_number' must be an integer 1–65535"
        if not (1 <= n <= 65535):
            return "'port_number' must be 1–65535"
    return None


# ── Serializers ───────────────────────────────────────────────────────────────

def _serialize_ip_summary(ip):
    return {
        'id': ip.id,
        'ip_address': ip.ip_address,
        'scope': _scope_label(ip),
        'completed': bool(ip.completed),
        'notes': ip.notes or '',
        'ai_notes': ip.ai_notes or '',
        'os': ip.os or '',
        'port_count': ip.port_set.count(),
        'domain_count': ip.domain_set.count(),
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
            'ai_notes': p.ai_notes or '',
            'vulnerability_count': len(vuln_sevs),
            'highest_severity': max(vuln_sevs) if vuln_sevs else None,
            'highest_severity_label': SEV_LABELS.get(max(vuln_sevs)) if vuln_sevs else None,
            'tools': _port_tools(p),
        })

    return {
        'id': ip.id,
        'ip_address': ip.ip_address,
        'scope': _scope_label(ip),
        'active_scope': ip.active_scope,
        'passive_scope': ip.passive_scope,
        'completed': bool(ip.completed),
        'notes': ip.notes or '',
        'ai_notes': ip.ai_notes or '',
        'os': ip.os or '',
        'whois': ip.whois or '',
        'cidr': ip.cidr.name if ip.cidr_id else None,
        'cidr_id': ip.cidr_id,
        'domains': list(ip.domain_set.values_list('name', flat=True)),
        'virtualhosts': ip.get_virtualhosts(),
        'ports': ports,
    }


def _serialize_port_summary(port):
    return {
        'id': port.id,
        'port_number': port.port_number,
        'proto': port.proto,
        'service_name': port.service_name,
        'status': port.status,
        'ai_notes': port.ai_notes or '',
        'ip_address': port.ip_address.ip_address,
        'ip_id': port.ip_address_id,
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

    gowitness_entries = []
    for gw in (port.meta.get('Gowitness') or []):
        gowitness_entries.append({k: v for k, v in gw.items() if k != 'screenshot_file'})

    return {
        'id': port.id,
        'port_number': port.port_number,
        'proto': port.proto,
        'service_name': port.service_name,
        'status': port.status,
        'ip_address': ip.ip_address,
        'ip_id': ip.id,
        'cert': port.cert or '',
        'ai_notes': port.ai_notes or '',
        'active_scope': port.active_scope,
        'passive_scope': port.passive_scope,
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
        'source': v.source,
        'cves': list(v.cves.values_list('name', flat=True)),
        'affected_ports': affected,
    }


def _serialize_domain_summary(d):
    return {
        'id': d.id,
        'name': d.name,
        'scope': _scope_label(d),
        'ai_notes': d.ai_notes or '',
        'base_domain': d.basedomain.name if d.basedomain_id else None,
        'ip_addresses': list(d.ip_addresses.values_list('ip_address', flat=True)),
    }


def _serialize_domain_detail(d):
    return {
        'id': d.id,
        'name': d.name,
        'scope': _scope_label(d),
        'active_scope': d.active_scope,
        'passive_scope': d.passive_scope,
        'dynamic_ip': d.dynamic_ip,
        'whois': d.whois or '',
        'ai_notes': d.ai_notes or '',
        'base_domain': d.basedomain.name if d.basedomain_id else None,
        'base_domain_id': d.basedomain_id,
        'ip_addresses': [
            {'id': ip.id, 'ip_address': ip.ip_address}
            for ip in d.ip_addresses.all()
        ],
    }


def _serialize_cidr_summary(c):
    return {
        'id': c.id,
        'cidr': c.name,
        'org_name': c.org_name or '',
        'scope': _scope_label(c),
        'size': c.size,
        'cloud': c.cloud,
    }


def _serialize_cidr_detail(c):
    return {
        'id': c.id,
        'cidr': c.name,
        'org_name': c.org_name or '',
        'scope': _scope_label(c),
        'active_scope': c.active_scope,
        'passive_scope': c.passive_scope,
        'size': c.size,
        'cloud': c.cloud,
        'ip_count': c.ipaddress_set.count(),
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


# ── M2M helpers ───────────────────────────────────────────────────────────────

def _set_m2m(manager, ids, model, label):
    """Replace an M2M relation. Returns error JsonResponse or None."""
    if not isinstance(ids, list):
        return _err(f"'{label}' must be a list of integers")
    try:
        clean = [int(i) for i in ids]
    except (ValueError, TypeError):
        return _err(f"'{label}' must be a list of integers")
    found_qs = model.objects.filter(pk__in=clean)
    missing = set(clean) - set(found_qs.values_list('pk', flat=True))
    if missing:
        return _err(f"{model.__name__} not found: {sorted(missing)}", 404)
    manager.set(found_qs)
    return None


# ── Views ─────────────────────────────────────────────────────────────────────

@csrf_exempt
def api_root(request):
    return JsonResponse({
        'name': 'Armory REST API',
        'version': '2.0',
        'description': 'Full CRUD JSON REST API for Armory security data.',
        'severity_scale': SEV_LABELS,
        'endpoints': ENDPOINTS,
    })


# ─── Hosts (IPAddress) ────────────────────────────────────────────────────────

@csrf_exempt
def hosts(request):
    if request.method == 'GET':
        scope = request.GET.get('scope', 'active')
        search = request.GET.get('search', '').strip() or None
        completed = _bool_param(request, 'completed')
        page, per_page = _paginate(request)

        ips, total = IPAddress.get_sorted(
            scope_type=scope, search=search, display_zero=False,
            page_num=page, entries=per_page,
        )
        results = []
        for ip in ips:
            if completed is not None and bool(ip.completed) != completed:
                continue
            results.append(_serialize_ip_summary(ip))
        return JsonResponse({
            'results': results, 'total': total, 'page': page,
            'per_page': per_page,
            'total_pages': max(1, (total + per_page - 1) // per_page),
        })

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        if not str(body.get('ip_address', '')).strip():
            return _err("'ip_address' is required")
        ip = IPAddress(ip_address=str(body['ip_address']).strip())
        e = _apply_fields(ip, body, IP_FIELDS)
        if e:
            return _err(e)
        try:
            ip.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        except Exception as ex:
            return _err(f"Failed to create: {ex}", 400)
        return JsonResponse(_serialize_ip_detail(ip), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
def host_detail(request, ip_id):
    ip = get_object_or_404(IPAddress, pk=ip_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_ip_detail(ip))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        e = _apply_fields(ip, body, IP_FIELDS)
        if e:
            return _err(e)
        try:
            ip.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        return JsonResponse(_serialize_ip_detail(ip))

    if request.method == 'DELETE':
        addr = ip.ip_address
        ip.delete()
        return JsonResponse({'deleted': True, 'id': ip_id, 'ip_address': addr})

    return _err('Method not allowed', 405)


# ─── Ports ────────────────────────────────────────────────────────────────────

@csrf_exempt
def ports(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = Port.objects.select_related('ip_address').all()

        ip_filter = request.GET.get('ip', '').strip()
        if ip_filter:
            qs = qs.filter(ip_address__ip_address__icontains=ip_filter)
        service = request.GET.get('service', '').strip()
        if service:
            qs = qs.filter(service_name__icontains=service)
        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(service_name__icontains=search) |
                Q(ip_address__ip_address__icontains=search)
            )

        qs = qs.order_by('ip_address__ip_address', 'port_number')
        return _paginated_response(qs, _serialize_port_summary, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        if 'ip_id' not in body:
            return _err("'ip_id' is required")
        try:
            ip = IPAddress.objects.get(pk=int(body['ip_id']))
        except (ValueError, TypeError, IPAddress.DoesNotExist):
            return _err(f"IPAddress with id={body.get('ip_id')!r} not found", 404)
        for f in ('port_number', 'proto'):
            if f not in body:
                return _err(f"'{f}' is required")
        e = _validate_port_number(body)
        if e:
            return _err(e)
        port = Port(ip_address=ip)
        e = _apply_fields(port, body, PORT_FIELDS)
        if e:
            return _err(e)
        try:
            port.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        except Exception as ex:
            return _err(f"Failed to create: {ex}", 400)
        return JsonResponse(_serialize_port_detail(port), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
def port_detail(request, port_id):
    port = get_object_or_404(Port, pk=port_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_port_detail(port))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        if 'ip_id' in body:
            try:
                port.ip_address = IPAddress.objects.get(pk=int(body['ip_id']))
            except (ValueError, TypeError, IPAddress.DoesNotExist):
                return _err(f"IPAddress with id={body.get('ip_id')!r} not found", 404)
        e = _validate_port_number(body)
        if e:
            return _err(e)
        e = _apply_fields(port, body, PORT_FIELDS)
        if e:
            return _err(e)
        try:
            port.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        return JsonResponse(_serialize_port_detail(port))

    if request.method == 'DELETE':
        port.delete()
        return JsonResponse({'deleted': True, 'id': port_id})

    return _err('Method not allowed', 405)


# ─── Vulnerabilities ──────────────────────────────────────────────────────────

@csrf_exempt
def vulns(request):
    if request.method == 'GET':
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

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        for f in ('name', 'severity'):
            if f not in body:
                return _err(f"'{f}' is required")
        e = _validate_severity(body)
        if e:
            return _err(e)
        v = Vulnerability()
        e = _apply_fields(v, body, VULN_FIELDS)
        if e:
            return _err(e)
        try:
            v.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        if 'port_ids' in body:
            err = _set_m2m(v.ports, body['port_ids'], Port, 'port_ids')
            if err:
                return err
        return JsonResponse(_serialize_vuln_detail(v), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
def vuln_detail(request, vuln_id):
    v = get_object_or_404(Vulnerability, pk=vuln_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_vuln_detail(v))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        e = _validate_severity(body)
        if e:
            return _err(e)
        e = _apply_fields(v, body, VULN_FIELDS)
        if e:
            return _err(e)
        try:
            v.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        if 'port_ids' in body:
            err = _set_m2m(v.ports, body['port_ids'], Port, 'port_ids')
            if err:
                return err
        return JsonResponse(_serialize_vuln_detail(v))

    if request.method == 'DELETE':
        v.delete()
        return JsonResponse({'deleted': True, 'id': vuln_id})

    return _err('Method not allowed', 405)


# ─── Domains ──────────────────────────────────────────────────────────────────

@csrf_exempt
def domains(request):
    if request.method == 'GET':
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
        return _paginated_response(qs, _serialize_domain_summary, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        if not str(body.get('name', '')).strip():
            return _err("'name' is required")
        d = Domain(name=str(body['name']).strip())
        e = _apply_fields(d, body, DOMAIN_FIELDS)
        if e:
            return _err(e)
        try:
            d.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        except Exception as ex:
            return _err(f"Failed to create: {ex}", 400)
        # Domain.save() silently returns the existing instance on name collision
        # without raising IntegrityError; in that case d.id stays None.
        if d.id is None:
            existing = Domain.objects.filter(name=d.name).first()
            return _err(
                f"Domain '{d.name}' already exists"
                + (f" (id={existing.id})" if existing else ''),
                409,
            )
        if 'ip_ids' in body:
            err = _set_m2m(d.ip_addresses, body['ip_ids'], IPAddress, 'ip_ids')
            if err:
                return err
        return JsonResponse(_serialize_domain_detail(d), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
def domain_detail(request, domain_id):
    d = get_object_or_404(Domain, pk=domain_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_domain_detail(d))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        # Domain.save() override is a no-op for existing rows (upstream quirk),
        # so bypass it via .update() for field changes. M2M is handled normally.
        updates, e = _build_update_dict(body, DOMAIN_FIELDS)
        if e:
            return _err(e)
        if updates:
            try:
                Domain.objects.filter(pk=d.pk).update(**updates)
            except IntegrityError as ex:
                return _err(f"Conflict: {ex}", 409)
            d.refresh_from_db()
        if 'ip_ids' in body:
            err = _set_m2m(d.ip_addresses, body['ip_ids'], IPAddress, 'ip_ids')
            if err:
                return err
        return JsonResponse(_serialize_domain_detail(d))

    if request.method == 'DELETE':
        name = d.name
        d.delete()
        return JsonResponse({'deleted': True, 'id': domain_id, 'name': name})

    return _err('Method not allowed', 405)


# ─── CIDRs ────────────────────────────────────────────────────────────────────

@csrf_exempt
def cidrs(request):
    if request.method == 'GET':
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
        return _paginated_response(qs, _serialize_cidr_summary, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        if not str(body.get('name', '')).strip():
            return _err("'name' is required")
        c = CIDR(name=str(body['name']).strip())
        e = _apply_fields(c, body, CIDR_FIELDS)
        if e:
            return _err(e)
        try:
            c.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        except Exception as ex:
            return _err(f"Failed to create: {ex}", 400)
        return JsonResponse(_serialize_cidr_detail(c), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
def cidr_detail(request, cidr_id):
    c = get_object_or_404(CIDR, pk=cidr_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_cidr_detail(c))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        e = _apply_fields(c, body, CIDR_FIELDS)
        if e:
            return _err(e)
        try:
            c.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        return JsonResponse(_serialize_cidr_detail(c))

    if request.method == 'DELETE':
        name = c.name
        c.delete()
        return JsonResponse({'deleted': True, 'id': cidr_id, 'cidr': name})

    return _err('Method not allowed', 405)


# ─── Stats & Search ───────────────────────────────────────────────────────────

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
    matched_ports = Port.objects.select_related('ip_address').filter(
        service_name__icontains=q
    )[:limit]

    return JsonResponse({
        'query': q,
        'hosts': [_serialize_ip_summary(ip) for ip in matched_ips],
        'domains': [_serialize_domain_summary(d) for d in matched_domains],
        'vulnerabilities': [_serialize_vuln_summary(v) for v in matched_vulns],
        'ports': [_serialize_port_summary(p) for p in matched_ports],
    })
