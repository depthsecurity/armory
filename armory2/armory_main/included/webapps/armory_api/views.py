"""
Armory REST API — full CRUD JSON endpoints designed for MCP tool integration.

All endpoints return JSON. POST and PATCH accept a JSON body.
DELETE cascades through Django foreign keys (deleting a host removes its
ports, virtualhosts, and vulnerability links).

Severity scale: 0=informational, 1=low, 2=medium, 3=high, 4=critical.

Every endpoint requires the Armory API key, sent either as an X-Armory-Key
header or as `Authorization: Bearer <key>`. The key is the Django SECRET_KEY,
which is set in ~/.armory/settings.py; armory-mcp reads the same value so the
two agree without any extra configuration.
"""

import hmac
import importlib.util
import json
import os
from functools import wraps
from django.conf import settings as django_settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.db import IntegrityError
from armory2.armory_main.models import (
    BaseDomain, IPAddress, Port, Domain, CIDR, VirtualHost, ToolRun,
    Vulnerability, VulnOutput, CVE, Url,
    User, Cred, Tag,
)

# This file is loaded by path (see urls.py), not as part of a package, so the
# sibling exec_runner module has to be loaded the same way.
_exec_spec = importlib.util.spec_from_file_location(
    "armory_api_exec_runner",
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "exec_runner.py"),
)
exec_runner = importlib.util.module_from_spec(_exec_spec)
_exec_spec.loader.exec_module(exec_runner)

# ── Constants ─────────────────────────────────────────────────────────────────

SEV_LABELS = {0: 'informational', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

API_KEY_HEADER = 'X-Armory-Key'
API_KEY_META = 'HTTP_X_ARMORY_KEY'

AUTH_DOC = (
    f'All endpoints require the Armory API key (the Django SECRET_KEY from '
    f'~/.armory/settings.py) in the {API_KEY_HEADER} header, or as '
    f'"Authorization: Bearer <key>".'
)

ENDPOINTS = {
    'GET    /armory_api/':              'API root — this document',
    'GET    /armory_api/hosts':         'List IPs. Params: scope (active|passive|all, default all), search, page, per_page, completed, recon_complete, display_zero (default true — set false to hide hosts with no ports above port 0)',
    'POST   /armory_api/hosts':         'Create IP. JSON: {ip_address, os?, notes?, ai_notes?, completed?, recon_complete?, active_scope?, passive_scope?, whois?, tag_ids?, tag_names?}',
    'GET    /armory_api/hosts/<id>':    'Full IP detail',
    'PATCH  /armory_api/hosts/<id>':    'Update IP. Any of: ip_address, os, notes, ai_notes, completed, recon_complete, active_scope, passive_scope, whois, tag_ids, tag_names',
    'DELETE /armory_api/hosts/<id>':    'Delete IP (cascades to ports, virtualhosts, vuln links)',
    'GET    /armory_api/ports':         'List ports. Params: search, ip, service, page, per_page, recon_complete',
    'POST   /armory_api/ports':         'Create port. JSON: {port_number, proto, ip_id, status?, service_name?, cert?, ai_notes?, recon_complete?, active_scope?, passive_scope?, tag_ids?, tag_names?}',
    'GET    /armory_api/ports/<id>':    'Port detail with vulns, nmap, and gowitness data',
    'PATCH  /armory_api/ports/<id>':    'Update port. Any of: port_number, proto, ip_id, status, service_name, cert, ai_notes, recon_complete, active_scope, passive_scope, tag_ids, tag_names',
    'DELETE /armory_api/ports/<id>':    'Delete port',
    'GET    /armory_api/vulns':         'List vulns. Params: severity_min, severity_max, search, ip, exploitable, page, per_page',
    'POST   /armory_api/vulns':         'Create vuln. JSON: {name, severity, description?, remediation?, exploitable?, source?, port_ids?, cve_ids?, cve_names?}',
    'GET    /armory_api/vulns/<id>':    'Vuln detail with all affected ports',
    'PATCH  /armory_api/vulns/<id>':    'Update vuln. Any of: name, severity, description, remediation, exploitable, source, port_ids, cve_ids, cve_names',
    'DELETE /armory_api/vulns/<id>':    'Delete vuln',
    'GET    /armory_api/vuln_outputs':      'List per-port vuln output rows, each with its linked URLs. Params: vuln_id, port_id, ip, search, full, page, per_page',
    'POST   /armory_api/vuln_outputs':      'Upsert output for a (vuln, port) pair. JSON: {vuln_id, port_id, data, append?}',
    'GET    /armory_api/vuln_outputs/<id>': 'Single output row with full data',
    'PATCH  /armory_api/vuln_outputs/<id>': 'Update one output row. JSON: {data, append?}',
    'DELETE /armory_api/vuln_outputs/<id>': 'Delete one output row (leaves the vuln, port, and any linked URLs intact)',
    'GET    /armory_api/domains':       'List domains. Params: scope, search, page, per_page, recon_complete',
    'POST   /armory_api/domains':       'Create domain. JSON: {name, whois?, ai_notes?, recon_complete?, dynamic_ip?, active_scope?, passive_scope?, ip_ids?, tag_ids?, tag_names?}',
    'GET    /armory_api/domains/<id>':  'Domain detail',
    'PATCH  /armory_api/domains/<id>':  'Update domain. Any of: name, whois, ai_notes, recon_complete, dynamic_ip, active_scope, passive_scope, ip_ids, tag_ids, tag_names',
    'DELETE /armory_api/domains/<id>':  'Delete domain',
    'GET    /armory_api/cidrs':         'List CIDRs. Params: scope, search, page, per_page',
    'POST   /armory_api/cidrs':         'Create CIDR. JSON: {name, org_name?, size?, cloud?, active_scope?, passive_scope?}',
    'GET    /armory_api/cidrs/<id>':    'CIDR detail',
    'PATCH  /armory_api/cidrs/<id>':    'Update CIDR. Any of: name, org_name, size, cloud, active_scope, passive_scope',
    'DELETE /armory_api/cidrs/<id>':    'Delete CIDR (cascades to all child IPs)',
    'GET    /armory_api/virtualhosts':      'List virtual hosts. Params: search, name, ip, ip_id, port_id, domain, active, scope, page, per_page',
    'POST   /armory_api/virtualhosts':      'Create (get_or_create on ip_id+port_id+name). JSON: {ip_id, name, port_id?, domain_id?, active?, active_scope?, passive_scope?}',
    'GET    /armory_api/virtualhosts/<id>': 'Virtual host detail',
    'PATCH  /armory_api/virtualhosts/<id>': 'Update. Any of: name, active, ip_id, port_id, domain_id, active_scope, passive_scope',
    'DELETE /armory_api/virtualhosts/<id>': 'Delete virtual host (cascades to its ToolRun rows)',
    'GET    /armory_api/basedomains':       'List root domains. Params: search, scope, page, per_page',
    'GET    /armory_api/basedomains/<id>':  'Root domain detail with DNS records and child domains',
    'PATCH  /armory_api/basedomains/<id>':  'Update scope flags and tags. Any of: active_scope, passive_scope, tag_ids, tag_names',
    'GET    /armory_api/urls':          'List discovered URLs. Params: search, method, port_id, ip, vuln_output_id (or none), vuln_id, scope, page, per_page',
    'POST   /armory_api/urls':          'Create URL (get_or_create on port_id+name+method). JSON: {port_id, name, method?, vuln_output_id?, active_scope?, passive_scope?}',
    'GET    /armory_api/urls/<id>':     'URL detail',
    'PATCH  /armory_api/urls/<id>':     'Update URL. Any of: name, method, port_id, vuln_output_id (null to unlink), active_scope, passive_scope',
    'DELETE /armory_api/urls/<id>':     'Delete URL',
    'GET    /armory_api/users':         'List discovered users. Params: search, basedomain_id, domain, tag, scope, page, per_page',
    'POST   /armory_api/users':         'Create user. JSON: {email, first_name?, last_name?, user_name?, job_title?, location?, basedomain_id?, domain?, tag_ids?, tag_names?}',
    'GET    /armory_api/users/<id>':    'User detail with credentials',
    'PATCH  /armory_api/users/<id>':    'Update user. Any of: email, first_name, last_name, user_name, job_title, location, basedomain_id, domain, tag_ids, tag_names',
    'DELETE /armory_api/users/<id>':    'Delete user (cascades to their creds)',
    'GET    /armory_api/creds':         'List credentials. Params: search, user_id, source, has_password, has_hash, tag, page, per_page',
    'POST   /armory_api/creds':         'Create cred. JSON: {user_id, password?, passhash?, source?, tag_ids?, tag_names?}',
    'GET    /armory_api/creds/<id>':    'Cred detail',
    'PATCH  /armory_api/creds/<id>':    'Update cred. Any of: password, passhash, source, user_id, tag_ids, tag_names',
    'DELETE /armory_api/creds/<id>':    'Delete cred',
    'GET    /armory_api/cves':          'List CVEs. Params: search, min_score, updated, page, per_page',
    'POST   /armory_api/cves':          'Create CVE (get_or_create on name). JSON: {name, description?, temporal_score?, updated?, vuln_ids?}',
    'GET    /armory_api/cves/<id>':     'CVE detail with the vulnerabilities referencing it',
    'PATCH  /armory_api/cves/<id>':     'Update CVE. Any of: name, description, temporal_score, updated, vuln_ids',
    'DELETE /armory_api/cves/<id>':     'Delete CVE (unlinks it from vulnerabilities)',
    'GET    /armory_api/tags':          'List tags with usage counts. Params: search, type, page, per_page',
    'POST   /armory_api/tags':          'Create tag (get_or_create on name). JSON: {name, type?} — type is ip|domain|cred|any',
    'GET    /armory_api/tags/<id>':     'Tag detail with everything it is applied to',
    'PATCH  /armory_api/tags/<id>':     'Update tag. Any of: name, type',
    'DELETE /armory_api/tags/<id>':     'Delete tag (removes it from everything it tagged)',
    'POST   /armory_api/tags/<id>/apply': 'Add or remove one tag without rewriting the whole list. JSON: {action: add|remove, ip_ids?, port_ids?, domain_ids?, basedomain_ids?, user_ids?, cred_ids?}',
    'GET    /armory_api/toolruns':      'Read-only tool history. Params: tool, port_id, virtualhost_id, ip, search, page, per_page',
    'GET    /armory_api/toolruns/<id>': 'Tool run detail',
    'GET    /armory_api/stats':         'Aggregate counts across all entity types',
    'GET    /armory_api/search':        'Cross-entity search. Params: q (required)',
    'GET    /armory_api/exec':          'List shell command jobs. Params: status (running|finished|timed_out|killed|failed), search, limit',
    'POST   /armory_api/exec':          'Run a shell command on the Armory host. JSON: {command, cwd?, timeout?, background?, env?, tail?}',
    'GET    /armory_api/exec/<job_id>': 'Command job status and output. Params: tail, wait (seconds to block for completion)',
    'DELETE /armory_api/exec/<job_id>': 'Kill a running command (its process group); the job record and captured output remain',
}

# Field type maps used for create/update body parsing.
IP_FIELDS = {
    'ip_address': str, 'os': str, 'notes': str, 'ai_notes': str, 'whois': str,
    'completed': bool, 'recon_complete': bool, 'active_scope': bool, 'passive_scope': bool,
}
PORT_FIELDS = {
    'port_number': int, 'proto': str, 'status': str, 'service_name': str,
    'cert': str, 'ai_notes': str, 'recon_complete': bool, 'active_scope': bool, 'passive_scope': bool,
}
VULN_FIELDS = {
    'name': str, 'description': str, 'remediation': str, 'source': str,
    'severity': int, 'exploitable': bool,
}
DOMAIN_FIELDS = {
    'name': str, 'whois': str, 'ai_notes': str, 'recon_complete': bool,
    'dynamic_ip': bool, 'active_scope': bool, 'passive_scope': bool,
}
CIDR_FIELDS = {
    'name': str, 'org_name': str, 'size': int,
    'cloud': bool, 'active_scope': bool, 'passive_scope': bool,
}
VIRTUALHOST_FIELDS = {
    'name': str, 'active': bool, 'active_scope': bool, 'passive_scope': bool,
}
URL_FIELDS = {
    'name': str, 'method': str, 'active_scope': bool, 'passive_scope': bool,
}
USER_FIELDS = {
    'email': str, 'first_name': str, 'last_name': str, 'user_name': str,
    'job_title': str, 'location': str, 'active_scope': bool, 'passive_scope': bool,
}
CRED_FIELDS = {
    'password': str, 'passhash': str, 'source': str,
    'active_scope': bool, 'passive_scope': bool,
}
CVE_FIELDS = {
    'name': str, 'description': str, 'temporal_score': float, 'updated': bool,
    'active_scope': bool, 'passive_scope': bool,
}
TAG_FIELDS = {'name': str, 'type': str}
# A root domain's name is what every child Domain resolves against, so it is not
# rewritable here — only scope and tags are.
BASEDOMAIN_FIELDS = {'active_scope': bool, 'passive_scope': bool}


# ── Authentication ────────────────────────────────────────────────────────────

def _presented_api_key(request):
    """Pull the API key out of the request headers. Returns '' if absent."""
    key = request.META.get(API_KEY_META, '')
    if key:
        return key.strip()
    auth = request.META.get('HTTP_AUTHORIZATION', '')
    if auth[:7].lower() == 'bearer ':
        return auth[7:].strip()
    return ''


def require_api_key(view):
    """Reject any request that does not carry the Armory API key.

    The key is the Django SECRET_KEY, so armory-mcp and any other local client
    can resolve it from the same ~/.armory/settings.py the web server loads.
    """
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        expected = str(getattr(django_settings, 'SECRET_KEY', '') or '')
        if not expected:
            return _err('SECRET_KEY is not set on the server; API is unavailable', status=500)

        presented = _presented_api_key(request)
        if not presented:
            return _err(
                f'Authentication required: send the Armory API key in the '
                f'{API_KEY_HEADER} header',
                status=401,
            )
        if not hmac.compare_digest(presented, expected):
            return _err('Invalid Armory API key', status=403)

        return view(request, *args, **kwargs)

    return wrapper


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
    if target is float:
        return float(val)
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
        'recon_complete': ip.recon_complete,
        'notes': ip.notes or '',
        'ai_notes': ip.ai_notes or '',
        'os': ip.os or '',
        'port_count': ip.port_set.count(),
        'domain_count': ip.domain_set.count(),
        'tags': _tags_of(ip),
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
            'recon_complete': p.recon_complete,
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
        'recon_complete': ip.recon_complete,
        'notes': ip.notes or '',
        'ai_notes': ip.ai_notes or '',
        'os': ip.os or '',
        'whois': ip.whois or '',
        'cidr': ip.cidr.name if ip.cidr_id else None,
        'cidr_id': ip.cidr_id,
        'domains': list(ip.domain_set.values_list('name', flat=True)),
        'virtualhosts': ip.get_virtualhosts(),
        'tags': _tags_of(ip),
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
        'recon_complete': port.recon_complete,
        'ip_address': port.ip_address.ip_address,
        'ip_id': port.ip_address_id,
        'tags': _tags_of(port),
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
        'recon_complete': port.recon_complete,
        'active_scope': port.active_scope,
        'passive_scope': port.passive_scope,
        'tools': _port_tools(port),
        'vulnerabilities': vulns,
        'nmap_scripts': port.meta.get('nmap_scripts') or {},
        'gowitness': gowitness_entries,
        'tags': _tags_of(port),
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
        'cves': [_serialize_cve_summary(c) for c in v.cves.all()],
        'affected_ports': affected,
    }


PREVIEW_CHARS = 300


def _serialize_vuln_output(vo, full=True):
    port = vo.port
    ip = port.ip_address
    data = vo.data or ''
    out = {
        'id': vo.id,
        'vuln_id': vo.vulnerability_id,
        'vuln_name': vo.vulnerability.name,
        'severity': vo.vulnerability.severity,
        'severity_label': SEV_LABELS.get(vo.vulnerability.severity, 'unknown'),
        'port_id': port.id,
        'port_number': port.port_number,
        'proto': port.proto,
        'service_name': port.service_name,
        'ip_id': ip.id,
        'ip_address': ip.ip_address,
        'length': len(data),
        'urls': [
            {'id': u.id, 'name': u.name, 'method': u.method}
            for u in vo.urls.all()
        ],
    }
    if full:
        out['data'] = data
    else:
        out['preview'] = data[:PREVIEW_CHARS]
        out['truncated'] = len(data) > PREVIEW_CHARS
    return out


def _serialize_vuln_output_preview(vo):
    return _serialize_vuln_output(vo, full=False)


def _serialize_domain_summary(d):
    return {
        'id': d.id,
        'name': d.name,
        'scope': _scope_label(d),
        'ai_notes': d.ai_notes or '',
        'recon_complete': d.recon_complete,
        'base_domain': d.basedomain.name if d.basedomain_id else None,
        'ip_addresses': list(d.ip_addresses.values_list('ip_address', flat=True)),
        'tags': _tags_of(d),
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
        'recon_complete': d.recon_complete,
        'base_domain': d.basedomain.name if d.basedomain_id else None,
        'base_domain_id': d.basedomain_id,
        'ip_addresses': [
            {'id': ip.id, 'ip_address': ip.ip_address}
            for ip in d.ip_addresses.all()
        ],
        'tags': _tags_of(d),
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


def _serialize_virtualhost_summary(vh):
    return {
        'id': vh.id,
        'name': vh.name,
        'active': vh.active,
        'ip_address': vh.ip_address.ip_address,
        'ip_id': vh.ip_address_id,
        'port_id': vh.port_id,
        'port_number': vh.port.port_number if vh.port_id else None,
        'domain': vh.domain.name if vh.domain_id else None,
        'domain_id': vh.domain_id,
    }


def _serialize_virtualhost_detail(vh):
    out = _serialize_virtualhost_summary(vh)
    out.update({
        'proto': vh.port.proto if vh.port_id else None,
        'service_name': vh.port.service_name if vh.port_id else None,
        'scope': _scope_label(vh),
        'active_scope': vh.active_scope,
        'passive_scope': vh.passive_scope,
        'source_tool': vh.source_tool or '',
    })
    return out


def _set_cves(v, body):
    """Replace a vulnerability's CVE links from body['cve_ids'] or ['cve_names'].

    Names are get_or_create'd, so a CVE that Armory has never seen (no Nessus
    import) can be attached in one call. Returns an error response or None.
    """
    if 'cve_ids' in body and 'cve_names' in body:
        return _err("Provide 'cve_ids' or 'cve_names', not both")
    if 'cve_ids' in body:
        return _set_m2m(v.cves, body['cve_ids'], CVE, 'cve_ids')
    if 'cve_names' in body:
        names = body['cve_names']
        if not isinstance(names, list):
            return _err("'cve_names' must be a list of strings")
        found = []
        for raw in names:
            name = str(raw or '').strip()
            if not name:
                continue
            cve, _ = CVE.objects.get_or_create(name=name)
            found.append(cve)
        v.cves.set(found)
    return None


# ── Tag helpers ───────────────────────────────────────────────────────────────

# Which Tag.type each taggable model accepts, mirroring the limit_choices_to on
# the model fields. A tag of type 'any' fits everywhere.
TAG_KIND = {
    'IPAddress': Tag.TYPE_IP,
    'Port': Tag.TYPE_IP,
    'Domain': Tag.TYPE_DOMAIN,
    'BaseDomain': Tag.TYPE_DOMAIN,
    'User': Tag.TYPE_CRED,
    'Cred': Tag.TYPE_CRED,
}

TAGGABLE = {
    'ip_ids': IPAddress,
    'port_ids': Port,
    'domain_ids': Domain,
    'basedomain_ids': BaseDomain,
    'user_ids': User,
    'cred_ids': Cred,
}


def _serialize_tag(t):
    return {'id': t.id, 'name': t.name, 'type': t.type}


def _tags_of(obj):
    return [_serialize_tag(t) for t in obj.tags.all()]


def _tag_fits(tag, kind):
    return tag.type in (kind, Tag.TYPE_ANY)


def _set_tags(obj, body):
    """Replace obj.tags from body['tag_ids'] or body['tag_names'].

    Both replace the whole list — use POST /tags/<id>/apply to add or remove a
    single tag without a read-modify-write. Names are get_or_create'd with the
    type the target model accepts. Returns an error response or None.
    """
    kind = TAG_KIND[type(obj).__name__]

    if 'tag_ids' in body and 'tag_names' in body:
        return _err("Provide 'tag_ids' or 'tag_names', not both")

    if 'tag_ids' in body:
        ids = body['tag_ids']
        if not isinstance(ids, list):
            return _err("'tag_ids' must be a list of integers")
        try:
            clean = [int(i) for i in ids]
        except (ValueError, TypeError):
            return _err("'tag_ids' must be a list of integers")
        found = list(Tag.objects.filter(pk__in=clean))
        missing = set(clean) - {t.id for t in found}
        if missing:
            return _err(f"Tag not found: {sorted(missing)}", 404)
        wrong = [f"{t.name} ({t.type})" for t in found if not _tag_fits(t, kind)]
        if wrong:
            return _err(f"Tags {wrong} cannot be applied to a {kind} record")
        obj.tags.set(found)
        return None

    if 'tag_names' in body:
        names = body['tag_names']
        if not isinstance(names, list):
            return _err("'tag_names' must be a list of strings")
        tags = []
        for raw in names:
            name = str(raw or '').strip()
            if not name:
                continue
            tag, _ = Tag.objects.get_or_create(name=name, defaults={'type': kind})
            if not _tag_fits(tag, kind):
                return _err(
                    f"Tag '{tag.name}' already exists as a {tag.type} tag and "
                    f"cannot be applied to a {kind} record"
                )
            tags.append(tag)
        obj.tags.set(tags)

    return None


def _serialize_basedomain_summary(bd):
    return {
        'id': bd.id,
        'name': bd.name,
        'scope': _scope_label(bd),
        'domain_count': bd.domain_set.count(),
        'user_count': bd.user_set.count(),
        'tags': _tags_of(bd),
    }


def _serialize_basedomain_detail(bd):
    out = _serialize_basedomain_summary(bd)
    # dns is a pickled dict of record type -> values; JSON-safe it defensively.
    try:
        dns = json.loads(json.dumps(bd.dns or {}, default=str))
    except (TypeError, ValueError):
        dns = {}
    out.update({
        'active_scope': bd.active_scope,
        'passive_scope': bd.passive_scope,
        'dns': dns,
        'domains': [
            {'id': d.id, 'name': d.name} for d in bd.domain_set.all()
        ],
    })
    return out


def _serialize_url(u):
    port = u.port
    vo = u.vuln_output
    return {
        'id': u.id,
        'name': u.name,
        'method': u.method,
        'vuln_output_id': u.vuln_output_id,
        'vuln_id': vo.vulnerability_id if vo else None,
        'vuln_name': vo.vulnerability.name if vo else None,
        'port_id': port.id,
        'port_number': port.port_number,
        'proto': port.proto,
        'service_name': port.service_name,
        'ip_address': port.ip_address.ip_address,
        'ip_id': port.ip_address_id,
        'scope': _scope_label(u),
        'active_scope': u.active_scope,
        'passive_scope': u.passive_scope,
    }


def _serialize_cred(c, include_user=True):
    out = {
        'id': c.id,
        'password': c.password or '',
        'passhash': c.passhash or '',
        'source': c.source or '',
        'user_id': c.user_id,
        'tags': _tags_of(c),
    }
    if include_user:
        out['email'] = c.user.email
        out['user_name'] = c.user.user_name or ''
    return out


def _serialize_user_summary(u):
    return {
        'id': u.id,
        'email': u.email,
        'user_name': u.user_name or '',
        'first_name': u.first_name or '',
        'last_name': u.last_name or '',
        'base_domain': u.domain.name if u.domain_id else None,
        'basedomain_id': u.domain_id,
        'cred_count': u.cred_set.count(),
        'tags': _tags_of(u),
    }


def _serialize_user_detail(u):
    out = _serialize_user_summary(u)
    out.update({
        'job_title': u.job_title or '',
        'location': u.location or '',
        'scope': _scope_label(u),
        'active_scope': u.active_scope,
        'passive_scope': u.passive_scope,
        'creds': [_serialize_cred(c, include_user=False) for c in u.cred_set.all()],
    })
    return out


def _serialize_cve_summary(c):
    return {
        'id': c.id,
        'name': c.name,
        'temporal_score': c.temporal_score,
        'updated': c.updated,
        'vulnerability_count': c.vulnerability_set.count(),
    }


def _serialize_cve_detail(c):
    out = _serialize_cve_summary(c)
    out['description'] = c.description or ''
    out['vulnerabilities'] = [
        _serialize_vuln_summary(v) for v in c.vulnerability_set.all()
    ]
    return out


def _serialize_toolrun(tr):
    target = tr.content_object
    return {
        'id': tr.id,
        'tool': tr.tool,
        'args': tr.args or '',
        'port': tr.port,
        'port_id': tr.port_obj_id,
        'port_number': tr.port_obj.port_number if tr.port_obj_id else None,
        'virtualhost_id': tr.virtualhost_id,
        'virtualhost': tr.virtualhost.name if tr.virtualhost_id else None,
        'target_type': tr.content_type.model if tr.content_type_id else None,
        'target_id': tr.object_id,
        'target': str(target) if target is not None else None,
        'created_at': tr.created_at.isoformat() if tr.created_at else None,
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
@require_api_key
def api_root(request):
    return JsonResponse({
        'name': 'Armory REST API',
        'version': '2.0',
        'description': 'Full CRUD JSON REST API for Armory security data.',
        'authentication': AUTH_DOC,
        'severity_scale': SEV_LABELS,
        'endpoints': ENDPOINTS,
    })


# ─── Hosts (IPAddress) ────────────────────────────────────────────────────────

@csrf_exempt
@require_api_key
def hosts(request):
    if request.method == 'GET':
        # Defaults return everything: all scopes, port-0-only and portless hosts
        # included, no completion filtering. Every filter is opt-in so that
        # /hosts and /ports always agree on which hosts exist.
        scope = request.GET.get('scope', 'all')
        search = request.GET.get('search', '').strip()
        completed = _bool_param(request, 'completed')
        recon_complete = _bool_param(request, 'recon_complete')
        display_zero = _bool_param(request, 'display_zero')
        page, per_page = _paginate(request)

        qs = IPAddress.objects.prefetch_related('tags').all()
        joined = False

        if scope == 'active':
            qs = qs.filter(active_scope=True)
        elif scope == 'passive':
            qs = qs.filter(passive_scope=True)

        if display_zero is False:
            # Opt-in parity with the host_summary UI: hide hosts whose only
            # ports are the Nessus general/tcp + general/udp pseudo-ports.
            qs = qs.filter(port__port_number__gt=0)
            joined = True

        if search:
            qs = qs.filter(
                Q(ip_address__icontains=search) | Q(domain__name__icontains=search)
            )
            joined = True

        if completed is True:
            qs = qs.filter(completed=True)
        elif completed is False:
            # completed is nullable; NULL counts as not completed, so
            # filter(completed=False) would silently drop those hosts.
            qs = qs.exclude(completed=True)
        if recon_complete is not None:
            qs = qs.filter(recon_complete=recon_complete)

        if joined:
            qs = qs.distinct()
        qs = qs.order_by('ip_address')
        return _paginated_response(qs, _serialize_ip_summary, page, per_page)

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
        err = _set_tags(ip, body)
        if err:
            return err
        return JsonResponse(_serialize_ip_detail(ip), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
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
        err = _set_tags(ip, body)
        if err:
            return err
        return JsonResponse(_serialize_ip_detail(ip))

    if request.method == 'DELETE':
        addr = ip.ip_address
        ip.delete()
        return JsonResponse({'deleted': True, 'id': ip_id, 'ip_address': addr})

    return _err('Method not allowed', 405)


# ─── Ports ────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_api_key
def ports(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = Port.objects.select_related('ip_address').prefetch_related('tags').all()

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
        recon_complete = _bool_param(request, 'recon_complete')
        if recon_complete is not None:
            qs = qs.filter(recon_complete=recon_complete)

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
        err = _set_tags(port, body)
        if err:
            return err
        return JsonResponse(_serialize_port_detail(port), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
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
        err = _set_tags(port, body)
        if err:
            return err
        return JsonResponse(_serialize_port_detail(port))

    if request.method == 'DELETE':
        port.delete()
        return JsonResponse({'deleted': True, 'id': port_id})

    return _err('Method not allowed', 405)


# ─── Vulnerabilities ──────────────────────────────────────────────────────────

@csrf_exempt
@require_api_key
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
        err = _set_cves(v, body)
        if err:
            return err
        return JsonResponse(_serialize_vuln_detail(v), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
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
        err = _set_cves(v, body)
        if err:
            return err
        return JsonResponse(_serialize_vuln_detail(v))

    if request.method == 'DELETE':
        v.delete()
        return JsonResponse({'deleted': True, 'id': vuln_id})

    return _err('Method not allowed', 405)


# ─── Vuln output (per-port proof / plugin output) ─────────────────────────────

@csrf_exempt
@require_api_key
def vuln_outputs(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        full = _bool_param(request, 'full')
        qs = VulnOutput.objects.select_related(
            'vulnerability', 'port', 'port__ip_address'
        ).prefetch_related('urls').all()

        vuln_id = request.GET.get('vuln_id')
        if vuln_id:
            try:
                qs = qs.filter(vulnerability_id=int(vuln_id))
            except ValueError:
                return _err('vuln_id must be an integer')

        port_id = request.GET.get('port_id')
        if port_id:
            try:
                qs = qs.filter(port_id=int(port_id))
            except ValueError:
                return _err('port_id must be an integer')

        ip_filter = request.GET.get('ip', '').strip()
        if ip_filter:
            qs = qs.filter(port__ip_address__ip_address__icontains=ip_filter)

        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(data__icontains=search) |
                Q(vulnerability__name__icontains=search)
            )

        qs = qs.order_by('port__ip_address__ip_address', 'port__port_number', 'vulnerability__name')
        serializer = _serialize_vuln_output if full else _serialize_vuln_output_preview
        return _paginated_response(qs, serializer, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        for f in ('vuln_id', 'port_id'):
            if f not in body:
                return _err(f"'{f}' is required")
        if 'data' not in body:
            return _err("'data' is required")
        try:
            vuln_id = int(body['vuln_id'])
            port_id = int(body['port_id'])
        except (TypeError, ValueError):
            return _err("'vuln_id' and 'port_id' must be integers")
        if not isinstance(body['data'], str):
            return _err("'data' must be a string")

        v = Vulnerability.objects.filter(pk=vuln_id).first()
        if not v:
            return _err(f'No vulnerability with id {vuln_id}', 404)
        port = Port.objects.filter(pk=port_id).first()
        if not port:
            return _err(f'No port with id {port_id}', 404)

        vo = VulnOutput.objects.filter(vulnerability=v, port=port).first()
        created = vo is None
        if created:
            vo = VulnOutput(vulnerability=v, port=port, data='')
        if body.get('append'):
            existing = vo.data or ''
            vo.data = (existing + '\n' + body['data']) if existing else body['data']
        else:
            vo.data = body['data']
        vo.save()

        # Keep the vuln's affected-port set in sync — an output row for a port
        # that is not in vulnerability.ports would never surface in vuln detail.
        v.ports.add(port)

        return JsonResponse(_serialize_vuln_output(vo), status=201 if created else 200)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
def vuln_output_detail(request, output_id):
    vo = get_object_or_404(VulnOutput.objects.prefetch_related('urls'), pk=output_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_vuln_output(vo))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        if 'data' not in body:
            return _err("'data' is required")
        if not isinstance(body['data'], str):
            return _err("'data' must be a string")
        if body.get('append'):
            existing = vo.data or ''
            vo.data = (existing + '\n' + body['data']) if existing else body['data']
        else:
            vo.data = body['data']
        vo.save()
        return JsonResponse(_serialize_vuln_output(vo))

    if request.method == 'DELETE':
        vo.delete()
        return JsonResponse({'deleted': True, 'id': output_id})

    return _err('Method not allowed', 405)


# ─── Domains ──────────────────────────────────────────────────────────────────

@csrf_exempt
@require_api_key
def domains(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        scope = request.GET.get('scope', 'all')
        search = request.GET.get('search', '').strip()

        qs = Domain.objects.prefetch_related('tags').all()
        if scope == 'active':
            qs = qs.filter(active_scope=True)
        elif scope == 'passive':
            qs = qs.filter(passive_scope=True)
        if search:
            qs = qs.filter(name__icontains=search)
        recon_complete = _bool_param(request, 'recon_complete')
        if recon_complete is not None:
            qs = qs.filter(recon_complete=recon_complete)

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
        err = _set_tags(d, body)
        if err:
            return err
        return JsonResponse(_serialize_domain_detail(d), status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
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
        err = _set_tags(d, body)
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
@require_api_key
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
@require_api_key
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

# ─── Virtual hosts ────────────────────────────────────────────────────────────

def _vh_related(qs):
    return qs.select_related('ip_address', 'port', 'domain')


def _resolve_vh_port(body, ip):
    """Resolve body['port_id'] to a Port on `ip`. Returns (port, error_response).

    A null port_id is legitimate — it is the host-wide virtual host row that
    Armory creates alongside the per-port ones.
    """
    raw = body.get('port_id')
    if raw in (None, ''):
        return None, None
    try:
        port = Port.objects.get(pk=int(raw))
    except (ValueError, TypeError, Port.DoesNotExist):
        return None, _err(f"Port with id={raw!r} not found", 404)
    if port.ip_address_id != ip.id:
        return None, _err(
            f"Port {port.id} belongs to {port.ip_address.ip_address}, "
            f"not {ip.ip_address}"
        )
    return port, None


@csrf_exempt
@require_api_key
def virtualhosts(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = _vh_related(VirtualHost.objects.all())

        name = request.GET.get('name', '').strip()
        if name:
            qs = qs.filter(name__icontains=name)
        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(name__icontains=search) |
                Q(ip_address__ip_address__icontains=search)
            )
        ip_filter = request.GET.get('ip', '').strip()
        if ip_filter:
            qs = qs.filter(ip_address__ip_address__icontains=ip_filter)
        ip_id = request.GET.get('ip_id', '').strip()
        if ip_id:
            try:
                qs = qs.filter(ip_address_id=int(ip_id))
            except (ValueError, TypeError):
                return _err("'ip_id' must be an integer")
        port_id = request.GET.get('port_id', '').strip()
        if port_id:
            try:
                qs = qs.filter(port_id=int(port_id))
            except (ValueError, TypeError):
                return _err("'port_id' must be an integer")
        domain = request.GET.get('domain', '').strip()
        if domain:
            qs = qs.filter(domain__name__icontains=domain)
        active = _bool_param(request, 'active')
        if active is not None:
            qs = qs.filter(active=active)
        scope = request.GET.get('scope', 'all')
        if scope == 'active':
            qs = qs.filter(active_scope=True)
        elif scope == 'passive':
            qs = qs.filter(passive_scope=True)

        qs = qs.order_by('ip_address__ip_address', 'name', 'port__port_number')
        return _paginated_response(qs, _serialize_virtualhost_summary, page, per_page)

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

        name = str(body.get('name', '') or '').strip()
        if not name:
            return _err("'name' is required")

        port, err = _resolve_vh_port(body, ip)
        if err:
            return err

        # (ip, port, name) is the natural key Armory's own modules get_or_create
        # on, so repeat that here rather than stacking duplicate rows.
        vh = _vh_related(VirtualHost.objects.filter(
            ip_address=ip, port=port, name=name,
        )).first()
        created = vh is None
        if created:
            vh = VirtualHost(ip_address=ip, port=port, name=name)

        if 'domain_id' in body:
            e = _apply_vh_domain(vh, body)
            if e:
                return e

        e = _apply_fields(vh, body, VIRTUALHOST_FIELDS)
        if e:
            return _err(e)
        vh.name = name

        try:
            vh.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        except Exception as ex:
            return _err(f"Failed to create: {ex}", 400)

        vh.refresh_from_db()
        out = _serialize_virtualhost_detail(vh)
        out['created'] = created
        return JsonResponse(out, status=201 if created else 200)

    return _err('Method not allowed', 405)


def _apply_vh_domain(vh, body):
    """Set vh.domain from body['domain_id']. Returns an error response or None.

    A null clears the link, but VirtualHost.save() re-resolves an empty domain
    from the vhost name (creating the Domain if it does not exist), so clearing
    only sticks for names that are bare IP addresses.
    """
    raw = body.get('domain_id')
    if raw in (None, ''):
        vh.domain = None
        return None
    try:
        vh.domain = Domain.objects.get(pk=int(raw))
    except (ValueError, TypeError, Domain.DoesNotExist):
        return _err(f"Domain with id={raw!r} not found", 404)
    return None


@csrf_exempt
@require_api_key
def virtualhost_detail(request, vh_id):
    vh = get_object_or_404(_vh_related(VirtualHost.objects.all()), pk=vh_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_virtualhost_detail(vh))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err

        ip = vh.ip_address
        if 'ip_id' in body:
            try:
                ip = IPAddress.objects.get(pk=int(body['ip_id']))
            except (ValueError, TypeError, IPAddress.DoesNotExist):
                return _err(f"IPAddress with id={body.get('ip_id')!r} not found", 404)
            vh.ip_address = ip

        if 'port_id' in body:
            port, err = _resolve_vh_port(body, ip)
            if err:
                return err
            vh.port = port
        elif 'ip_id' in body and vh.port_id and vh.port.ip_address_id != ip.id:
            return _err(
                f"Port {vh.port_id} belongs to {vh.port.ip_address.ip_address}, "
                f"not {ip.ip_address} — set port_id too"
            )

        renamed = 'name' in body and str(body['name'] or '').strip() != vh.name

        if 'domain_id' in body:
            e = _apply_vh_domain(vh, body)
            if e:
                return e

        e = _apply_fields(vh, body, VIRTUALHOST_FIELDS)
        if e:
            return _err(e)

        # The name drives the Domain link, so a rename that does not name a
        # domain of its own drops the old link and lets VirtualHost.save()
        # resolve the new one (creating the Domain if it does not exist).
        if renamed and 'domain_id' not in body:
            vh.domain = None

        try:
            vh.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        vh.refresh_from_db()
        return JsonResponse(_serialize_virtualhost_detail(vh))

    if request.method == 'DELETE':
        name, addr = vh.name, vh.ip_address.ip_address
        vh.delete()
        return JsonResponse({'deleted': True, 'id': vh_id, 'name': name, 'ip_address': addr})

    return _err('Method not allowed', 405)


# ─── Base domains (root domains) ──────────────────────────────────────────────

@csrf_exempt
@require_api_key
def basedomains(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    page, per_page = _paginate(request)
    qs = BaseDomain.objects.prefetch_related('tags').all()

    search = request.GET.get('search', '').strip()
    if search:
        qs = qs.filter(name__icontains=search)
    scope = request.GET.get('scope', 'all')
    if scope == 'active':
        qs = qs.filter(active_scope=True)
    elif scope == 'passive':
        qs = qs.filter(passive_scope=True)
    tag = request.GET.get('tag', '').strip()
    if tag:
        qs = qs.filter(tags__name__iexact=tag)

    qs = qs.order_by('name').distinct()
    return _paginated_response(qs, _serialize_basedomain_summary, page, per_page)


@csrf_exempt
@require_api_key
def basedomain_detail(request, basedomain_id):
    bd = get_object_or_404(BaseDomain, pk=basedomain_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_basedomain_detail(bd))

    if request.method == 'PATCH':
        # Root domains are created implicitly (by Domain.save() and by the user
        # endpoints), and renaming one would orphan every child Domain that
        # resolves against it, so only scope and tags are writable here.
        body, err = _parse_body(request)
        if err:
            return err
        e = _apply_fields(bd, body, BASEDOMAIN_FIELDS)
        if e:
            return _err(e)
        bd.save()
        err = _set_tags(bd, body)
        if err:
            return err
        return JsonResponse(_serialize_basedomain_detail(bd))

    return _err('Method not allowed', 405)


def _apply_url_vuln_output(u, body, port):
    """Set/clear Url.vuln_output from a request body. Returns an error string.

    ``vuln_output_id: null`` clears the link. The output row has to be on the
    same port as the URL — an output row is per (vuln, port), so pointing a URL
    at one belonging to a different port would record evidence against a host
    and port that never served it.
    """
    if 'vuln_output_id' not in body:
        return None
    raw = body['vuln_output_id']
    if raw in (None, '', 0):
        u.vuln_output = None
        return None
    try:
        vo = VulnOutput.objects.select_related('vulnerability').get(pk=int(raw))
    except (ValueError, TypeError, VulnOutput.DoesNotExist):
        return f"VulnOutput with id={raw!r} not found"
    if vo.port_id != port.id:
        return (
            f"VulnOutput {vo.id} is recorded against port {vo.port_id}, "
            f"but this URL is on port {port.id}"
        )
    u.vuln_output = vo
    return None


# ─── URLs ─────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_api_key
def urls(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = Url.objects.select_related(
            'port', 'port__ip_address', 'vuln_output', 'vuln_output__vulnerability',
        ).all()

        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(name__icontains=search)
        method = request.GET.get('method', '').strip()
        if method:
            qs = qs.filter(method__iexact=method)
        port_id = request.GET.get('port_id', '').strip()
        if port_id:
            try:
                qs = qs.filter(port_id=int(port_id))
            except (ValueError, TypeError):
                return _err("'port_id' must be an integer")
        ip_filter = request.GET.get('ip', '').strip()
        if ip_filter:
            qs = qs.filter(port__ip_address__ip_address__icontains=ip_filter)
        vuln_output_id = request.GET.get('vuln_output_id', '').strip()
        if vuln_output_id:
            if vuln_output_id.lower() in ('none', 'null'):
                qs = qs.filter(vuln_output__isnull=True)
            else:
                try:
                    qs = qs.filter(vuln_output_id=int(vuln_output_id))
                except (ValueError, TypeError):
                    return _err("'vuln_output_id' must be an integer, 'none', or 'null'")
        vuln_id = request.GET.get('vuln_id', '').strip()
        if vuln_id:
            try:
                qs = qs.filter(vuln_output__vulnerability_id=int(vuln_id))
            except (ValueError, TypeError):
                return _err("'vuln_id' must be an integer")
        scope = request.GET.get('scope', 'all')
        if scope == 'active':
            qs = qs.filter(active_scope=True)
        elif scope == 'passive':
            qs = qs.filter(passive_scope=True)

        qs = qs.order_by('name', 'method')
        return _paginated_response(qs, _serialize_url, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        if 'port_id' not in body:
            return _err("'port_id' is required")
        try:
            port = Port.objects.get(pk=int(body['port_id']))
        except (ValueError, TypeError, Port.DoesNotExist):
            return _err(f"Port with id={body.get('port_id')!r} not found", 404)
        name = str(body.get('name', '') or '').strip()
        if not name:
            return _err("'name' is required")
        method = str(body.get('method', 'get') or 'get').strip().lower()

        u = Url.objects.select_related(
            'port', 'port__ip_address', 'vuln_output', 'vuln_output__vulnerability',
        ).filter(
            port=port, name=name, method=method,
        ).first()
        created = u is None
        if created:
            u = Url(port=port, name=name, method=method)

        e = _apply_fields(u, body, URL_FIELDS)
        if e:
            return _err(e)
        e = _apply_url_vuln_output(u, body, port)
        if e:
            return _err(e)
        u.name, u.method = name, method
        u.save()
        out = _serialize_url(u)
        out['created'] = created
        return JsonResponse(out, status=201 if created else 200)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
def url_detail(request, url_id):
    u = get_object_or_404(
        Url.objects.select_related(
            'port', 'port__ip_address', 'vuln_output', 'vuln_output__vulnerability',
        ),
        pk=url_id,
    )

    if request.method == 'GET':
        return JsonResponse(_serialize_url(u))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        if 'port_id' in body:
            try:
                u.port = Port.objects.get(pk=int(body['port_id']))
            except (ValueError, TypeError, Port.DoesNotExist):
                return _err(f"Port with id={body.get('port_id')!r} not found", 404)
        e = _apply_fields(u, body, URL_FIELDS)
        if e:
            return _err(e)
        e = _apply_url_vuln_output(u, body, u.port)
        if e:
            return _err(e)
        # Moving a URL to another port orphans an output link on the old port.
        if u.vuln_output_id and u.vuln_output.port_id != u.port_id:
            u.vuln_output = None
        u.save()
        return JsonResponse(_serialize_url(u))

    if request.method == 'DELETE':
        name = u.name
        u.delete()
        return JsonResponse({'deleted': True, 'id': url_id, 'name': name})

    return _err('Method not allowed', 405)


# ─── Users ────────────────────────────────────────────────────────────────────

def _resolve_basedomain(body, email=''):
    """Resolve the BaseDomain for a user. Returns (basedomain, error_response).

    Accepts an explicit basedomain_id, a domain name (get_or_create, the same
    path TheHarvester takes), or falls back to the domain part of the email.
    """
    raw = body.get('basedomain_id')
    if raw not in (None, ''):
        try:
            return BaseDomain.objects.get(pk=int(raw)), None
        except (ValueError, TypeError, BaseDomain.DoesNotExist):
            return None, _err(f"BaseDomain with id={raw!r} not found", 404)

    name = str(body.get('domain', '') or '').strip().lower()
    if not name and email and '@' in email:
        name = email.split('@')[-1].strip().lower()
    if not name:
        return None, _err(
            "Provide 'basedomain_id' or 'domain', or an 'email' to derive the domain from"
        )
    bd, _ = BaseDomain.objects.get_or_create(name=name)
    return bd, None


def _user_qs():
    return User.objects.select_related('domain').prefetch_related('tags', 'cred_set')


@csrf_exempt
@require_api_key
def users(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = _user_qs()

        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(email__icontains=search) |
                Q(user_name__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        basedomain_id = request.GET.get('basedomain_id', '').strip()
        if basedomain_id:
            try:
                qs = qs.filter(domain_id=int(basedomain_id))
            except (ValueError, TypeError):
                return _err("'basedomain_id' must be an integer")
        domain = request.GET.get('domain', '').strip()
        if domain:
            qs = qs.filter(domain__name__icontains=domain)
        tag = request.GET.get('tag', '').strip()
        if tag:
            qs = qs.filter(tags__name__iexact=tag)
        scope = request.GET.get('scope', 'all')
        if scope == 'active':
            qs = qs.filter(active_scope=True)
        elif scope == 'passive':
            qs = qs.filter(passive_scope=True)

        qs = qs.order_by('email').distinct()
        return _paginated_response(qs, _serialize_user_summary, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        email = str(body.get('email', '') or '').strip()
        if not email:
            return _err("'email' is required")

        bd, err = _resolve_basedomain(body, email)
        if err:
            return err

        u = _user_qs().filter(email=email).first()
        created = u is None
        if created:
            u = User(email=email, domain=bd)
        elif 'basedomain_id' in body or 'domain' in body:
            u.domain = bd

        e = _apply_fields(u, body, USER_FIELDS)
        if e:
            return _err(e)
        u.email = email
        try:
            u.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        err = _set_tags(u, body)
        if err:
            return err
        out = _serialize_user_detail(u)
        out['created'] = created
        return JsonResponse(out, status=201 if created else 200)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
def user_detail(request, user_id):
    u = get_object_or_404(_user_qs(), pk=user_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_user_detail(u))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        if 'basedomain_id' in body or 'domain' in body:
            bd, err = _resolve_basedomain(body, str(body.get('email', '') or u.email))
            if err:
                return err
            u.domain = bd
        e = _apply_fields(u, body, USER_FIELDS)
        if e:
            return _err(e)
        try:
            u.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        err = _set_tags(u, body)
        if err:
            return err
        return JsonResponse(_serialize_user_detail(u))

    if request.method == 'DELETE':
        email = u.email
        u.delete()
        return JsonResponse({'deleted': True, 'id': user_id, 'email': email})

    return _err('Method not allowed', 405)


# ─── Credentials ──────────────────────────────────────────────────────────────

def _cred_qs():
    return Cred.objects.select_related('user').prefetch_related('tags')


def _resolve_cred_user(body):
    """Returns (user, error_response). Accepts user_id, or an email to look up."""
    raw = body.get('user_id')
    if raw not in (None, ''):
        try:
            return User.objects.get(pk=int(raw)), None
        except (ValueError, TypeError, User.DoesNotExist):
            return None, _err(f"User with id={raw!r} not found", 404)

    email = str(body.get('email', '') or '').strip()
    if not email:
        return None, _err("Provide 'user_id' or 'email'")
    user = User.objects.filter(email=email).first()
    if user:
        return user, None
    bd, err = _resolve_basedomain(body, email)
    if err:
        return None, err
    return User.objects.create(email=email, domain=bd), None


@csrf_exempt
@require_api_key
def creds(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = _cred_qs()

        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(user__email__icontains=search) |
                Q(user__user_name__icontains=search) |
                Q(password__icontains=search) |
                Q(source__icontains=search)
            )
        user_id = request.GET.get('user_id', '').strip()
        if user_id:
            try:
                qs = qs.filter(user_id=int(user_id))
            except (ValueError, TypeError):
                return _err("'user_id' must be an integer")
        source = request.GET.get('source', '').strip()
        if source:
            qs = qs.filter(source__icontains=source)
        has_password = _bool_param(request, 'has_password')
        if has_password is True:
            qs = qs.exclude(Q(password__isnull=True) | Q(password=''))
        elif has_password is False:
            qs = qs.filter(Q(password__isnull=True) | Q(password=''))
        has_hash = _bool_param(request, 'has_hash')
        if has_hash is True:
            qs = qs.exclude(Q(passhash__isnull=True) | Q(passhash=''))
        elif has_hash is False:
            qs = qs.filter(Q(passhash__isnull=True) | Q(passhash=''))
        tag = request.GET.get('tag', '').strip()
        if tag:
            qs = qs.filter(tags__name__iexact=tag)

        qs = qs.order_by('user__email', 'id').distinct()
        return _paginated_response(qs, _serialize_cred, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        user, err = _resolve_cred_user(body)
        if err:
            return err

        password = str(body.get('password', '') or '').strip()
        passhash = str(body.get('passhash', '') or '').strip()
        if not password and not passhash:
            return _err("Provide 'password' or 'passhash' (or both)")

        # Repeated imports of the same dump should not stack duplicate rows.
        c = _cred_qs().filter(
            user=user, password=password or None, passhash=passhash or None,
        ).first()
        created = c is None
        if created:
            c = Cred(user=user, password=password or None, passhash=passhash or None)

        e = _apply_fields(c, body, CRED_FIELDS)
        if e:
            return _err(e)
        c.user = user
        c.password = password or None
        c.passhash = passhash or None
        c.save()
        err = _set_tags(c, body)
        if err:
            return err
        out = _serialize_cred(c)
        out['created'] = created
        return JsonResponse(out, status=201 if created else 200)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
def cred_detail(request, cred_id):
    c = get_object_or_404(_cred_qs(), pk=cred_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_cred(c))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        if 'user_id' in body or 'email' in body:
            user, err = _resolve_cred_user(body)
            if err:
                return err
            c.user = user
        e = _apply_fields(c, body, CRED_FIELDS)
        if e:
            return _err(e)
        c.save()
        err = _set_tags(c, body)
        if err:
            return err
        return JsonResponse(_serialize_cred(c))

    if request.method == 'DELETE':
        c.delete()
        return JsonResponse({'deleted': True, 'id': cred_id})

    return _err('Method not allowed', 405)


# ─── CVEs ─────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_api_key
def cves(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = CVE.objects.all()

        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(Q(name__icontains=search) | Q(description__icontains=search))
        min_score = request.GET.get('min_score', '').strip()
        if min_score:
            try:
                qs = qs.filter(temporal_score__gte=float(min_score))
            except (ValueError, TypeError):
                return _err("'min_score' must be a number")
        updated = _bool_param(request, 'updated')
        if updated is not None:
            qs = qs.filter(updated=updated)

        qs = qs.order_by('-temporal_score', 'name')
        return _paginated_response(qs, _serialize_cve_summary, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        name = str(body.get('name', '') or '').strip()
        if not name:
            return _err("'name' is required")

        c = CVE.objects.filter(name=name).first()
        created = c is None
        if created:
            c = CVE(name=name)

        e = _apply_fields(c, body, CVE_FIELDS)
        if e:
            return _err(e)
        c.name = name
        c.save()
        if 'vuln_ids' in body:
            err = _set_m2m(c.vulnerability_set, body['vuln_ids'], Vulnerability, 'vuln_ids')
            if err:
                return err
        out = _serialize_cve_detail(c)
        out['created'] = created
        return JsonResponse(out, status=201 if created else 200)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
def cve_detail(request, cve_id):
    c = get_object_or_404(CVE, pk=cve_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_cve_detail(c))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        e = _apply_fields(c, body, CVE_FIELDS)
        if e:
            return _err(e)
        c.save()
        if 'vuln_ids' in body:
            err = _set_m2m(c.vulnerability_set, body['vuln_ids'], Vulnerability, 'vuln_ids')
            if err:
                return err
        return JsonResponse(_serialize_cve_detail(c))

    if request.method == 'DELETE':
        name = c.name
        c.delete()
        return JsonResponse({'deleted': True, 'id': cve_id, 'name': name})

    return _err('Method not allowed', 405)


# ─── Tags ─────────────────────────────────────────────────────────────────────

def _tag_usage(t):
    return {
        'hosts': [
            {'id': o.id, 'ip_address': o.ip_address} for o in t.ipaddress_set.all()
        ],
        'ports': [
            {'id': o.id, 'port_number': o.port_number, 'ip_address': o.ip_address.ip_address}
            for o in t.port_set.select_related('ip_address').all()
        ],
        'domains': [{'id': o.id, 'name': o.name} for o in t.domain_set.all()],
        'basedomains': [{'id': o.id, 'name': o.name} for o in t.basedomain_set.all()],
        'users': [{'id': o.id, 'email': o.email} for o in t.user_set.all()],
        'creds': [{'id': o.id, 'user_id': o.user_id} for o in t.cred_set.all()],
    }


def _serialize_tag_detail(t):
    usage = _tag_usage(t)
    out = _serialize_tag(t)
    out['usage'] = usage
    out['usage_count'] = sum(len(v) for v in usage.values())
    return out


def _serialize_tag_summary(t):
    out = _serialize_tag(t)
    out['usage_count'] = (
        t.ipaddress_set.count() + t.port_set.count() + t.domain_set.count() +
        t.basedomain_set.count() + t.user_set.count() + t.cred_set.count()
    )
    return out


@csrf_exempt
@require_api_key
def tags(request):
    if request.method == 'GET':
        page, per_page = _paginate(request)
        qs = Tag.objects.all()

        search = request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(name__icontains=search)
        tag_type = request.GET.get('type', '').strip()
        if tag_type:
            valid = [c[0] for c in Tag.TYPE_CHOICES]
            if tag_type not in valid:
                return _err(f"'type' must be one of {valid}")
            qs = qs.filter(type=tag_type)

        return _paginated_response(qs, _serialize_tag_summary, page, per_page)

    if request.method == 'POST':
        body, err = _parse_body(request)
        if err:
            return err
        name = str(body.get('name', '') or '').strip()
        if not name:
            return _err("'name' is required")
        tag_type = str(body.get('type', Tag.TYPE_ANY) or Tag.TYPE_ANY).strip()
        valid = [c[0] for c in Tag.TYPE_CHOICES]
        if tag_type not in valid:
            return _err(f"'type' must be one of {valid}")

        existing = Tag.objects.filter(name=name).first()
        if existing:
            if 'type' in body and existing.type != tag_type:
                return _err(
                    f"Tag '{name}' already exists with type '{existing.type}'. "
                    f"PATCH /armory_api/tags/{existing.id} to change it.",
                    409,
                )
            out = _serialize_tag_detail(existing)
            out['created'] = False
            return JsonResponse(out)

        t = Tag.objects.create(name=name, type=tag_type)
        out = _serialize_tag_detail(t)
        out['created'] = True
        return JsonResponse(out, status=201)

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
def tag_detail(request, tag_id):
    t = get_object_or_404(Tag, pk=tag_id)

    if request.method == 'GET':
        return JsonResponse(_serialize_tag_detail(t))

    if request.method == 'PATCH':
        body, err = _parse_body(request)
        if err:
            return err
        if 'type' in body:
            valid = [c[0] for c in Tag.TYPE_CHOICES]
            if str(body['type']).strip() not in valid:
                return _err(f"'type' must be one of {valid}")
        e = _apply_fields(t, body, TAG_FIELDS)
        if e:
            return _err(e)
        try:
            t.save()
        except IntegrityError as ex:
            return _err(f"Conflict: {ex}", 409)
        return JsonResponse(_serialize_tag_detail(t))

    if request.method == 'DELETE':
        name = t.name
        t.delete()
        return JsonResponse({'deleted': True, 'id': tag_id, 'name': name})

    return _err('Method not allowed', 405)


@csrf_exempt
@require_api_key
def tag_apply(request, tag_id):
    """Add or remove one tag across records without rewriting their tag lists."""
    if request.method != 'POST':
        return _err('Method not allowed', 405)

    t = get_object_or_404(Tag, pk=tag_id)
    body, err = _parse_body(request)
    if err:
        return err

    action = str(body.get('action', 'add') or 'add').strip().lower()
    if action not in ('add', 'remove'):
        return _err("'action' must be 'add' or 'remove'")

    targets = {k: v for k, v in body.items() if k in TAGGABLE}
    if not targets:
        return _err(f"Provide at least one of {sorted(TAGGABLE)}")

    changed = {}
    for key, ids in targets.items():
        model = TAGGABLE[key]
        kind = TAG_KIND[model.__name__]
        if not _tag_fits(t, kind):
            return _err(
                f"Tag '{t.name}' is a {t.type} tag and cannot be applied to {key}"
            )
        if not isinstance(ids, list):
            return _err(f"'{key}' must be a list of integers")
        try:
            clean = [int(i) for i in ids]
        except (ValueError, TypeError):
            return _err(f"'{key}' must be a list of integers")
        found = list(model.objects.filter(pk__in=clean))
        missing = set(clean) - {o.id for o in found}
        if missing:
            return _err(f"{model.__name__} not found: {sorted(missing)}", 404)
        for obj in found:
            if action == 'add':
                obj.tags.add(t)
            else:
                obj.tags.remove(t)
        changed[key] = len(found)

    out = _serialize_tag_detail(t)
    out['action'] = action
    out['changed'] = changed
    return JsonResponse(out)


# ─── Tool runs (read-only history) ────────────────────────────────────────────

@csrf_exempt
@require_api_key
def toolruns(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    page, per_page = _paginate(request)
    qs = ToolRun.objects.select_related(
        'port_obj', 'virtualhost', 'content_type',
    ).all()

    tool = request.GET.get('tool', '').strip()
    if tool:
        qs = qs.filter(tool__icontains=tool)
    search = request.GET.get('search', '').strip()
    if search:
        qs = qs.filter(Q(tool__icontains=search) | Q(args__icontains=search))
    port_id = request.GET.get('port_id', '').strip()
    if port_id:
        try:
            qs = qs.filter(port_obj_id=int(port_id))
        except (ValueError, TypeError):
            return _err("'port_id' must be an integer")
    vh_id = request.GET.get('virtualhost_id', '').strip()
    if vh_id:
        try:
            qs = qs.filter(virtualhost_id=int(vh_id))
        except (ValueError, TypeError):
            return _err("'virtualhost_id' must be an integer")
    ip_filter = request.GET.get('ip', '').strip()
    if ip_filter:
        # A run may hang off the host, off one of its ports (either through the
        # generic relation or the port_obj FK), or off a virtual host on it —
        # "everything run against this IP" has to cover all four.
        qs = qs.filter(
            Q(ip_addresses__ip_address__icontains=ip_filter) |
            Q(ports__ip_address__ip_address__icontains=ip_filter) |
            Q(port_obj__ip_address__ip_address__icontains=ip_filter) |
            Q(virtualhost__ip_address__ip_address__icontains=ip_filter)
        )
    target_type = request.GET.get('target_type', '').strip()
    if target_type:
        qs = qs.filter(content_type__model=target_type.lower())

    qs = qs.order_by('-created_at', '-id').distinct()
    return _paginated_response(qs, _serialize_toolrun, page, per_page)


@csrf_exempt
@require_api_key
def toolrun_detail(request, toolrun_id):
    if request.method != 'GET':
        return _err('Method not allowed', 405)
    tr = get_object_or_404(
        ToolRun.objects.select_related('port_obj', 'virtualhost', 'content_type'),
        pk=toolrun_id,
    )
    return JsonResponse(_serialize_toolrun(tr))


@csrf_exempt
@require_api_key
def stats(request):
    if request.method != 'GET':
        return _err('Method not allowed', 405)

    ip_qs = IPAddress.objects.all()
    port_qs = Port.objects.all()
    vuln_qs = Vulnerability.objects.all()
    domain_qs = Domain.objects.all()
    cidr_qs = CIDR.objects.all()
    vh_qs = VirtualHost.objects.all()
    user_qs = User.objects.all()
    cred_qs = Cred.objects.all()

    vuln_by_severity = {
        label: vuln_qs.filter(severity=sev).count()
        for sev, label in SEV_LABELS.items()
    }

    return JsonResponse({
        'hosts': {
            'total':          ip_qs.count(),
            'active':         ip_qs.filter(active_scope=True).count(),
            'passive':        ip_qs.filter(passive_scope=True).count(),
            'completed':      ip_qs.filter(completed=True).count(),
            'recon_complete': ip_qs.filter(recon_complete=True).count(),
        },
        'ports': {
            'total':          port_qs.count(),
            'http':           port_qs.filter(service_name='http').count(),
            'https':          port_qs.filter(service_name='https').count(),
            'unique_services': port_qs.values('service_name').distinct().count(),
            'recon_complete': port_qs.filter(recon_complete=True).count(),
        },
        'vulnerabilities': {
            'total':       vuln_qs.count(),
            'exploitable': vuln_qs.filter(exploitable=True).count(),
            'output_rows': VulnOutput.objects.count(),
            **vuln_by_severity,
        },
        'domains': {
            'total':          domain_qs.count(),
            'active':         domain_qs.filter(active_scope=True).count(),
            'passive':        domain_qs.filter(passive_scope=True).count(),
            'recon_complete': domain_qs.filter(recon_complete=True).count(),
        },
        'cidrs': {
            'total':  cidr_qs.count(),
            'active': cidr_qs.filter(active_scope=True).count(),
        },
        'virtualhosts': {
            'total':        vh_qs.count(),
            'active':       vh_qs.filter(active=True).count(),
            'unique_names': vh_qs.values('name').distinct().count(),
        },
        'basedomains': {
            'total':  BaseDomain.objects.count(),
            'active': BaseDomain.objects.filter(active_scope=True).count(),
        },
        'urls': {
            'total':           Url.objects.count(),
            'unique_names':    Url.objects.values('name').distinct().count(),
        },
        'users': {
            'total':       user_qs.count(),
            'with_creds':  user_qs.filter(cred__isnull=False).distinct().count(),
        },
        'creds': {
            'total':          cred_qs.count(),
            'with_password':  cred_qs.exclude(Q(password__isnull=True) | Q(password='')).count(),
            'with_hash':      cred_qs.exclude(Q(passhash__isnull=True) | Q(passhash='')).count(),
        },
        'cves': {
            'total':     CVE.objects.count(),
            'linked':    CVE.objects.filter(vulnerability__isnull=False).distinct().count(),
        },
        'tags': {'total': Tag.objects.count()},
        'toolruns': {
            'total':         ToolRun.objects.count(),
            'unique_tools':  ToolRun.objects.values('tool').distinct().count(),
        },
    })


@csrf_exempt
@require_api_key
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
    matched_vhosts = _vh_related(VirtualHost.objects.filter(name__icontains=q))[:limit]
    matched_basedomains = BaseDomain.objects.prefetch_related('tags').filter(
        name__icontains=q
    )[:limit]
    matched_urls = Url.objects.select_related('port', 'port__ip_address').filter(
        name__icontains=q
    )[:limit]
    matched_users = _user_qs().filter(
        Q(email__icontains=q) | Q(user_name__icontains=q) |
        Q(first_name__icontains=q) | Q(last_name__icontains=q)
    )[:limit]
    matched_cves = CVE.objects.filter(name__icontains=q)[:limit]
    matched_tags = Tag.objects.filter(name__icontains=q)[:limit]

    return JsonResponse({
        'query': q,
        'hosts': [_serialize_ip_summary(ip) for ip in matched_ips],
        'domains': [_serialize_domain_summary(d) for d in matched_domains],
        'vulnerabilities': [_serialize_vuln_summary(v) for v in matched_vulns],
        'ports': [_serialize_port_summary(p) for p in matched_ports],
        'virtualhosts': [_serialize_virtualhost_summary(v) for v in matched_vhosts],
        'basedomains': [_serialize_basedomain_summary(b) for b in matched_basedomains],
        'urls': [_serialize_url(u) for u in matched_urls],
        'users': [_serialize_user_summary(u) for u in matched_users],
        'cves': [_serialize_cve_summary(c) for c in matched_cves],
        'tags': [_serialize_tag(t) for t in matched_tags],
    })


# ─── Shell command execution ──────────────────────────────────────────────────

def _exec_unavailable():
    """Return an error response if shell execution must not run, else None.

    Two gates. ARMORY_API_EXEC_ENABLED lets an operator turn the facility off
    entirely. The default-key check is not optional: the built-in SECRET_KEY is
    published in this repo, so an install that never set its own would otherwise
    hand a shell to anyone who can reach the port.
    """
    if not getattr(django_settings, 'ARMORY_API_EXEC_ENABLED', True):
        return _err(
            'Shell execution is disabled on this server. Set '
            'ARMORY_API_EXEC_ENABLED = True in ~/.armory/settings.py to enable it.',
            status=403,
        )
    if getattr(django_settings, 'ARMORY_API_KEY_IS_DEFAULT', False):
        return _err(
            'Shell execution is refused while the API key is the built-in default, '
            'which is public. Set a SECRET_KEY in ~/.armory/settings.py first.',
            status=403,
        )
    return None


def _int_param(request, name, default, minimum, maximum):
    try:
        return min(maximum, max(minimum, int(request.GET.get(name, default))))
    except (ValueError, TypeError):
        return default


@csrf_exempt
@require_api_key
def exec_commands(request):
    unavailable = _exec_unavailable()
    if unavailable:
        return unavailable

    if request.method == 'GET':
        status = request.GET.get('status', '').strip() or None
        search_term = request.GET.get('search', '').strip() or None
        limit = _int_param(request, 'limit', 20, 1, 200)
        jobs = exec_runner.all_jobs(status=status, search=search_term)
        return JsonResponse({
            'total': len(jobs),
            'results': [exec_runner.serialize(j, include_output=False) for j in jobs[:limit]],
        })

    if request.method != 'POST':
        return _err('Method not allowed', 405)

    body, err = _parse_body(request)
    if err:
        return err

    command = str(body.get('command', '') or '').strip()
    if not command:
        return _err("'command' is required")

    cwd = str(body.get('cwd', '') or '').strip()
    if cwd:
        cwd = os.path.expanduser(cwd)
        if not os.path.isdir(cwd):
            return _err(f"cwd is not a directory: {cwd}", 404)
    else:
        cwd = None

    try:
        timeout = int(body.get('timeout', exec_runner.DEFAULT_TIMEOUT))
    except (ValueError, TypeError):
        return _err("Invalid value for 'timeout'")
    if timeout < 1 or timeout > exec_runner.MAX_TIMEOUT:
        return _err(f"'timeout' must be between 1 and {exec_runner.MAX_TIMEOUT} seconds")

    env = body.get('env')
    if env is not None and not isinstance(env, dict):
        return _err("'env' must be a JSON object of environment variables")

    background = _coerce(body.get('background', False), bool)

    try:
        tail = int(body.get('tail', 0))
    except (ValueError, TypeError):
        return _err("Invalid value for 'tail'")

    job = exec_runner.run(
        command, cwd=cwd, timeout=timeout, env=env, background=background,
    )
    return JsonResponse(exec_runner.serialize(job, tail=max(0, tail)), status=201)


@csrf_exempt
@require_api_key
def exec_command_detail(request, job_id):
    unavailable = _exec_unavailable()
    if unavailable:
        return unavailable

    job = exec_runner.get(job_id)
    if job is None:
        return _err(f'Command job not found: {job_id}', 404)

    if request.method == 'GET':
        wait_for = _int_param(request, 'wait', 0, 0, exec_runner.MAX_TIMEOUT)
        if wait_for:
            exec_runner.wait(job, wait_for)
        tail = _int_param(request, 'tail', 0, 0, exec_runner.DEFAULT_MAX_OUTPUT)
        return JsonResponse(exec_runner.serialize(job, tail=tail))

    if request.method == 'DELETE':
        killed = exec_runner.kill(job)
        result = exec_runner.serialize(job, include_output=False)
        result['killed'] = killed
        if not killed:
            result['message'] = 'Job had already finished; nothing to kill'
        return JsonResponse(result)

    return _err('Method not allowed', 405)
