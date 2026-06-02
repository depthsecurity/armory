import json
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.db.models import Q
from armory2.armory_main.models import (
    Tag, CIDR, BaseDomain, Domain, IPAddress, Port, VirtualHost,
    Vulnerability, CVE, VulnOutput, Url, User, Cred,
)

SEVERITY_CHOICES = [(0, 'Info'), (1, 'Low'), (2, 'Medium'), (3, 'High'), (4, 'Critical')]
PROTO_CHOICES = [('tcp', 'TCP'), ('udp', 'UDP')]
METHOD_CHOICES = [
    ('get', 'GET'), ('post', 'POST'), ('put', 'PUT'),
    ('delete', 'DELETE'), ('patch', 'PATCH'), ('head', 'HEAD'), ('options', 'OPTIONS'),
]

# ---------------------------------------------------------------------------
# Model registry — drives list columns, form fields, search, ordering.
#
# Field types: text, textarea, number, float, checkbox, select, fk, m2m
# Column types (for display): bool, severity, fk  (default: plain text)
# ---------------------------------------------------------------------------

MODEL_CONFIGS = {
    'tag': {
        'model': Tag,
        'label': 'Tag',
        'plural': 'Tags',
        'columns': [
            {'key': 'name', 'label': 'Name'},
            {'key': 'type', 'label': 'Type'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'Name', 'required': True},
            {'name': 'type', 'type': 'select', 'label': 'Type',
             'choices': Tag.TYPE_CHOICES, 'default': 'any'},
        ],
        'search': ['name'],
        'order_by': 'name',
    },
    'cidr': {
        'model': CIDR,
        'label': 'CIDR',
        'plural': 'CIDRs',
        'columns': [
            {'key': 'name', 'label': 'CIDR'},
            {'key': 'org_name', 'label': 'Organization'},
            {'key': 'size', 'label': 'Size'},
            {'key': 'cloud', 'label': 'Cloud', 'type': 'bool'},
            {'key': 'active_scope', 'label': 'Active', 'type': 'bool'},
            {'key': 'passive_scope', 'label': 'Passive', 'type': 'bool'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'CIDR Notation', 'required': True},
            {'name': 'org_name', 'type': 'text', 'label': 'Organization'},
            {'name': 'cloud', 'type': 'checkbox', 'label': 'Cloud Provider'},
            {'name': 'active_scope', 'type': 'checkbox', 'label': 'Active Scope'},
            {'name': 'passive_scope', 'type': 'checkbox', 'label': 'Passive Scope'},
        ],
        'search': ['name', 'org_name'],
        'order_by': 'name',
    },
    'basedomain': {
        'model': BaseDomain,
        'label': 'Base Domain',
        'plural': 'Base Domains',
        'columns': [
            {'key': 'name', 'label': 'Name'},
            {'key': 'active_scope', 'label': 'Active', 'type': 'bool'},
            {'key': 'passive_scope', 'label': 'Passive', 'type': 'bool'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'Domain Name', 'required': True},
            {'name': 'active_scope', 'type': 'checkbox', 'label': 'Active Scope'},
            {'name': 'passive_scope', 'type': 'checkbox', 'label': 'Passive Scope'},
            {'name': 'tags', 'type': 'm2m', 'label': 'Tags',
             'queryset': lambda: Tag.objects.filter(type__in=['domain', 'any']).order_by('name'),
             'display': str},
        ],
        'search': ['name'],
        'order_by': 'name',
    },
    'domain': {
        'model': Domain,
        'label': 'Domain',
        'plural': 'Domains',
        'columns': [
            {'key': 'name', 'label': 'Name'},
            {'key': 'basedomain', 'label': 'Base Domain', 'type': 'fk'},
            {'key': 'dynamic_ip', 'label': 'Dynamic', 'type': 'bool'},
            {'key': 'active_scope', 'label': 'Active', 'type': 'bool'},
            {'key': 'passive_scope', 'label': 'Passive', 'type': 'bool'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'Domain Name', 'required': True,
             'hint': 'Base domain is resolved automatically from the name.'},
            {'name': 'active_scope', 'type': 'checkbox', 'label': 'Active Scope'},
            {'name': 'passive_scope', 'type': 'checkbox', 'label': 'Passive Scope'},
            {'name': 'dynamic_ip', 'type': 'checkbox', 'label': 'Dynamic IP'},
            {'name': 'is_ptr', 'type': 'checkbox', 'label': 'PTR Record'},
            {'name': 'tags', 'type': 'm2m', 'label': 'Tags',
             'queryset': lambda: Tag.objects.filter(type__in=['domain', 'any']).order_by('name'),
             'display': str},
        ],
        'search': ['name'],
        'order_by': 'name',
    },
    'ipaddress': {
        'model': IPAddress,
        'label': 'IP Address',
        'plural': 'IP Addresses',
        'columns': [
            {'key': 'ip_address', 'label': 'IP Address'},
            {'key': 'os', 'label': 'OS'},
            {'key': 'completed', 'label': 'Done', 'type': 'bool'},
            {'key': 'active_scope', 'label': 'Active', 'type': 'bool'},
            {'key': 'passive_scope', 'label': 'Passive', 'type': 'bool'},
        ],
        'fields': [
            {'name': 'ip_address', 'type': 'text', 'label': 'IP Address', 'required': True,
             'hint': 'CIDR and version are resolved automatically.'},
            {'name': 'os', 'type': 'text', 'label': 'Operating System'},
            {'name': 'notes', 'type': 'textarea', 'label': 'Notes'},
            {'name': 'completed', 'type': 'checkbox', 'label': 'Mark Completed'},
            {'name': 'active_scope', 'type': 'checkbox', 'label': 'Active Scope'},
            {'name': 'passive_scope', 'type': 'checkbox', 'label': 'Passive Scope'},
            {'name': 'tags', 'type': 'm2m', 'label': 'Tags',
             'queryset': lambda: Tag.objects.filter(type__in=['ip', 'any']).order_by('name'),
             'display': str},
        ],
        'search': ['ip_address', 'os'],
        'order_by': 'ip_address',
    },
    'port': {
        'model': Port,
        'label': 'Port',
        'plural': 'Ports',
        'columns': [
            {'key': 'ip_address', 'label': 'IP', 'type': 'fk'},
            {'key': 'port_number', 'label': 'Port'},
            {'key': 'proto', 'label': 'Proto'},
            {'key': 'service_name', 'label': 'Service'},
            {'key': 'status', 'label': 'Status'},
        ],
        'fields': [
            {'name': 'ip_address', 'type': 'fk', 'label': 'IP Address', 'required': True,
             'queryset': lambda: IPAddress.objects.all().order_by('ip_address'),
             'display': lambda o: o.ip_address},
            {'name': 'port_number', 'type': 'number', 'label': 'Port Number', 'required': True},
            {'name': 'proto', 'type': 'select', 'label': 'Protocol', 'choices': PROTO_CHOICES},
            {'name': 'service_name', 'type': 'text', 'label': 'Service Name'},
            {'name': 'status', 'type': 'text', 'label': 'Status', 'default': 'open'},
            {'name': 'active_scope', 'type': 'checkbox', 'label': 'Active Scope'},
            {'name': 'passive_scope', 'type': 'checkbox', 'label': 'Passive Scope'},
            {'name': 'tags', 'type': 'm2m', 'label': 'Tags',
             'queryset': lambda: Tag.objects.filter(type__in=['ip', 'any']).order_by('name'),
             'display': str},
        ],
        'search': ['ip_address__ip_address', 'service_name'],
        'order_by': 'ip_address__ip_address',
    },
    'virtualhost': {
        'model': VirtualHost,
        'label': 'Virtual Host',
        'plural': 'Virtual Hosts',
        'columns': [
            {'key': 'name', 'label': 'Hostname'},
            {'key': 'ip_address', 'label': 'IP', 'type': 'fk'},
            {'key': 'port', 'label': 'Port', 'type': 'fk'},
            {'key': 'active', 'label': 'Active', 'type': 'bool'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'Hostname', 'required': True},
            {'name': 'ip_address', 'type': 'fk', 'label': 'IP Address', 'required': True,
             'queryset': lambda: IPAddress.objects.all().order_by('ip_address'),
             'display': lambda o: o.ip_address},
            {'name': 'port', 'type': 'fk', 'label': 'Port', 'required': False,
             'queryset': lambda: Port.objects.select_related('ip_address').order_by('ip_address__ip_address', 'port_number'),
             'display': lambda o: f"{o.ip_address.ip_address}:{o.port_number}/{o.proto}"},
            {'name': 'active', 'type': 'checkbox', 'label': 'Active'},
        ],
        'search': ['name', 'ip_address__ip_address'],
        'order_by': 'name',
    },
    'vulnerability': {
        'model': Vulnerability,
        'label': 'Vulnerability',
        'plural': 'Vulnerabilities',
        'columns': [
            {'key': 'name', 'label': 'Name'},
            {'key': 'severity', 'label': 'Severity', 'type': 'severity'},
            {'key': 'exploitable', 'label': 'Exploitable', 'type': 'bool'},
            {'key': 'source', 'label': 'Source'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'Name', 'required': True},
            {'name': 'severity', 'type': 'select', 'label': 'Severity',
             'choices': SEVERITY_CHOICES, 'default': 0},
            {'name': 'description', 'type': 'textarea', 'label': 'Description'},
            {'name': 'remediation', 'type': 'textarea', 'label': 'Remediation'},
            {'name': 'exploitable', 'type': 'checkbox', 'label': 'Exploitable'},
            {'name': 'source', 'type': 'text', 'label': 'Source', 'default': 'manual'},
            {'name': 'ports', 'type': 'm2m', 'label': 'Affected Ports',
             'queryset': lambda: Port.objects.select_related('ip_address').order_by('ip_address__ip_address', 'port_number'),
             'display': lambda o: f"{o.ip_address.ip_address}:{o.port_number}/{o.proto}"},
            {'name': 'cves', 'type': 'm2m', 'label': 'CVEs',
             'queryset': lambda: CVE.objects.order_by('name'),
             'display': str},
        ],
        'search': ['name', 'description'],
        'order_by': 'name',
    },
    'cve': {
        'model': CVE,
        'label': 'CVE',
        'plural': 'CVEs',
        'columns': [
            {'key': 'name', 'label': 'CVE ID'},
            {'key': 'temporal_score', 'label': 'Score'},
            {'key': 'updated', 'label': 'Updated', 'type': 'bool'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'CVE ID', 'required': True},
            {'name': 'description', 'type': 'textarea', 'label': 'Description'},
            {'name': 'temporal_score', 'type': 'float', 'label': 'Temporal Score', 'default': 0.0},
            {'name': 'updated', 'type': 'checkbox', 'label': 'Updated'},
        ],
        'search': ['name', 'description'],
        'order_by': 'name',
    },
    'url': {
        'model': Url,
        'label': 'URL',
        'plural': 'URLs',
        'columns': [
            {'key': 'name', 'label': 'URL'},
            {'key': 'method', 'label': 'Method'},
            {'key': 'port', 'label': 'Port', 'type': 'fk'},
        ],
        'fields': [
            {'name': 'name', 'type': 'text', 'label': 'URL', 'required': True},
            {'name': 'method', 'type': 'select', 'label': 'Method',
             'choices': METHOD_CHOICES, 'default': 'get'},
            {'name': 'port', 'type': 'fk', 'label': 'Port', 'required': True,
             'queryset': lambda: Port.objects.select_related('ip_address').order_by('ip_address__ip_address', 'port_number'),
             'display': lambda o: f"{o.ip_address.ip_address}:{o.port_number}/{o.proto}"},
        ],
        'search': ['name'],
        'order_by': 'name',
    },
    'vulnoutput': {
        'model': VulnOutput,
        'label': 'Vuln Output',
        'plural': 'Vuln Outputs',
        'columns': [
            {'key': 'vulnerability', 'label': 'Vulnerability', 'type': 'fk'},
            {'key': 'port', 'label': 'Port', 'type': 'fk'},
            {'key': 'data', 'label': 'Data Preview', 'truncate': 80},
        ],
        'fields': [
            {'name': 'vulnerability', 'type': 'fk', 'label': 'Vulnerability', 'required': True,
             'queryset': lambda: Vulnerability.objects.order_by('name'),
             'display': lambda o: o.name},
            {'name': 'port', 'type': 'fk', 'label': 'Port', 'required': True,
             'queryset': lambda: Port.objects.select_related('ip_address').order_by('ip_address__ip_address', 'port_number'),
             'display': lambda o: f"{o.ip_address.ip_address}:{o.port_number}/{o.proto}"},
            {'name': 'data', 'type': 'textarea', 'label': 'Output Data'},
        ],
        'search': ['vulnerability__name', 'port__ip_address__ip_address'],
        'order_by': 'vulnerability__name',
    },
    'user': {
        'model': User,
        'label': 'User',
        'plural': 'Users',
        'columns': [
            {'key': 'email', 'label': 'Email'},
            {'key': 'user_name', 'label': 'Username'},
            {'key': 'domain', 'label': 'Domain', 'type': 'fk'},
            {'key': 'job_title', 'label': 'Job Title'},
        ],
        'fields': [
            {'name': 'email', 'type': 'text', 'label': 'Email', 'required': True},
            {'name': 'first_name', 'type': 'text', 'label': 'First Name'},
            {'name': 'last_name', 'type': 'text', 'label': 'Last Name'},
            {'name': 'user_name', 'type': 'text', 'label': 'Username'},
            {'name': 'domain', 'type': 'fk', 'label': 'Domain', 'required': True,
             'queryset': lambda: BaseDomain.objects.order_by('name'),
             'display': lambda o: o.name},
            {'name': 'job_title', 'type': 'text', 'label': 'Job Title'},
            {'name': 'location', 'type': 'text', 'label': 'Location'},
            {'name': 'tags', 'type': 'm2m', 'label': 'Tags',
             'queryset': lambda: Tag.objects.filter(type__in=['cred', 'any']).order_by('name'),
             'display': str},
        ],
        'search': ['email', 'user_name', 'first_name', 'last_name'],
        'order_by': 'email',
    },
    'cred': {
        'model': Cred,
        'label': 'Credential',
        'plural': 'Credentials',
        'columns': [
            {'key': 'user', 'label': 'User', 'type': 'fk'},
            {'key': 'source', 'label': 'Source'},
            {'key': 'password', 'label': 'Password'},
        ],
        'fields': [
            {'name': 'user', 'type': 'fk', 'label': 'User', 'required': True,
             'queryset': lambda: User.objects.order_by('email'),
             'display': lambda o: o.email},
            {'name': 'password', 'type': 'text', 'label': 'Password'},
            {'name': 'passhash', 'type': 'text', 'label': 'Password Hash'},
            {'name': 'source', 'type': 'text', 'label': 'Source'},
            {'name': 'tags', 'type': 'm2m', 'label': 'Tags',
             'queryset': lambda: Tag.objects.filter(type__in=['cred', 'any']).order_by('name'),
             'display': str},
        ],
        'search': ['user__email', 'source'],
        'order_by': 'user__email',
    },
}

SIDEBAR = [
    {'label': 'Network', 'keys': ['cidr', 'ipaddress', 'port', 'domain', 'basedomain', 'virtualhost']},
    {'label': 'Vulnerabilities', 'keys': ['vulnerability', 'cve', 'url', 'vulnoutput']},
    {'label': 'Users & Creds', 'keys': ['user', 'cred']},
    {'label': 'Other', 'keys': ['tag']},
]

PAGE_SIZE = 50

_HX_SUCCESS = json.dumps({'closeModal': {}, 'refreshList': {}})


def index(request):
    sidebar = [
        {
            'label': cat['label'],
            'models': [{'key': k, 'label': MODEL_CONFIGS[k]['plural']} for k in cat['keys']],
        }
        for cat in SIDEBAR
    ]
    return render(request, 'data_manager/index.html', {
        'title': 'Data Manager',
        'sidebar': sidebar,
        'first_model': 'cidr',
    })


def list_model(request, model_key):
    cfg = MODEL_CONFIGS.get(model_key)
    if not cfg:
        return HttpResponse('Not found', status=404)

    search = request.GET.get('search', '').strip()
    page = max(1, int(request.GET.get('page', 1)))

    qs = cfg['model'].objects.all()

    if search and cfg.get('search'):
        q = Q()
        for field in cfg['search']:
            q |= Q(**{f'{field}__icontains': search})
        qs = qs.filter(q)

    if cfg.get('order_by'):
        try:
            qs = qs.order_by(cfg['order_by'])
        except Exception:
            pass

    total = qs.count()
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, total_pages)
    objects = qs[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]

    rows = []
    for obj in objects:
        row = {'id': obj.pk, 'cells': []}
        for col in cfg['columns']:
            row['cells'].append({'col': col, 'value': _get_col_value(obj, col)})
        rows.append(row)

    return render(request, 'data_manager/_list.html', {
        'model_key': model_key,
        'cfg': cfg,
        'rows': rows,
        'search': search,
        'page': page,
        'total': total,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
    })


def create_model(request, model_key):
    cfg = MODEL_CONFIGS.get(model_key)
    if not cfg:
        return HttpResponse('Not found', status=404)

    if request.method == 'POST':
        obj, errors = _save_from_form(cfg, request)
        if not errors:
            resp = HttpResponse(status=204)
            resp['HX-Trigger'] = _HX_SUCCESS
            return resp
        form_fields = _build_form_context(cfg, errors=errors)
        return render(request, 'data_manager/_form.html', {
            'model_key': model_key, 'cfg': cfg,
            'form_fields': form_fields, 'action': 'create',
            'errors': errors, 'form_error': errors.get('form_error', ''),
        })

    form_fields = _build_form_context(cfg)
    return render(request, 'data_manager/_form.html', {
        'model_key': model_key, 'cfg': cfg,
        'form_fields': form_fields, 'action': 'create', 'errors': {}, 'form_error': '',
    })


def edit_model(request, model_key, obj_id):
    cfg = MODEL_CONFIGS.get(model_key)
    if not cfg:
        return HttpResponse('Not found', status=404)

    instance = get_object_or_404(cfg['model'], pk=obj_id)

    if request.method == 'POST':
        obj, errors = _save_from_form(cfg, request, instance)
        if not errors:
            resp = HttpResponse(status=204)
            resp['HX-Trigger'] = _HX_SUCCESS
            return resp
        form_fields = _build_form_context(cfg, instance, errors)
        return render(request, 'data_manager/_form.html', {
            'model_key': model_key, 'cfg': cfg,
            'form_fields': form_fields, 'action': 'edit',
            'obj_id': obj_id, 'errors': errors,
            'form_error': errors.get('form_error', ''),
        })

    form_fields = _build_form_context(cfg, instance)
    return render(request, 'data_manager/_form.html', {
        'model_key': model_key, 'cfg': cfg,
        'form_fields': form_fields, 'action': 'edit',
        'obj_id': obj_id, 'errors': {}, 'form_error': '',
    })


def delete_model(request, model_key, obj_id):
    cfg = MODEL_CONFIGS.get(model_key)
    if not cfg:
        return HttpResponse('Not found', status=404)

    instance = get_object_or_404(cfg['model'], pk=obj_id)

    if request.method == 'POST':
        instance.delete()
        resp = HttpResponse(status=204)
        resp['HX-Trigger'] = _HX_SUCCESS
        return resp

    return render(request, 'data_manager/_delete_confirm.html', {
        'model_key': model_key, 'cfg': cfg,
        'obj': instance, 'obj_id': obj_id,
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_col_value(obj, col):
    val = getattr(obj, col['key'], None)
    if val is None:
        return ''
    col_type = col.get('type')
    if col_type in ('bool', 'severity'):
        return val
    if col_type == 'fk':
        return str(val)
    if col.get('truncate'):
        s = str(val)
        limit = col['truncate']
        return s[:limit] + '…' if len(s) > limit else s
    return val


def _build_form_context(cfg, instance=None, errors=None):
    form_fields = []
    for field in cfg['fields']:
        f = {k: v for k, v in field.items() if k not in ('queryset', 'display')}

        if 'queryset' in field:
            qs = field['queryset']()
            display_fn = field.get('display', str)
            f['options'] = [(o.pk, display_fn(o)) for o in qs]

        if 'choices' in field:
            f['options'] = [(str(c[0]), c[1]) for c in field['choices']]

        if instance:
            if field['type'] == 'm2m':
                f['current_value'] = list(
                    getattr(instance, field['name']).values_list('pk', flat=True)
                )
            elif field['type'] == 'fk':
                fk_obj = getattr(instance, field['name'])
                f['current_value'] = fk_obj.pk if fk_obj else ''
            else:
                raw = getattr(instance, field['name'], '')
                f['current_value'] = '' if raw is None else raw
        else:
            f['current_value'] = f.get('default', '')

        f['error'] = (errors or {}).get(field['name'], '')
        form_fields.append(f)

    return form_fields


def _save_from_form(cfg, request, instance=None):
    data = request.POST
    obj = cfg['model']() if instance is None else instance
    errors = {}
    m2m_to_set = {}

    for field in cfg['fields']:
        name = field['name']
        ftype = field['type']

        try:
            if ftype == 'm2m':
                ids = data.getlist(name)
                m2m_to_set[name] = field['queryset']().filter(pk__in=ids)
                continue

            if ftype in ('text', 'textarea', 'email'):
                val = data.get(name, '').strip()
                if field.get('required') and not val:
                    errors[name] = 'Required.'
                else:
                    setattr(obj, name, val)

            elif ftype == 'number':
                val_str = data.get(name, '').strip()
                if field.get('required') and not val_str:
                    errors[name] = 'Required.'
                elif val_str:
                    try:
                        setattr(obj, name, int(val_str))
                    except ValueError:
                        errors[name] = 'Must be a whole number.'
                else:
                    setattr(obj, name, 0)

            elif ftype == 'float':
                val_str = data.get(name, '').strip()
                if val_str:
                    try:
                        setattr(obj, name, float(val_str))
                    except ValueError:
                        errors[name] = 'Must be a number.'
                else:
                    setattr(obj, name, 0.0)

            elif ftype == 'checkbox':
                setattr(obj, name, name in data)

            elif ftype == 'select':
                val = data.get(name, '')
                if field.get('required') and val == '':
                    errors[name] = 'Required.'
                else:
                    choices = field.get('choices', [])
                    if choices and isinstance(choices[0][0], int):
                        try:
                            val = int(val)
                        except (ValueError, TypeError):
                            pass
                    setattr(obj, name, val)

            elif ftype == 'fk':
                fk_id = data.get(name, '').strip()
                if fk_id:
                    qs = field['queryset']()
                    try:
                        setattr(obj, name, qs.get(pk=fk_id))
                    except Exception:
                        errors[name] = 'Invalid selection.'
                elif field.get('required'):
                    errors[name] = 'Required.'
                else:
                    setattr(obj, name + '_id', None)

        except Exception as e:
            errors[name] = str(e)

    if errors:
        return None, errors

    try:
        obj.save()
        for fname, qs in m2m_to_set.items():
            getattr(obj, fname).set(qs)
        return obj, {}
    except Exception as e:
        return None, {'form_error': str(e)}
