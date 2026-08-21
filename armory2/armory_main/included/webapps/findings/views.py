from django.shortcuts import render, get_object_or_404
from django.db.models import Q, Count

from armory2.armory_main.models import Vulnerability, VulnOutput


SEV_MAP = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}

# Tailwind classes per severity, kept here so the list, the detail pane and the
# sidebar counts can never drift out of sync.
SEV_STYLES = {
    0: {
        'pill': 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-300',
        'bar': 'bg-slate-400 dark:bg-slate-500',
    },
    1: {
        'pill': 'bg-blue-100 text-blue-800 dark:bg-blue-800 dark:text-blue-200',
        'bar': 'bg-blue-500',
    },
    2: {
        'pill': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-700 dark:text-yellow-100',
        'bar': 'bg-yellow-500',
    },
    3: {
        'pill': 'bg-orange-100 text-orange-800 dark:bg-orange-700 dark:text-orange-100',
        'bar': 'bg-orange-500',
    },
    4: {
        'pill': 'bg-red-100 text-red-800 dark:bg-red-700 dark:text-red-100 ring-1 ring-red-300 dark:ring-red-500',
        'bar': 'bg-red-600',
    },
}

SORT_FIELDS = {
    'severity_desc': ['-severity', 'name'],
    'severity_asc': ['severity', 'name'],
    'name': ['name'],
    'hosts_desc': ['-port_count', '-severity'],
    'recent': ['-modified_at'],
}


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


def _sources():
    return sorted(
        s for s in Vulnerability.objects.values_list('source', flat=True).distinct() if s
    )


def _severity_list():
    """Severity filter checkboxes, highest severity first."""
    return [
        {'value': sev, 'label': SEV_MAP[sev], 'styles': SEV_STYLES[sev]}
        for sev in sorted(SEV_MAP, reverse=True)
    ]


def _filtered_vulns(request):
    """Apply every filter from the search form to the Vulnerability queryset."""
    p = request.POST
    filters = {
        'search': (p.get('search') or '').strip(),
        'search_output': bool(p.get('search_output')),
        'severities': p.getlist('severity'),
        'source': p.get('source') or '',
        'exploitable': p.get('exploitable') or '',
        'host': (p.get('host') or '').strip(),
        'scope': p.get('scope') or 'all',
        'sort': p.get('sort') or 'severity_desc',
        'orphans': bool(p.get('orphans')),
    }

    vulns = Vulnerability.objects.all()

    if filters['search']:
        query = (
            Q(name__icontains=filters['search'])
            | Q(description__icontains=filters['search'])
            | Q(remediation__icontains=filters['search'])
        )
        if filters['search_output']:
            query |= Q(vulnoutput__data__icontains=filters['search'])
        vulns = vulns.filter(query)

    if filters['severities']:
        wanted = [int(s) for s in filters['severities'] if s.isdigit()]
        if wanted:
            vulns = vulns.filter(severity__in=wanted)

    if filters['source']:
        vulns = vulns.filter(source__iexact=filters['source'])

    if filters['exploitable'] == 'yes':
        vulns = vulns.filter(exploitable=True)
    elif filters['exploitable'] == 'no':
        vulns = vulns.filter(exploitable=False)

    if filters['host']:
        vulns = vulns.filter(
            Q(ports__ip_address__ip_address__icontains=filters['host'])
            | Q(ports__ip_address__domain__name__icontains=filters['host'])
        )

    if filters['scope'] == 'active':
        vulns = vulns.filter(ports__ip_address__active_scope=True)
    elif filters['scope'] == 'passive':
        vulns = vulns.filter(ports__ip_address__passive_scope=True)

    # distinct() is required because the host/scope/output filters join across
    # the ports M2M and would otherwise return one row per matching port.
    vulns = vulns.annotate(
        port_count=Count('ports', distinct=True),
        output_count=Count('vulnoutput', distinct=True),
    ).distinct()

    if not filters['orphans']:
        vulns = vulns.filter(port_count__gt=0)

    return vulns.order_by(*SORT_FIELDS.get(filters['sort'], SORT_FIELDS['severity_desc']))


def index(request):
    return render(request, 'findings/index.html', {
        'title': 'Findings',
        'sources': _sources(),
        'severities': _severity_list(),
        'total_vulns': Vulnerability.objects.count(),
        'total_outputs': VulnOutput.objects.count(),
    })


def get_findings(request):
    vulns = _filtered_vulns(request)

    page = max(1, int(request.POST.get('page') or 1))
    entries = max(1, int(request.POST.get('entries') or 50))

    total = vulns.count()
    page_data = _make_page_data(page, total, entries)
    # A stale page number (filters tightened while paged deep) would render an
    # empty list, so clamp it back into range before slicing.
    page = min(page, page_data['last_page'])
    page_data = _make_page_data(page, total, entries)
    start = (page - 1) * entries

    rows = []
    for v in vulns[start:start + entries]:
        rows.append({
            'obj': v,
            'styles': SEV_STYLES.get(v.severity, SEV_STYLES[0]),
            'sev_label': SEV_MAP.get(v.severity, v.severity),
            'port_count': v.port_count,
            'output_count': v.output_count,
        })

    # Counts come off the filtered set so the sidebar always describes what is
    # actually on screen.
    sev_counts = {row['severity']: row['n'] for row in
                  vulns.values('severity').annotate(n=Count('id')).order_by()}
    # value feeds the source <select>, so keep it raw ('' for a blank source)
    # and only prettify the label.
    source_counts = sorted(
        ({'value': row['source'] or '',
          'label': row['source'] or '(none)',
          'count': row['n']}
         for row in vulns.values('source').annotate(n=Count('id')).order_by()),
        key=lambda x: -x['count'],
    )

    return render(request, 'findings/finding_results.html', {
        'rows': rows,
        'total': total,
        'page_data': page_data,
        'sev_summary': [
            {
                'value': sev,
                'label': SEV_MAP[sev],
                'styles': SEV_STYLES[sev],
                'count': sev_counts.get(sev, 0),
            }
            for sev in sorted(SEV_MAP, reverse=True)
        ],
        'source_counts': source_counts,
        'exploitable_count': vulns.filter(exploitable=True).count(),
    })


def get_detail(request, vuln_id):
    vuln = get_object_or_404(Vulnerability, pk=vuln_id)

    outputs = {
        o.port_id: o for o in
        vuln.vulnoutput_set.select_related('port', 'port__ip_address')
    }

    instances = []
    for port in vuln.ports.select_related('ip_address').order_by(
        'ip_address__ip_address', 'port_number'
    ):
        output = outputs.pop(port.id, None)
        instances.append({
            'port': port,
            'domains': port.ip_address.domain_set.all().order_by('name'),
            'vhosts': port.get_active_virtualhosts(),
            'output': output,
        })

    # VulnOutput rows whose port is no longer linked to the vuln still hold
    # evidence, so surface them rather than silently dropping them.
    orphan_outputs = sorted(outputs.values(), key=lambda o: o.id)

    return render(request, 'findings/finding_detail.html', {
        'vuln': vuln,
        'sev_label': SEV_MAP.get(vuln.severity, vuln.severity),
        'styles': SEV_STYLES.get(vuln.severity, SEV_STYLES[0]),
        'instances': instances,
        'orphan_outputs': orphan_outputs,
        'cves': vuln.cves.all().order_by('-temporal_score', 'name'),
    })


def get_output(request, output_id):
    """Raw VulnOutput data, for copy/paste out of the UI."""
    output = get_object_or_404(
        VulnOutput.objects.select_related('port', 'port__ip_address', 'vulnerability'),
        pk=output_id,
    )
    return render(request, 'findings/output_raw.html', {
        'output': output,
        'title': 'Finding Output',
    })
