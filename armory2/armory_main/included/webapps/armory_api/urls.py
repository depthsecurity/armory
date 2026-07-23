from django.urls import path
import os
import importlib.util

spec = importlib.util.spec_from_file_location(
    "views", os.path.dirname(os.path.realpath(__file__)) + "/views.py"
)
views = importlib.util.module_from_spec(spec)
spec.loader.exec_module(views)

urlpatterns = [
    path('',                          views.api_root,      name="api_root"),
    path('hosts',                     views.hosts,         name="api_hosts"),
    path('hosts/<int:ip_id>',         views.host_detail,   name="api_host_detail"),
    path('ports',                     views.ports,         name="api_ports"),
    path('ports/<int:port_id>',       views.port_detail,   name="api_port_detail"),
    path('vulns',                     views.vulns,         name="api_vulns"),
    path('vulns/<int:vuln_id>',       views.vuln_detail,   name="api_vuln_detail"),
    path('domains',                   views.domains,       name="api_domains"),
    path('domains/<int:domain_id>',   views.domain_detail, name="api_domain_detail"),
    path('cidrs',                     views.cidrs,         name="api_cidrs"),
    path('cidrs/<int:cidr_id>',       views.cidr_detail,   name="api_cidr_detail"),
    path('stats',                     views.stats,         name="api_stats"),
    path('search',                    views.search,        name="api_search"),
]
