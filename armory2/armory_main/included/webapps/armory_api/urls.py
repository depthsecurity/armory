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
    path('vuln_outputs',              views.vuln_outputs,       name="api_vuln_outputs"),
    path('vuln_outputs/<int:output_id>', views.vuln_output_detail, name="api_vuln_output_detail"),
    path('domains',                   views.domains,       name="api_domains"),
    path('domains/<int:domain_id>',   views.domain_detail, name="api_domain_detail"),
    path('cidrs',                     views.cidrs,         name="api_cidrs"),
    path('cidrs/<int:cidr_id>',       views.cidr_detail,   name="api_cidr_detail"),
    path('virtualhosts',              views.virtualhosts,       name="api_virtualhosts"),
    path('virtualhosts/<int:vh_id>',  views.virtualhost_detail, name="api_virtualhost_detail"),
    path('basedomains',               views.basedomains,        name="api_basedomains"),
    path('basedomains/<int:basedomain_id>', views.basedomain_detail, name="api_basedomain_detail"),
    path('urls',                      views.urls,               name="api_urls"),
    path('urls/<int:url_id>',         views.url_detail,         name="api_url_detail"),
    path('users',                     views.users,              name="api_users"),
    path('users/<int:user_id>',       views.user_detail,        name="api_user_detail"),
    path('creds',                     views.creds,              name="api_creds"),
    path('creds/<int:cred_id>',       views.cred_detail,        name="api_cred_detail"),
    path('cves',                      views.cves,               name="api_cves"),
    path('cves/<int:cve_id>',         views.cve_detail,         name="api_cve_detail"),
    path('tags',                      views.tags,               name="api_tags"),
    path('tags/<int:tag_id>',         views.tag_detail,         name="api_tag_detail"),
    path('tags/<int:tag_id>/apply',   views.tag_apply,          name="api_tag_apply"),
    path('toolruns',                  views.toolruns,           name="api_toolruns"),
    path('toolruns/<int:toolrun_id>', views.toolrun_detail,     name="api_toolrun_detail"),
    path('stats',                     views.stats,         name="api_stats"),
    path('search',                    views.search,        name="api_search"),
    path('exec',                      views.exec_commands,      name="api_exec"),
    path('exec/<str:job_id>',         views.exec_command_detail, name="api_exec_detail"),
]
