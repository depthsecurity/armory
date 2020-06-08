#!/usr/bin/python
from armory2.armory_main.models import (

    IPAddress,
    BaseDomain,
    Domain,
    CIDR,
)
from armory2.armory_main.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This report displays all of the various Base Domains, Domains, and IP Addresses with scoping information
    """

    markdown = ["###", "`"]

    name = "CertReport"


    def set_options(self):
        super(Report, self).set_options()

    def run(self, args):

        results = []

        base_domains = BaseDomain.objects.all()

        for b in base_domains:
            results.append(
                "%s\tActive Scope: %s\tPassive Scope: %s"
                % (b.name, b.active_scope, b.passive_scope)
            )

            for d in b.domain_set.all():
                results.append(
                    "\t%s\tActive Scope: %s\tPassive Scope: %s"
                    % (d.name, d.active_scope, d.passive_scope)
                )

        cidrs = CIDR.objects.all()

        results.append("\n\n")
        for c in cidrs:
            results.append("%s - %s" % (c.name, c.org_name))
            for ip in c.ipaddress_set.all():
                results.append(
                    "\t%s\tActive Scope: %s\tPassive Scope: %s"
                    % (ip.ip_address, ip.active_scope, ip.passive_scope)
                )

        self.process_output(results, args)
