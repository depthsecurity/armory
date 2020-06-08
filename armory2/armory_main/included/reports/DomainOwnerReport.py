#!/usr/bin/python
from armory2.armory_main.models import Domain
from armory2.armory_main.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This lists who owns the CIDR for each of the domains.
    """

    name = "DomainOwner"

    
    def run(self, args):
        # Cidrs = self.CIDR.
        results = []

        domains = Domain.objects.all()
        for d in domains:

            if len(d.ip_addresses.all()) > 0:
                owner = d.ip_addresses.all()[0].cidr.org_name

                results.append("%s,%s" % (owner, d.name))

        res = sorted(results)

        self.process_output(res, args)
