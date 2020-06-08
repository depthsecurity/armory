#!/usr/bin/python
from armory2.armory_main.models import Domain
from armory2.armory_main.included.ReportTemplate import ReportTemplate
import pdb

class Report(ReportTemplate):
    """
    This is a domain summary report. It shows base domain, then
    all of the subdomains, along with any resolved IPs.
    """

    name = "DomainSummaryReport"
    markdown = ["###", "-"]


    def run(self, args):
        # Cidrs = self.CIDR.
        results = []
        
        if args.scope not in ("active", "passive"):
            args.scope = "all"
        domains = Domain.get_set(scope_type=args.scope)
        domain_data = {}
        
        for d in domains:

            if not domain_data.get(d.basedomain.name, False):

                domain_data[d.basedomain.name] = {}

            domain_data[d.basedomain.name][d.name] = [
                i.ip_address
                for i in d.ip_addresses.all()
                # if (i.in_scope and args.scope == "active")
                # or (i.passive_scope and args.scope == "passive")  # noqa: W503
                # or (args.scope == "all")  # noqa: W503
            ]

        for b in sorted(domain_data.keys()):

            results.append(b)

            for d in sorted(domain_data[b].keys()):
                results.append("\t{} ({})".format(d, ", ".join(domain_data[b][d])))

        self.process_output(results, args)
