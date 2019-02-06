#!/usr/bin/python
from armory.database.repositories import DomainRepository
from armory.included.ReportTemplate import ReportTemplate
import pdb

class Report(ReportTemplate):
    """
    This is a domain summary report. It shows base domain, then
    all of the subdomains, along with any resolved IPs.
    """

    name = "DomainSummaryReport"
    markdown = ["###", "-"]

    def __init__(self, db):

        self.Domain = DomainRepository(db, self.name)

    def run(self, args):
        # Cidrs = self.CIDR.
        results = []
        
        if args.scope not in ("active", "passive"):
            args.scope = "all"
        domains = self.Domain.all(scope_type=args.scope)
        domain_data = {}
        
        for d in domains:

            if not domain_data.get(d.base_domain.domain, False):

                domain_data[d.base_domain.domain] = {}

            domain_data[d.base_domain.domain][d.domain] = [
                i.ip_address
                for i in d.ip_addresses
                # if (i.in_scope and args.scope == "active")
                # or (i.passive_scope and args.scope == "passive")  # noqa: W503
                # or (args.scope == "all")  # noqa: W503
            ]

        for b in sorted(domain_data.keys()):

            results.append(b)

            for d in sorted(domain_data[b].keys()):
                results.append("\t{} ({})".format(d, ", ".join(domain_data[b][d])))

        self.process_output(results, args)
