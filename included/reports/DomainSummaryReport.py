#!/usr/bin/python

from included.ReportTemplate import ReportTemplate
from database.repositories import BaseDomainRepository
import pdb
import json


class Report(ReportTemplate):
    """
    This is a domain summary report. It shows base domain, then
    all of the subdomains, along with any resolved IPs.
    """

    name = "DomainSummaryReport"
    markdown = ["###", "-"]

    def __init__(self, db):

        self.BaseDomain = BaseDomainRepository(db, self.name)

    def run(self, args):
        # Cidrs = self.CIDR.
        results = []
        basedomains = self.BaseDomain.all()
        for b in basedomains:
            if (
                (args.scope == "active" and b.in_scope)
                or (args.scope == "passive" and b.passive_scope)
                or (args.scope == "all")
            ):

                domain_data = []
                for d in b.subdomains:
                    if d.ip_addresses:
                        domain_data.append(
                            "%s (%s)"
                            % (
                                d.domain,
                                ", ".join([i.ip_address for i in d.ip_addresses]),
                            )
                        )

                results.append(b.domain)
                for d in sorted(domain_data):
                    results.append("\t" + d)

        self.process_output(results, args)
