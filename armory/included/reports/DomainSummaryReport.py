#!/usr/bin/python

from armory.included.ReportTemplate import ReportTemplate
from armory.database.repositories import DomainRepository
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

        self.Domain = DomainRepository(db, self.name)

    def run(self, args):
        # Cidrs = self.CIDR.
        results = []
        if args.scope != ('active' or 'passive'):
            args.scope = 'all'
        domains = self.Domain.all(scope_type=args.scope)
        domain_data = {}

        for d in domains:
            
            if not domain_data.get(d.base_domain.domain, False):
                
                domain_data[d.base_domain.domain] = {}

            domain_data[d.base_domain.domain][d.domain] = [i.ip_address for i in d.ip_addresses if (i.in_scope == True and args.scope == 'active') or (i.passive_scope and args.scope == 'passive') or (args.scope == 'all')]


        for b in sorted(domain_data.keys()):
            
                results.append(b)

                for d in sorted(domain_data[b].keys()):
                    results.append('\t{} ({})'.format(d, ', '.join(domain_data[b][d])))
                

        self.process_output(results, args)
