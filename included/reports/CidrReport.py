#!/usr/bin/python

from included.ReportTemplate import ReportTemplate
from database.repositories import (
    DomainRepository,
    IPRepository,
    CIDRRepository,
    BaseDomainRepository,
)
import pdb
import json


class Report(ReportTemplate):
    """
    This report displays all of the CIDR information, as well as the IP addresses and
    associated domains.
    """

    markdown = ["### ", "#### ", "- ", "-- "]

    name = ""

    def __init__(self, db):
        self.BaseDomain = BaseDomainRepository(db)
        self.Domain = DomainRepository(db)
        self.IPAddress = IPRepository(db)
        self.CIDR = CIDRRepository(db)

    def run(self, args):
        # Cidrs = self.CIDR.
        results = {}

        CIDRs = self.CIDR.all()
        for c in CIDRs:

            if results.get(c.org_name, False):
                if not results[c.org_name].get(c.cidr, False):
                    results[c.org_name][c.cidr] = {}
            else:
                results[c.org_name] = {c.cidr: {}}
            for ip in c.ip_addresses:
                if ip.passive_scope:
                    results[c.org_name][c.cidr][ip.ip_address] = []
                    for d in ip.domains:
                        if d.passive_scope:
                            results[c.org_name][c.cidr][ip.ip_address].append(d.domain)

        res = []
        results[""] = results.pop(None)
        for cidr in sorted(results.keys()):
            if not cidr:
                res.append("")
            else:
                res.append(cidr)
            for ranges in sorted(results[cidr].keys()):
                res.append("\t" + ranges)
                for ips in sorted(results[cidr][ranges].keys()):
                    res.append("\t\t" + ips)
                    for domain in sorted(results[cidr][ranges][ips]):
                        res.append("\t\t\t" + domain)
        self.process_output(res, args)
