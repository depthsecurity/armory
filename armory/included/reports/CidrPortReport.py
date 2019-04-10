#!/usr/bin/python
from armory.database.repositories import (
    DomainRepository,
    IPRepository,
    CIDRRepository,
    BaseDomainRepository,
)
from armory.included.ReportTemplate import ReportTemplate
import pdb

class Report(ReportTemplate):
    """
    This report displays all of the CIDR information, as well as the IP addresses and
    associated domains.
    """

    markdown = ["# ", "## ", "### ", "#### ", "##### ", "###### "]

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
                if (args.scope == "passive" and ip.passive_scope) or (
                    args.scope == "active" and ip.in_scope) or (
                    args.scope == "all"):
                    results[c.org_name][c.cidr][ip.ip_address] = []
                    for d in ip.domains:
                        if d.passive_scope:
                            results[c.org_name][c.cidr][ip.ip_address].append(d.domain)
        pdb.set_trace()
        res = []
        if results.get(None, False):
            results[""] = results.pop(None)
        
        # This cleans out any CIDRs that don't have scoped hosts.
        newresults = results.copy()
        for k, v in results.items():
            new_vals = v.copy()
            for c, r in v.items():
                if not r:
                    new_vals.pop(c)
            if not new_vals:
                newresults.pop(k)

        results = newresults.copy()
        
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
