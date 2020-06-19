#!/usr/bin/python
from armory2.armory_main.models import CIDR, BaseDomain
from armory2.armory_main.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    Displays WHOIS records for domains and IPs.
    """

    name = "WhoisReport"

    markdown = ["##", "###", "`"]


    def run(self, args):
        # Cidrs = self.CIDR.
        results = []
        if args.scope != "all":
            domains = BaseDomain.get_set(scope_type=args.scope)
        else:
            domains = BaseDomain.objects.all()

        domain_data = {}
        for d in domains:
            if d.meta.get("whois", False):
                domain_data[d.name] = d.meta["whois"]

        cidr_data = {}

        CIDRs = CIDR.get_set(scope_type=args.scope)
        for c in CIDRs:
            if c.meta.get("whois", False):
                cidr_data[c.name] = c.meta["whois"]
        # pdb.set_trace()

        domain_blacklist = [
            "Please note: ",
            "URL of the ICANN WHOIS",
            ">>>",
            "Notes:",
            "whitelisting here:",
            "NOTICE: ",
            "TERMS OF USE: ",
            "by the following",
            "to: (1) allow",
        ]

        results.append("ARIN Registration")
        for c in sorted(cidr_data.keys()):
            results.append("\t" + c)
            for l in cidr_data[c].split("\n"):
                if ": " in l and l[0] != "#":
                    results.append("\t\t" + l)
        results.append("Domain Registration")
        for d in sorted(domain_data.keys()):
            results.append("\t" + d.upper())
            for l in domain_data[d].split("\n"):
                if ": " in l:
                    clean = True
                    for b in domain_blacklist:
                        if b in l:
                            clean = False
                    if clean:
                        results.append("\t\t" + l)

        self.process_output(results, args)
