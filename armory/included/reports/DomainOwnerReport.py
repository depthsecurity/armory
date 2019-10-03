#!/usr/bin/python
from armory.database.repositories import DomainRepository, IPRepository, CIDRRepository
from armory.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This lists who owns the CIDR for each of the domains.
    """

    name = "DomainOwner"

    def __init__(self, db):

        self.Domain = DomainRepository(db)
        self.IPAddress = IPRepository(db)
        self.CIDR = CIDRRepository(db)

    def set_options(self):
        super(Report, self).set_options()
        self.options.add_argument(
            "-i", "--include-ips", help="Source tool", action="store_true"
        )

    def run(self, args):
        # Cidrs = self.CIDR.
        results = []

        domains = self.Domain.all()
        for d in domains:

            if len(d.ip_addresses) > 0:
                owner = d.ip_addresses[0].cidr.org_name
                ips = ""
                if args.include_ips:
                    ips = "[{}]".format(
                        ", ".join([i.ip_address for i in d.ip_addresses])
                    )
                results.append("{}, {} {}".format(owner, d.domain, ips))

        res = sorted(results)

        self.process_output(res, args)
