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

    def run(self, args):
        # Cidrs = self.CIDR.
        results = []

        domains = self.Domain.all()
        for d in domains:

            if len(d.ip_addresses) > 0:
                owner = d.ip_addresses[0].cidr.org_name

                results.append("%s,%s" % (owner, d.domain))

        res = sorted(results)

        self.process_output(res, args)
