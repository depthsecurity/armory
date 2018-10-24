#!/usr/bin/python

from included.ReportTemplate import ReportTemplate
from database.repositories import (
    IPRepository,
    BaseDomainRepository,
    DomainRepository,
    CIDRRepository,
)
import pdb
import json


class Report(ReportTemplate):
    """
    This report displays all of the various Base Domains, Domains, and IP Addresses with scoping information
    """

    markdown = ["###", "`"]

    name = "CertReport"

    def __init__(self, db):

        self.IPAddress = IPRepository(db)
        self.Domains = DomainRepository(db)
        self.BaseDomains = BaseDomainRepository(db)
        self.CIDRs = CIDRRepository(db)

    def set_options(self):
        super(Report, self).set_options()

    def run(self, args):

        results = []

        base_domains = self.BaseDomains.all()

        for b in base_domains:
            results.append(
                "%s\tActive Scope: %s\tPassive Scope: %s"
                % (b.domain, b.in_scope, b.passive_scope)
            )

            for d in b.subdomains:
                results.append(
                    "\t%s\tActive Scope: %s\tPassive Scope: %s"
                    % (d.domain, d.in_scope, d.passive_scope)
                )

        cidrs = self.CIDRs.all()

        results.append("\n\n")
        for c in cidrs:
            results.append("%s - %s" % (c.cidr, c.org_name))
            for ip in c.ip_addresses:
                results.append(
                    "\t%s\tActive Scope: %s\tPassive Scope: %s"
                    % (ip.ip_address, ip.in_scope, ip.passive_scope)
                )

        self.process_output(results, args)
