#!/usr/bin/python

from included.ReportTemplate import ReportTemplate
from database.repositories import PortRepository
import pdb
import json


class Report(ReportTemplate):
    """
    This report displays all of the hosts sorted by service.
    """

    markdown = ["", "# ", "- "]

    name = ""

    def __init__(self, db):
        self.Ports = PortRepository(db)

    def run(self, args):
        # Cidrs = self.CIDR.
        results = {}

        ports = self.Ports.all()
        services = {}

        for p in ports:

            if (
                (args.scope == "active" and p.ip_address.in_scope)
                or (args.scope == "passive" and p.ip_address.passive_scope)
                or (args.scope == "all")
                and p.status == "open"
            ):
                if not services.get(p.proto, False):
                    services[p.proto] = {}

                if not services[p.proto].get(p.port_number, False):
                    services[p.proto][p.port_number] = {}

                services[p.proto][p.port_number][p.ip_address.ip_address] = {
                    "domains": [d.domain for d in p.ip_address.domains],
                    "svc": p.service_name,
                }

        res = []

        for p in sorted(services):
            for s in sorted(services[p]):

                res.append("\tProtocol: {} Port: {}".format(p, s))
                res.append("\n")
                for ip in sorted(services[p][s].keys()):
                    if services[p][s][ip]["domains"]:
                        res.append(
                            "\t\t{} ({}): {}".format(
                                ip,
                                services[p][s][ip]["svc"],
                                ", ".join(services[p][s][ip]["domains"]),
                            )
                        )
                    else:
                        res.append(
                            "\t\t{} ({}) (No domain)".format(
                                ip, services[p][s][ip]["svc"]
                            )
                        )
                res.append("\n")

        self.process_output(res, args)
