#!/usr/bin/python
from armory2.armory_main.models import Port
from armory2.armory_main.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This report displays all of the hosts sorted by service.
    """

    markdown = ["", "# ", "- "]

    name = ""

    def set_options(self):
        super(Report, self).set_options()

        self.options.add_argument(
            "--port",
            help="Single port to target"
        )

        self.options.add_argument(
            "--only_ips",
            help="List IPs only when targeting specific port",
            action="store_true",
        )

    def run(self, args):
        # Cidrs = self.CIDR.

        if args.port is not None:
            ports = Port.objects.filter(port_number=int(args.port))

        else:
            ports = Port.objects.all()
        
        services = {}

        for p in ports:

            if (
                (args.scope == "active" and p.ip_address.in_scope)
                or (  # noqa: W503
                    args.scope == "passive" and p.ip_address.passive_scope
                )
                or (args.scope == "all")  # noqa: W503
                and p.status == "open"  # noqa: W503
            ):
                if not services.get(p.proto, False):
                    services[p.proto] = {}

                if not services[p.proto].get(p.port_number, False):
                    services[p.proto][p.port_number] = {}

                services[p.proto][p.port_number][p.ip_address.ip_address] = {
                    "domains": [d.name for d in p.ip_address.domain_set.all()],
                    "svc": p.service_name,
                }

        res = []

        for p in sorted(services):
            for s in sorted(services[p]):
                res.append("\tProtocol: {} Port: {}".format(p, s))
                res.append("\n")
                for ip in sorted(services[p][s].keys()):

                    if (args.port is not None) and args.only_ips:
                        res.append(ip)

                    else:
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
