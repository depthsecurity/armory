#!/usr/bin/python
from armory2.armory_main.models import Domain
from armory2.armory_main.included.ReportTemplate import ReportTemplate
import netaddr


class Report(ReportTemplate):
    """
    This is a domain summary report. It shows base domain, then
    all of the subdomains, along with any resolved IPs.
    """

    name = "DomainSummaryReport"
    markdown = ["###", "-"]

    def set_options(self):

        super(Report, self).set_options()

        self.options.add_argument(
            "-i",
            "--initial_ips",
            help=(
                "File containing initial IPs, this will be used to mark the IPs"
                " not included in the original scope with (Excluded from Pentest Scope)"
            ),
        )
        self.options.add_argument(
            "-d",
            "--initial_domains",
            help=(
                "File containing the basedomains whose IPs should be included within the scope."
                " Those not included within these IPs will show (Excluded from Pentest Scope)."
            ),
        )
        self.options.add_argument(
            "-ex",
            "--exclude_message",
            help=(
                "The message to display for IPs not in the scope of the initial_ips and the "
                "resolved ips for the initial_domains."
            ),
            default="(Excluded from Scope)",
        )

    def run(self, args):
        # Cidrs = self.CIDR.
        results = []

        if args.scope not in ("active", "passive"):
            args.scope = "all"
        initial_ips = set()
        initial_domains = set()
        if args.initial_ips:
            with open(args.initial_ips) as fd:
                for line in fd:
                    line = line.strip()
                    try:
                        initial_ips = initial_ips.union(
                            netaddr.ip.nmap.iter_nmap_range(line)
                        )
                    except netaddr.core.AddrFormatError:
                        # This is caused by not having a valid nmap range example: 192.168.1.1-23
                        # in most cases, therefore, attempt to use netaddr's range.
                        if line.find("-") == -1:
                            print("Invalid IP/CIDR/Range format: {}".format(line))
                        else:
                            try:
                                initial_ips = initial_ips.union(
                                    netaddr.IPRange(*line.split("-"))
                                )
                            except netaddr.core.AddrFormatError:
                                print("Invalid IP/CIDR/Range format: {}".format(line))
        if args.initial_domains:
            with open(args.initial_domains) as fd:
                for line in fd:
                    initial_domains.add(line.strip())
        domains = Domain.get_set(scope_type=args.scope)
        domain_data = {}

        for d in domains:
            bd_name = d.basedomain.name.lower()
            dname = d.name.lower()
            if not domain_data.get(bd_name, False):

                domain_data[bd_name] = {}

            if d.ip_addresses.count() > 0:
                for ip in d.ip_addresses.all():
                    ip_msg = "{}".format(ip)
                    if initial_domains and bd_name == dname:
                        initial_ips.add(netaddr.IPAddress(ip.ip_address))
                    if (
                        initial_ips
                        and netaddr.IPAddress(ip.ip_address) not in initial_ips
                    ):
                        ip_msg = "{} {}".format(ip, args.exclude_message)
                    if dname not in domain_data[bd_name]:
                        domain_data[bd_name][dname] = set()
                    domain_data[bd_name][dname].add(ip_msg)
            else:
                domain_data[bd_name][dname] = set("")

        for b in sorted(domain_data.keys()):

            results.append(b)

            for d in sorted(domain_data[b].keys()):
                results.append("\t{} ({})".format(d, ", ".join(domain_data[b][d])))

        self.process_output(results, args)
