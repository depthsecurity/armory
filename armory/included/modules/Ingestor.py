#!/usr/bin/python
from armory.database.repositories import (
    DomainRepository,
    IPRepository,
    CIDRRepository,
    BaseDomainRepository,
    ScopeCIDRRepository,
)
from netaddr import IPNetwork, IPAddress, iprange_to_cidrs
from ..ModuleTemplate import ModuleTemplate
from ..utilities.color_display import display, display_new, display_error
import dns.resolver
import string


def check_string(s):

    for c in s:
        if c in string.ascii_letters:
            return True
    return False


class Module(ModuleTemplate):
    """
    Ingests domains and IPs. Domains get ip info and cidr info, and IPs get
    CIDR info.

    """

    name = "Ingestor"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.CIDR = CIDRRepository(db, self.name)
        self.ScopeCIDR = ScopeCIDRRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-d",
            "--import_domains",
            help="Either domain to import or file containing domains to import. One per line",
        )
        self.options.add_argument(
            "-i",
            "--import_ips",
            help="Either IP/range to import or file containing IPs and ranges, one per line.",
        )
        self.options.add_argument(
            "-a",
            "--active",
            help="Set scoping on imported data as active",
            action="store_true",
        )
        self.options.add_argument(
            "-p",
            "--passive",
            help="Set scoping on imported data as passive",
            action="store_true",
        )
        self.options.add_argument(
            "-sc",
            "--scope_cidrs",
            help="Cycle through out of scope networks and decide if you want to add them in scope",
            action="store_true",
        )
        self.options.add_argument(
            "-sb",
            "--scope_base_domains",
            help="Cycle through out of scope base domains and decide if you want to add them in scope",
            action="store_true",
        )
        self.options.add_argument("--descope", help="Descope an IP, domain, or CIDR")
        self.options.add_argument(
            "-Ii",
            "--import_database_ips",
            help="Import IPs from database",
            action="store_true",
        )
        self.options.add_argument(
            "--force",
            help="Force processing again, even if already processed",
            action="store_true",
        )

    def run(self, args):

        self.in_scope = args.active
        self.passive_scope = args.passive

        if args.descope:
            if "/" in args.descope:
                self.descope_cidr(args.descope)
            elif check_string(args.descope):
                pass

            else:
                self.descope_ip(args.descope)

                # Check if in ScopeCIDR and remove if found

        if args.import_ips:
            try:
                ips = open(args.import_ips)
                for line in ips:

                    if line.strip():
                        if "/" in line or "-" in line:
                            self.process_cidr(line)

                        else:
                            self.process_ip(line.strip(), force_scope=True)
                        self.Domain.commit()
            except IOError:

                if "/" in args.import_ips or "-" in args.import_ips:
                    self.process_cidr(args.import_ips)

                else:
                    self.process_ip(args.import_ips.strip(), force_scope=True)
                self.Domain.commit()

        if args.import_domains:
            try:
                domains = open(args.import_domains)
                for line in domains:
                    if line.strip():
                        self.process_domain(line.strip())
                        self.Domain.commit()
            except IOError:
                self.process_domain(args.import_domains.strip())
                self.Domain.commit()

        if args.scope_base_domains:
            base_domains = self.BaseDomain.all(in_scope=False, passive_scope=False)

            for bd in base_domains:
                self.reclassify_domain(bd)

            self.BaseDomain.commit()

    def get_domain_ips(self, domain):
        ips = []
        try:
            answers = dns.resolver.query(domain, "A")
            for a in answers:
                ips.append(a.address)
            return ips
        except Exception:
            return []

    def process_domain(self, domain_str):

        created, domain = self.Domain.find_or_create(
            only_tool=True,
            domain=domain_str,
            in_scope=self.in_scope,
            passive_scope=self.passive_scope,
        )
        if not created:
            if (
                domain.in_scope != self.in_scope
                or domain.passive_scope != self.passive_scope  # noqa: W503
            ):
                display(
                    "Domain %s already exists with different scoping. Updating to Active Scope: %s Passive Scope: %s"
                    % (domain_str, self.in_scope, self.passive_scope)
                )

                domain.in_scope = self.in_scope
                domain.passive_scope = self.passive_scope
                domain.update()

                if domain.base_domain.domain == domain.domain:
                    display("Name also matches a base domain. Updating that as well.")
                    domain.base_domain.in_scope = self.in_scope
                    domain.base_domain.passive_scope = self.passive_scope
                    domain.base_domain.update()

    def process_ip(self, ip_str, force_scope=True):

        created, ip = self.IPAddress.find_or_create(
            only_tool=True,
            ip_address=ip_str,
            in_scope=self.in_scope,
            passive_scope=self.passive_scope,
        )
        if not created:
            if ip.in_scope != self.in_scope or ip.passive_scope != self.passive_scope:
                display(
                    "IP %s already exists with different scoping. Updating to Active Scope: %s Passive Scope: %s"
                    % (ip_str, self.in_scope, self.passive_scope)
                )

                ip.in_scope = self.in_scope
                ip.passive_scope = self.passive_scope
                ip.update()
        return ip

    def process_cidr(self, line):
        display("Processing %s" % line)
        if "/" in line:
            created, cidr = self.ScopeCIDR.find_or_create(cidr=line.strip())
            if created:
                display_new("Adding %s to scoped CIDRs in database" % line.strip())
                cidr.in_scope = True
                cidr.update()

        elif "-" in line:
            start_ip, end_ip = line.strip().replace(" ", "").split("-")
            if "." not in end_ip:
                end_ip = ".".join(start_ip.split(".")[:3] + [end_ip])

            cidrs = iprange_to_cidrs(start_ip, end_ip)

            for c in cidrs:

                created, cidr = self.ScopeCIDR.find_or_create(cidr=str(c))
                if created:
                    display_new("Adding %s to scoped CIDRs in database" % line.strip())
                    cidr.in_scope = True
                    cidr.update()

    def reclassify_domain(self, bd):
        if bd.meta.get("whois", False):
            display_new("Whois data found for {}".format(bd.domain))
            print(bd.meta["whois"])
            res = input("Should this domain be scoped (A)ctive, (P)assive, or (N)ot? [a/p/N] ")
            if res.lower() == "a":
                bd.in_scope = True
                bd.passive_scope = True

            elif res.lower() == "p":
                bd.in_scope = False
                bd.passive_scope = True
            else:
                bd.in_scope = False
                bd.passive_scope = False
            bd.save()
        else:
            display_error(
                "Unfortunately, there is no whois information for {}. Please populate it using the Whois module".format(
                    bd.domain
                )
            )

    def descope_ip(self, ip):
        ip = self.IPAddress.all(ip_address=ip)
        if ip:
            for i in ip:
                display("Removing IP {} from scope".format(i.ip_address))
                i.in_scope = False
                i.passive_scope = False
                i.update()
                for d in i.domains:
                    in_scope_ips = [
                        ipa
                        for ipa in d.ip_addresses
                        if ipa.in_scope or ipa.passive_scope
                    ]
                    if not in_scope_ips:
                        display(
                            "Domain {} has no more scoped IPs. Removing from scope.".format(
                                d.domain
                            )
                        )
                        d.in_scope = False
                        d.passive_scope = False
            self.IPAddress.commit()

    def descope_cidr(self, cidr):
        CIDR = self.ScopeCIDR.all(cidr=cidr)
        if CIDR:
            for c in CIDR:
                display("Removing {} from ScopeCIDRs".format(c.cidr))
                c.delete()
        cnet = IPNetwork(cidr)
        for ip in self.IPAddress.all():
            if IPAddress(ip.ip_address) in cnet:

                self.descope_ip(ip.ip_address)
