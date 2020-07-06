#!/usr/bin/python
from armory2.armory_main.models import BaseDomain, CIDR, IPAddress, Domain

from netaddr import IPNetwork, IPAddress as nIPAddress, iprange_to_cidrs
from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
from armory2.armory_main.included.utilities.color_display import display, display_new, display_error
import dns.resolver
import string

import pdb


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

    # def __init__(self, db):
    #     self.db = db
    #     BaseDomain = BaseDomain(db, self.name)
    #     self.Domain = Domain(db, self.name)
    #     self.IPAddress = IP(db, self.name)
    #     self.CIDR = CIDR(db, self.name)
    #     self.ScopeCIDR = ScopeCIDR(db, self.name)

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
        self.options.add_argument(
            "--label",
            help="Organizational Label for Scoped CIDRs (disables whois")

    def run(self, args):

        self.active_scope = args.active
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
                        # pdb.set_trace()
                        if "/" in line or "-" in line:
                            self.process_cidr(line, args.label)

                        else:
                            self.process_ip(line.strip(), force_scope=True)
                        
            except IOError:

                if "/" in args.import_ips or "-" in args.import_ips:
                    self.process_cidr(args.import_ips, args.label)

                else:
                    self.process_ip(args.import_ips.strip(), force_scope=True)
                

        if args.import_domains:
            try:
                domains = open(args.import_domains)
                for line in domains:
                    if line.strip():
                        self.process_domain(line.strip())
                
            except IOError:
                self.process_domain(args.import_domains.strip())
                

        if args.scope_base_domains:
            base_domains = BaseDomain.all(active_scope=False, passive_scope=False)

            for bd in base_domains:
                self.reclassify_domain(bd)

            

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

        domain, created = Domain.objects.get_or_create(
            
            name=domain_str, defaults = {'active_scope':self.active_scope, 'passive_scope':self.passive_scope}
        )
        if not created:
            if (
                domain.active_scope != self.active_scope
                or domain.passive_scope != self.passive_scope  # noqa: W503
            ):
                display(
                    "Domain %s already exists with different scoping. Updating to Active Scope: %s Passive Scope: %s"
                    % (domain_str, self.active_scope, self.passive_scope)
                )

                domain.active_scope = self.active_scope
                domain.passive_scope = self.passive_scope
                domain.save()

                if domain.basedomain.name == domain.name:
                    display("Name also matches a base domain. Updating that as well.")
                    domain.basedomain.active_scope = self.active_scope
                    domain.basedomain.passive_scope = self.passive_scope
                    domain.basedomain.save()

    def process_ip(self, ip_str, force_scope=True):
        ip, created = IPAddress.objects.get_or_create(
            ip_address=ip_str, defaults={'active_scope':self.active_scope,
                        'passive_scope':self.passive_scope}
        )
        if not created:
            if ip.active_scope != self.active_scope or ip.passive_scope != self.passive_scope:
                display(
                    "IP %s already exists with different scoping. Updating to Active Scope: %s Passive Scope: %s"
                    % (ip_str, self.active_scope, self.passive_scope)
                )

                ip.active_scope = self.active_scope
                ip.passive_scope = self.passive_scope
                ip.save()
        return ip

    def process_cidr(self, line, label=None):
        display("Processing %s" % line)
        if "/" in line:
            # pdb.set_trace()
            cidr, created = CIDR.objects.get_or_create(name=line.strip(), defaults={'org_name':label, 'active_scope': True, 'passive_scope': True})
            if created:
                display_new("Adding %s to Active CIDRs in database" % line.strip())
                
        elif "-" in line:
            start_ip, end_ip = line.strip().replace(" ", "").split("-")
            if "." not in end_ip:
                end_ip = ".".join(start_ip.split(".")[:3] + [end_ip])

            cidrs = iprange_to_cidrs(start_ip, end_ip)

            for c in cidrs:

                cidr, created = CIDR.objects.get_or_create(name=str(c), defaults={'active_scope': True, 'passive_scope': True})
                if created:
                    display_new("Adding %s to Active CIDRs in database" % line.strip())
                    
    def reclassify_domain(self, bd):
        if bd.meta.get("whois", False):
            display_new("Whois data found for {}".format(bd.name))
            print(bd.meta["whois"])
            res = input("Should this domain be scoped (A)ctive, (P)assive, or (N)ot? [a/p/N] ")
            if res.lower() == "a":
                bd.active_scope = True
                bd.passive_scope = True

            elif res.lower() == "p":
                bd.active_scope = False
                bd.passive_scope = True
            else:
                bd.active_scope = False
                bd.passive_scope = False
            bd.save()
        else:
            display_error(
                "Unfortunately, there is no whois information for {}. Please populate it using the Whois module".format(
                    bd.name
                )
            )

    def descope_ip(self, ip):
        ip = IPAddress.objects.get(ip_address=ip)
        if ip:
            for i in ip:
                display("Removing IP {} from scope".format(i.ip_address))
                i.active_scope = False
                i.passive_scope = False
                i.save()
                for d in i.domains:
                    active_scope_ips = [
                        ipa
                        for ipa in d.ip_addresses
                        if ipa.active_scope or ipa.passive_scope
                    ]
                    if not active_scope_ips:
                        display(
                            "Domain {} has no more scoped IPs. Removing from scope.".format(
                                d.name
                            )
                        )
                        d.active_scope = False
                        d.passive_scope = False
            

    def descope_cidr(self, cidr):
        c = CIDR.objects.get(name=cidr)
        if c:
            display("Unscoping {} from CIDRs".format(c.name))
            c.active_scope = False
        cnet = IPNetwork(cidr)
        for ip in IPAddress.objects.get(active_scope=True):
            if nIPAddress(ip.ip_address) in cnet:

                self.descope_ip(ip.ip_address)
