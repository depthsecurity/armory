#!/usr/bin/python

from database.repositories import DomainRepository, IPRepository, CIDRRepository, BaseDomainRepository, ScopeCIDRRepository
from tld import get_tld
import dns.resolver
from included.ModuleTemplate import ModuleTemplate
from netaddr import IPNetwork, IPAddress, iprange_to_cidrs
from ipwhois import IPWhois
import pdb
import warnings
from included.utilities.color_display import display, display_new


class Module(ModuleTemplate):
    '''
    Ingests domains and IPs. Domains get ip info and cidr info, and IPs get
    CIDR info.

    '''

    name = "Ingestor"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db,self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.CIDR = CIDRRepository(db, self.name)
        self.ScopeCIDR = ScopeCIDRRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-d', '--import_domains', help="Either domain to import or file containing domains to import. One per line")
        self.options.add_argument('-i', '--import_ips', help="Either IP/range to import or file containing IPs and ranges, one per line.")
        self.options.add_argument('-a', '--active', help='Set scoping on imported data as active', action="store_true")
        self.options.add_argument('-p', '--passive', help='Set scoping on imported data as passive', action="store_true")
        self.options.add_argument('-si', '--scope_ips', help='Cycle through out of scope IPs and decide if you want to add them in scope', action="store_true")
        self.options.add_argument('-sc', '--scope_cidrs', help='Cycle through out of scope networks and decide if you want to add them in scope', action="store_true")
        self.options.add_argument('-sd', '--scope_domains', help='Cycle through out of scope domains and decide if you want to add them in scope', action="store_true")
        self.options.add_argument('-sb', '--scope_base_domains', help='Cycle through out of scope base domains and decide if you want to add them in scope', action="store_true")

        self.options.add_argument('-Ii', '--import_database_ips', help='Import IPs from database', action="store_true")
        self.options.add_argument('--force', help="Force processing again, even if already processed", action="store_true")
    def run(self, args):
        
        self.in_scope = args.active
        self.passive_scope = args.passive

        if args.import_ips:
            try:
                ips = open(args.import_ips)
                for line in ips:

                    if line.strip():
                        if '/' in line or '-' in line:
                            self.process_cidr(line)
                        
                        else:
                            self.process_ip(line.strip(), force_scope=True)
                        self.Domain.commit()
            except IOError:
                
                if '/' in args.import_ips or '-' in args.import_ips:
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


                


    def get_domain_ips(self, domain):
        ips = []
        try:
            answers = dns.resolver.query(domain, 'A')
            for a in answers:
                ips.append(a.address)
            return ips
        except:
            return []

    def process_domain(self, domain_str):
        
        created, domain = self.Domain.find_or_create(only_tool=True, domain=domain_str, in_scope=self.in_scope, passive_scope=self.passive_scope)
        if not created:
            if domain.in_scope != self.in_scope or domain.passive_scope != self.passive_scope:
                display("Domain %s already exists with different scoping. Updating to Active Scope: %s Passive Scope: %s" % (domain_str, self.in_scope, self.passive_scope))

                domain.in_scope = self.in_scope
                domain.passive_scope = self.passive_scope
                domain.update()




    def process_ip(self, ip_str, force_scope=True):
        
        created, ip = self.IPAddress.find_or_create(only_tool=True, ip_address=ip_str, in_scope=in_scope, passive_scope=self.passive_scope)
        if not created:
            if ip.in_scope != self.in_scope or ip.passive_scope != self.passive_scope:
                display("IP %s already exists with different scoping. Updating to Active Scope: %s Passive Scope: %s" % (ip_str, self.in_scope, self.passive_scope))

                ip.in_scope = self.in_scope
                ip.passive_scope = self.passive_scope
                ip.update()
        return ip   

    def process_cidr(self, line):
        display("Processing %s" % line)
        if '/' in line:
            created, cidr = self.ScopeCIDR.find_or_create(cidr=line.strip())
            if created:
                display_new("Adding %s to scoped CIDRs in database" % line.strip())
                cidr.in_scope = True
                cidr.update()


        elif '-' in line:
            start_ip, end_ip = line.strip().replace(' ', '').split('-')
            if '.' not in end_ip:
                end_ip = '.'.join(start_ip.split('.')[:3] + [end_ip])
                
            cidrs = iprange_to_cidrs(start_ip, end_ip)

            for c in cidrs:
                
                created, cidr = self.ScopeCIDR.find_or_create(cidr=str(c))
                if created:
                    display_new("Adding %s to scoped CIDRs in database" % line.strip())
                    cidr.in_scope = True
                    cidr.update()

    def scope_ips(self):
        IPAddresses = self.IPAddress.all()
