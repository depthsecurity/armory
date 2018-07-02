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

        self.options.add_argument('-f', '--import_file', help="File containing domains to import. One per line")
        self.options.add_argument('-d', '--domain', help="Single domain to import")
        self.options.add_argument('-i', '--import_ips', help="File containing IPs and ranges, one per line.")
        self.options.add_argument('-Id', '--import_database_domains', help='Import domains from database', action="store_true")
        self.options.add_argument('-Ii', '--import_database_ips', help='Import IPs from database', action="store_true")
        self.options.add_argument('--force', help="Force processing again, even if already processed", action="store_true")
    def run(self, args):
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

        if args.import_database_ips:
            for ip in self.IPAddress.all():
                self.process_ip(ip.ip_address)
                self.Domain.commit()

        if args.import_file:
            domains = open(args.import_file)
            for line in domains:
                if line.strip():
                    self.process_domain(line.strip())
                    self.Domain.commit()
            
        if args.domain:
            self.process_domain(args.domain, force_scope=True)
            self.Domain.commit()
        
        if args.import_database_domains:
            if args.force:
                domains = self.Domain.all()
            else:
                domains = self.Domain.all(tool=self.name)
            for d in domains:
                # pdb.set_trace()
                self.process_domain(d.domain)
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

    def process_domain(self, domain_str, force_scope=False):
        
        created, domain = self.Domain.find_or_create(only_tool=True, domain=domain_str, in_scope=force_scope, passive_scope=True)


    def process_ip(self, ip_str, force_scope=True):
        
        created, ip = self.IPAddress.find_or_create(only_tool=True, ip_address=ip_str, in_scope=force_scope, passive_scope=True)

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
