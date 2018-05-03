#!/usr/bin/python

from database.repositories import DomainRepository, IPRepository, CIDRRepository, BaseDomainRepository, ScopeCIDRRepository
from tld import get_tld
import dns.resolver
from included.ModuleTemplate import ModuleTemplate
from netaddr import IPNetwork, IPAddress, iprange_to_cidrs
from ipwhois import IPWhois
import pdb
import warnings

# Shut up whois warnings.

warnings.filterwarnings("ignore")

# List of invalid CIDRs for ipwhois

private_subnets = [IPNetwork('0.0.0.0/8'),
IPNetwork('10.0.0.0/8'),
IPNetwork('100.64.0.0/10'),
IPNetwork('127.0.0.0/8'),
IPNetwork('169.254.0.0/16'),
IPNetwork('172.16.0.0/12'),
IPNetwork('192.0.0.0/24'),
IPNetwork('192.0.2.0/24'),
IPNetwork('192.88.99.0/24'),
IPNetwork('192.168.0.0/16'),
IPNetwork('198.18.0.0/15'),
IPNetwork('198.51.100.0/24'),
IPNetwork('203.0.113.0/24'),
IPNetwork('224.0.0.0/4'),
IPNetwork('240.0.0.0/4'),
IPNetwork('255.255.255.255/32')]

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
        if args.import_file:
            domains = open(args.import_file)
            for line in domains:
                if line.strip():
                    self.process_domain(line.strip(), force_scope=True)
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
                
        if args.import_ips:
            ips = open(args.import_ips)
            for line in ips:

                if line.strip():
                    if '/' in line or '-' in line:
                        self.process_cidr(line)
                    
                    else:
                        self.process_ip(line.strip(), force_scope=True)
                    self.Domain.commit()
        
        if args.import_database_ips:
            for ip in self.IPAddress.all():
                self.process_ip(ip.ip_address)
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
        # First check if the root domain exists, and if it doesn't, add it

        
        created, domain = self.Domain.find_or_create(only_tool=True, domain=domain_str, force_in_scope=force_scope)

        # if not created:
        #     # print("%s already processed, skipping." % domain_str)
        #     return
        print("Processing %s" % domain_str)
        
        # Next get ip addresses of domain

        ips = self.get_domain_ips(domain_str)

        for i in ips:
            ip = self.process_ip(i, force_scope=force_scope)
        
            domain.ip_addresses.append(ip)
            domain.save()


    def process_ip(self, ip_str, force_scope=False):
        
        created, ip = self.IPAddress.find_or_create(only_tool=True, ip_address=ip_str, force_in_scope=force_scope)
        if created:
            print(" - Found New IP: %s" % ip_str) 

            res = self.check_private_subnets(ip_str)

            if res:
                cidr_data = res
            else:                
                try:
                    res = IPWhois(ip_str).lookup_whois(get_referral=True)
                except: 
                    res = IPWhois(ip_str).lookup_whois()
                cidr_data = []

                for n in res['nets']:
                    if ',' in n['cidr']:
                        for cidr_str in n['cidr'].split(', '):
                            cidr_data.append([cidr_str, n['description']])
                    else:
                        cidr_data.append([n['cidr'], n['description']])
        
            try:
                cidr_data = [cidr_d for cidr_d in cidr_data if IPAddress(ip_str) in IPNetwork(cidr_d[0])]
            except:
                pdb.set_trace()
            cidr_len = len(IPNetwork(cidr_data[0][0]))
            matching_cidr = cidr_data[0]
            for c in cidr_data:
                if len(IPNetwork(c[0])) < cidr_len:
                    matching_cidr = c

            print("New CIDR found: %s - %s" % (matching_cidr[1], matching_cidr[0]))
            cidr = self.CIDR.find_or_create(only_tool=True, cidr=matching_cidr[0], org_name=matching_cidr[1])[1]

            ip.cidr = cidr
            ip.save()
        # else:
        #     print(" - IP Already processed: %s" % ip_str)
        return ip   

    def check_private_subnets(self, ip_str):
        for cidr in private_subnets:

            if IPAddress(ip_str) in cidr:
                return ([str(cidr), 'Non-Public Subnet'],)

        return False


    def process_cidr(self, line):
        if '/' in line:
            print("Adding %s to scoped CIDRs" % line.strip())
            self.ScopeCIDR.find_or_create(cidr=line.strip())

        elif '-' in line:
            start_ip, end_ip = line.strip().replace(' ', '').split('-')
            if '.' not in end_ip:
                end_ip = '.'.join(start_ip.split('.')[:3] + [end_ip])
                
            cidrs = iprange_to_cidrs(start_ip, end_ip)

            for c in cidrs:
                print("Adding %s to scoped CIDRs" % str(c))
                self.ScopeCIDR.find_or_create(cidr=str(c))
