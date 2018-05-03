from included.ModuleTemplate import ModuleTemplate
from database.repositories import BaseDomainRepository, DomainRepository, ScopeCIDRRepository
from included.utilities import which
import os
import subprocess
import json
import pdb
from exceptions import IOError
from tld import get_tld
import xml.etree.ElementTree as ET

class Module(ModuleTemplate):

    name = "DNSRecon"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.ScopeCIDR = ScopeCIDRRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()
        self.options.add_argument('-d','--domain', help="Target domain for dnsRecon")
        self.options.add_argument('-f', '--file', help="Import domains from file")
        self.options.add_argument('-i', '--import_database', help="Import domains from database", action="store_true")
        self.options.add_argument('-o', '--output_path', help="Relative path (to the base directory) to store dnsRecon XML output", default="dnsReconFiles")
        self.options.add_argument('-x', '--dns_recon_file', help="dnsRecon XML output name")
        self.options.add_argument('-r', '--range', help="Range to scan for PTR records")
        self.options.add_argument('-R', '--import_range', help="Import CIDRs from in-scope ranges in database", action="store_true")
        self.options.add_argument('--threads', help="Number of threads to use", default="10")
        self.options.add_argument('--force', help="Force overwrite", action="store_true")
        self.options.add_argument('--import_output_xml', help="Import XML file")
        self.options.add_argument('--import_output_json', help="Import json file")

    def run(self, args):
        # pdb.set_trace()
        if not args.binary:
            self.binary = which.run('dnsrecon')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("Dnsrecon binary not found. Please explicitly provide path with --binary")

        if args.output_path[0] == "/":
            self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
        else:
            self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        if args.domain:
            created, domain = self.BaseDomain.find_or_create(domain=args.domain)
            self.process_domain(domain, args)
            self.BaseDomain.commit()
        elif args.file:
            domains = open(args.file).read().split('\n')
            for d in domains:
                if d:
                    created, domain = self.BaseDomain.find_or_create(domain=d)
                    self.process_domain(domain, args)
                    self.BaseDomain.commit()

        elif args.import_database:
            domains = self.BaseDomain.all()
            for domain in domains:
                self.process_domain(domain, args)                
                self.BaseDomain.commit()

        elif args.range:
            self.process_range(args.range, args)
            self.BaseDomain.commit()

        elif args.import_range:
            cidrs = self.ScopeCIDR.all()

            for cidr in cidrs:
                self.process_range(cidr.cidr, args)
                self.BaseDomain.commit()

        elif args.import_output_json:
            data = open(args.import_output_json).read()
            self.process_data(data, args, data_type="json")
            self.BaseDomain.commit()

        elif args.import_output_xml:
            data = open(args.import_output_xml).read()
            self.process_data(data, args, data_type="json")
            self.BaseDomain.commit()

        else:
            print("You need to supply some options to do something.")
    def process_domain(self, domain_obj, args):

        domain = domain_obj.domain
        print("Processing %s" % domain)
        if args.dns_recon_file:
            dns_recon_file = os.path.join(self.path,args.dnsReconFile)
        else:
            dns_recon_file = os.path.join(self.path,domain+".json")

        if os.path.isfile(dns_recon_file):
            if not args.force:
                answered = False
                while answered == False:
                    rerun = raw_input("Would you like to [r]un dnsRecon again and overwrite the file, [p]arse the file, or change the file [n]ame? ")
                    if rerun.lower() == 'r':
                        answered = True
                    
                    elif rerun.lower() == 'p':
                        answered = True
                        return dnsReconFile

                    elif rerun.lower() == 'n':
                        new = False
                        while new == False:
                            newFile = raw_input("enter a new file name: ")
                            if not os.path.exists(os.path.join(self.path,newFile)):
                                dns_recon_file = os.path.join(path,newFile)
                                answered = True
                                new = True
                            else:
                                print "That file exists as well"
        command = self.binary

        if args.threads:
            command += " --threads %s " % args.threads

        command += " -d {} -j {} ".format(domain, dns_recon_file)
        
        subprocess.Popen(command, shell=True).wait()

        try:
            res = json.loads(open(dns_recon_file).read())
            domain_obj.dns = {'data':res}
            domain_obj.save()


            self.process_data(res, args, data_type='json')
        except IOError:
            print("DnsRecon for %s failed." % domain)
            return None

    def process_data(self, data, args, data_type="json"):

        if data_type == "xml":
            tree = ET.fromstring(data)
            root = tree.getroot()
            records = root.findall("record")
        else:
            records = data

        for record in data:
            created = False
            domain = ""
            if record.get("type") == "A":
                created, domain = self.Domain.find_or_create(domain=record.get("name").lower().replace("www.",""))
            if record.get("type") == "A" :
                domain = record.get("name").lower().replace("www.","")
                #ip = record.get("address")     #take what nslookup(get_domain_ip) says instead
            
            elif record.get("type") == "MX":
                domain = record.get("exchange").lower().replace("www.","")

            elif record.get("type") == "SRV":
                domain = record.get("target").lower().replace("www.","")

            if domain:
                created, domain_obj = self.Domain.find_or_create(domain=domain)
                if created: 
                    print("New domain found: " + domain)
                

    def process_range(self, cidr, args):

        
        print("Processing %s" % cidr)
        if args.dns_recon_file:
            dns_recon_file = os.path.join(self.path,args.dnsReconFile)
        else:
            dns_recon_file = os.path.join(self.path,cidr.replace('/', '_')+".json")

        if os.path.isfile(dns_recon_file):
            if not args.force:
                answered = False
                while answered == False:
                    rerun = raw_input("Would you like to [r]un dnsRecon again and overwrite the file, [p]arse the file, or change the file [n]ame? ")
                    if rerun.lower() == 'r':
                        answered = True
                    
                    elif rerun.lower() == 'p':
                        answered = True
                        return dnsReconFile

                    elif rerun.lower() == 'n':
                        new = False
                        while new == False:
                            newFile = raw_input("enter a new file name: ")
                            if not os.path.exists(os.path.join(self.path,newFile)):
                                dns_recon_file = os.path.join(path,newFile)
                                answered = True
                                new = True
                            else:
                                print "That file exists as well"
        command = self.binary

        if args.threads:
            command += " --threads %s " % args.threads

        command += " -s -r {} -j {} ".format(cidr, dns_recon_file)
        
        subprocess.Popen(command, shell=True).wait()

        try:
            res = json.loads(open(dns_recon_file).read())
            
            for r in res[1:]:

                domain = r['name']
                created, domain_obj = self.Domain.find_or_create(domain=domain)
                if created:
                    print("New domain found: %s" % domain)
                

            self.process_data(res, args, data_type='json')
        except IOError:
            print("DnsRecon for %s failed." % domain)
            return None
