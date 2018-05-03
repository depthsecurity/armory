#!/usr/bin/python

from database.repositories import BaseDomainRepository, DomainRepository
from included.ModuleTemplate import ModuleTemplate
from subprocess import check_output
from included.utilities import which
import shlex
import os

class Module(ModuleTemplate):
    
    name = "GobusterDNS"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-fw', '--force_wildcard', help="Continues after hitting wildcard cert", action="store_true")
        self.options.add_argument('-t', '--threads', help="Number of threads")
        self.options.add_argument('-d', '--domain', help="Domain to brute force")
        self.options.add_argument('-w', '--wordlist', help="Wordlist to use")
        self.options.add_argument('-f', '--file', help="Import domains from file")
        self.options.add_argument('-i', '--import_database', help="Import domains from database", action="store_true")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default="gobuster")
        self.options.add_argument('-s', '--rescan', help="Rescan domains that have already been brute forced", action="store_true")
    
    def run(self, args):
        
        if not args.wordlist:
            print("Wordlist is required!")
            return
        
        if not args.binary:
            self.binary = which.run('gobuster')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("Gobuster binary not found. Please explicitly provide path with --binary")


        if args.domain:
            created, domain = self.BaseDomain.find_or_create(domain=args.domain)
            self.brute_force_domain(domain, args)
            self.BaseDomain.commit()
        elif args.file:
            domains = open(args.file).read().split('\n')
            for d in domains:
                if d:
                    created, domain = self.BaseDomain.find_or_create(domain=d)
                    self.brute_force_domain(domain, args)
                    self.BaseDomain.commit()

        elif args.import_database:
            if args.rescan:
                domains = self.BaseDomain.all()
            else:
                domains = self.BaseDomain.all(tool=self.name)
            for domain in domains:
                self.brute_force_domain(domain, args) 
                domain.set_tool(self.name)               
                self.BaseDomain.commit()

    def brute_force_domain(self, domain_obj, args):

        domain = domain_obj.domain

        command_args = " -m dns"
        
        if args.force_wildcard:
            command_args += " -fw"

        if args.threads:
            command_args += " -t " + args.threads

        command_args += " -w " + args.wordlist        

        cmd = shlex.split(self.binary + command_args + " -u " + domain)
        print("Executing: %s" % ' '.join(cmd))
        res = check_output(cmd)

        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        output_path = os.path.join(output_path, "%s-dns.txt" % domain)
        open(output_path, 'w').write(res)

        data = res.split('\n')

        for d in data:
            if 'Found: ' in d:
                new_domain = d.split(' ')[1].lower()
                created, subdomain = self.Domain.find_or_create(domain=new_domain)
                if created:
                    print("New subdomain found: %s" % new_domain)

                # else:
                    # print("%s already in database." % new_domain)

