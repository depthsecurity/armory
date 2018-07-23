#!/usr/bin/python

from database.repositories import BaseDomainRepository, DomainRepository
from included.ModuleTemplate import ModuleTemplate
import subprocess
from included.utilities import which
import shlex
import os
import pdb

class Module(ModuleTemplate):
    
    name = "Sublist3r"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-t', '--threads', help="Number of threads")
        self.options.add_argument('-d', '--domain', help="Domain to brute force")
        self.options.add_argument('-f', '--file', help="Import domains from file")
        self.options.add_argument('-i', '--import_database', help="Import domains from database", action="store_true")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default="sublist3r")
        self.options.add_argument('-s', '--rescan', help="Rescan domains that have already been scanned", action="store_true")
    
    def run(self, args):
                
        if not args.binary:
            self.binary = which.run('sublist3r')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("Sublist3r binary not found. Please explicitly provide path with --binary")


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
            domains = self.BaseDomain.all(tool=self.name, scope_type="passive")
            for d in domains:
                
                self.process_domain(d, args)
                d.set_tool(self.name)
                self.BaseDomain.commit()
                
    def process_domain(self, domain_obj, args):

        domain = domain_obj.domain

        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        output_path = os.path.join(output_path, "%s-sublist3r.txt" % domain)
        
        command_args = " -o %s" % output_path
        
        if args.threads:
            command_args += " -t " + args.threads

        cmd = shlex.split(self.binary + command_args + " -d " + domain)
        print("Executing: %s" % ' '.join(cmd))
        
        res = subprocess.Popen(cmd).wait()
        try:
            data = open(output_path).read().split('\n')
            for d in data:
            
                new_domain = d.split(':')[0].lower()
                if new_domain:
                    created, subdomain = self.Domain.find_or_create(domain=new_domain)
                    if created:
                        print("New subdomain found: %s" % new_domain)
                        


        except IOError:
            print("No results found.")

        
            # else:
                # print("%s already in database." % new_domain)



        