#!/usr/bin/python

from database.repositories import BaseDomainRepository, DomainRepository, UserRepository
from included.ModuleTemplate import ModuleTemplate
import subprocess
from included.utilities import which
import shlex
import os
import pdb
import xmltodict
from tld import get_tld

class Module(ModuleTemplate):
    
    name = "TheHarvester"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.User = UserRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-t', '--threads', help="Number of threads")
        self.options.add_argument('-d', '--domain', help="Domain to brute force")
        self.options.add_argument('-f', '--file', help="Import domains from file")
        self.options.add_argument('-i', '--import_database', help="Import domains from database", action="store_true")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default=self.name)
        self.options.add_argument('-s', '--rescan', help="Rescan domains that have already been scanned", action="store_true")
    
    def run(self, args):
                
        if not args.binary:
            self.binary = which.run('theharvester')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("TheHarvester binary not found. Please explicitly provide path with --binary")


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
            if args.rescan:
                domains = self.BaseDomain.all()
            else:
                domains = self.BaseDomain.all(tool=self.name)
            for d in domains:
                
                self.process_domain(d, args)
                d.set_tool(self.name)
                self.BaseDomain.commit()
                
    def process_domain(self, domain_obj, args):

        domain = domain_obj.domain

        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:])
        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        output_path = os.path.join(output_path, "%s-theharvester" % domain.replace('.', '_') )
        
        command_args = " -f %s" % output_path
        
        command_args += " -b all "
        # if args.threads:
        #     command_args += " -t " + args.threads

        cmd = shlex.split(self.binary + command_args + " -d " + domain)
        print("Executing: %s" % ' '.join(cmd))
        
        res = subprocess.Popen(cmd).wait()
        
            
        try:
            data = xmltodict.parse(open(output_path + '.xml').read())
        except:
            data = None

        if data:

            if data['theHarvester'].get('email', False):
                if type(data['theHarvester']['email']) == list:
                    emails = data['theHarvester']['email']
                else:
                    emails = [data['theHarvester']['email']]
                for e in emails:

                    created, user = self.User.find_or_create(email=e)
                    user.domain = domain_obj
                    user.update()

                    if created:
                        print("New email: %s" % e)
            if data['theHarvester'].get('host', False):
                if type(data['theHarvester']['host']) == list:
                    hosts = data['theHarvester']['host']
                else:
                    hosts = [data['theHarvester']['host']]

                for d in hosts:
                    created, domain = self.Domain.find_or_create(domain=d['hostname'])
                    if created:
                        print("New domain: %s" % d['hostname'])
        if data['theHarvester'].get('vhost', False):
                if type(data['theHarvester']['vhost']) == list:
                    hosts = data['theHarvester']['vhost']
                else:
                    hosts = [data['theHarvester']['vhost']]

                for d in hosts:
                    created, domain = self.Domain.find_or_create(domain=d['hostname'])
                    if created:
                        print("New domain: %s" % d['hostname'])