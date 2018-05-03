#!/usr/bin/python

from database.repositories import BaseDomainRepository, ScopeCIDRRepository
from included.ModuleTemplate import ModuleTemplate
import subprocess
from included.utilities import which
import shlex
import os
import pdb
from multiprocessing import Pool as ThreadPool
import json

class Module(ModuleTemplate):
    
    name = "Whois"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.ScopeCidr = ScopeCIDRRepository(db, self.name)
        
    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-d', '--domain', help="Domain to query")
        self.options.add_argument('-c', '--cidr', help="CIDR to query")
        
        self.options.add_argument('-t', '--threads', help='Number of threads to run', default="1")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default="whois")
        self.options.add_argument('-s', '--rescan', help="Rescan domains that have already been scanned", action="store_true")
    
        self.options.add_argument('--import_database', help="Run WHOIS on all domains and CIDRs in database", action="store_true")
        
    def run(self, args):
                
        self.args = args
        if not args.binary:
            self.binary = which.run('whois')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("whois binary not found. Please explicitly provide path with --binary")


        if args.domain:
            created, domain = self.BaseDomain.find_or_create(domain=args.domain)
            
            self.process_domains(domains=[domain], ips=[])
        
        elif args.cidr:
            created, cidr = self.ScopeCIDR.find_or_create(cidr=args.cidr)
            
            self.process_domains(domains=[], ips=[domain])
                    
        elif args.import_database:
            
            domains = self.BaseDomain.all()
            cidrs = self.ScopeCidr.all()


            self.process_domains(domains=domains, cidrs=cidrs)

            self.ScopeCidr.commit()

    def process_domains(self, domains, cidrs):

        args = self.args
        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        
        

        commands = []

        for domain in domains: 
            name = domain.domain

            file_path = os.path.join(output_path, "%s.txt" % name)

            command_args = " "
        
            cmd = shlex.split(self.binary + command_args + name)
            commands.append([cmd, file_path, name])
        
        for cidr in cidrs: 
            name = cidr.cidr.split('/')[0]

            file_path = os.path.join(output_path, "%s.txt" % name)

            command_args = " "
        
            cmd = shlex.split(self.binary + command_args + name)
            commands.append([cmd, file_path, cidr.cidr])
        
        pool = ThreadPool(int(args.threads))
        
        
        res = pool.map(run_cmd, commands)

        print("Importing data to database")

        res_d = {}

        for r in res:
            if r:
                res_d[r[0]] = r[1]

        domains = self.BaseDomain.all()

        for d in domains:
            if res_d.get(d.domain, False):
                d.meta['whois'] = res_d[d.domain]
                d.update()
        pdb.set_trace()
        for c in self.ScopeCidr.all():
            if res_d.get(c.cidr, False):
                c.meta['whois'] = res_d[c.cidr]
                c.update()


def run_cmd(cmd):
    
    print("Executing: %s" % ' '.join(cmd[0]))
        
    try:
        # res = subprocess.check_output(cmd[0])
        #open(cmd[1], 'w').write(res)
        res = open(cmd[1]).read()
        return (cmd[2], res)

    except:
        return None