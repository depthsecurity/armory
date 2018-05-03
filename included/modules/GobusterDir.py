#!/usr/bin/python

from database.repositories import IPRepository, DomainRepository, PortRepository, UrlRepository
from included.ModuleTemplate import ModuleTemplate
from subprocess import Popen
from included.utilities import which, get_urls
import shlex
import os
import re
import pdb
from multiprocessing import Pool as ThreadPool


try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


class Module(ModuleTemplate):
    
    name = "GobusterDir"

    def __init__(self, db):
        self.db = db
        self.IPAddress = IPRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.Port = PortRepository(db, self.name)
        self.Url = UrlRepository(db, self.name)
        

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-P', '--auth_password', help="Password for basic auth")
        self.options.add_argument('-U', '--auth_username', help="Username for basic auth")
        self.options.add_argument('-a', '--user_agent', help="User agent string")
        self.options.add_argument('-c', '--cookies', help="Cookies to use for the requests")
        self.options.add_argument('-f', '--forward_slash', help="Add a forward slash to URL", action="store_true")
        self.options.add_argument('-t', '--threads', help="Number of threads")
        self.options.add_argument('-p', '--proxy', help="Proxy to use for requests")
        self.options.add_argument('-r', '--redirects', help="Follow redirects", action="store_true")
        self.options.add_argument('-s', '--scan_codes', help="Positive scan codes (default '200,204,301,302,307')")
        self.options.add_argument('-x', '--extension', help="File extension to search for")
        self.options.add_argument('-u', '--url', help="URL to brute force")
        self.options.add_argument('-w', '--wordlist', help="Wordlist to use")
        self.options.add_argument('--file', help="Import URLs from file")
        self.options.add_argument('-i', '--import_database', help="Import URLs from database", action="store_true")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default="gobuster")
        self.options.add_argument('--force', help="Rescan domains that have already been brute forced", action="store_true")
        self.options.add_argument('--output_file', help="Name of file to output results to", default="output.txt")
        self.options.add_argument('--process_threads', help="Number of threads master tool will use", default="10")
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

        # pdb.set_trace()
        if args.url:
            
            self.brute_force_domain(args.url, args)
            self.Domain.commit()
        
        elif args.file:
            urls = open(args.file).read().split('\n')
            for u in urls:
                if u:
                    self.brute_force_domain(u, args)
                    self.Domain.commit()

        elif args.import_database:
            urls = get_urls.run(self.db)
            
        
        
            self.brute_force_domains(urls, args)                
                

    def brute_force_domain(self, url, args):

        res = urlparse(url)
        host = res.netloc.split(':')[0]
        if ':' in res.netloc:
            port = int(res.netloc.split(':')[1])
        elif res.scheme == 'https':
            port = 443
        else:
            port = 80
        # if re.match( r'(\d*)\.(\d*)\.(\d*)\.(\d)', host, re.M|re.I):
        #     created, ip = self.IPAddress.find_or_create(ip_address=host)
        # else:
        #     created, domain = self.Domain.find_or_create(domain=host)
        #     ip = domain.ip_addresses[0]

        # created, port = self.Port.find_or_create(port_number=port, ip_address_id = ip.id)



        command_args = " -m dir"
        
        if args.auth_username and args.auth_password:
            command_args += " -U %s -P %s " % (args.auth_username, args.auth_password)

        if args.threads:
            command_args += " -t " + args.threads

        command_args += " -k -w " + args.wordlist        

        if args.user_agent:
            command_args += " -a %s " % args.user_agent

        if args.cookies:
            command_args += " -c %s " % args.cookies

        if args.proxy:
            command_args += " -p %s " % args.proxy

        if args.redirects:
            command_args += " -r "

        if args.scan_codes:
            command_args += " -s %s " % args.scan_codes

        if args.extension:
            command_args += " -x %s " % args.extension

        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )

        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)


        if not os.path.exists(output_path):
            os.makedirs(output_path)

        output_path = os.path.join(output_path, "%s-dir.txt" % url.split('/')[-1])
        command_args += " -o %s " % output_path

        

        cmd = shlex.split(self.binary + command_args + " -l -u " + url)
        print("Executing: %s" % ' '.join(cmd))
        
        Popen(cmd, shell=False).wait()

    def brute_force_domains(self, urls, args):

        commands = []

        for url in urls:
            res = urlparse(url)
            host = res.netloc.split(':')[0]
            if ':' in res.netloc:
                port = int(res.netloc.split(':')[1])
            elif res.scheme == 'https':
                port = 443
            else:
                port = 80
            # if re.match( r'(\d*)\.(\d*)\.(\d*)\.(\d)', host, re.M|re.I):
            #     created, ip = self.IPAddress.find_or_create(ip_address=host)
            # else:
            #     created, domain = self.Domain.find_or_create(domain=host)
            #     ip = domain.ip_addresses[0]

            # created, port = self.Port.find_or_create(port_number=port, ip_address_id = ip.id)



            command_args = " -m dir"
            
            if args.auth_username and args.auth_password:
                command_args += " -U %s -P %s " % (args.auth_username, args.auth_password)

            if args.threads:
                command_args += " -t " + args.threads

            command_args += " -k -w " + args.wordlist        

            if args.user_agent:
                command_args += " -a %s " % args.user_agent

            if args.cookies:
                command_args += " -c %s " % args.cookies

            if args.proxy:
                command_args += " -p %s " % args.proxy

            if args.redirects:
                command_args += " -r "

            if args.scan_codes:
                command_args += " -s %s " % args.scan_codes

            if args.extension:
                command_args += " -x %s " % args.extension

            if args.output_path[0] == "/":
                output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )

            else:
                output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)


            if not os.path.exists(output_path):
                os.makedirs(output_path)

            output_path = os.path.join(output_path, "%s-dir.txt" % url.split('/')[-1])
            command_args += " -o %s " % output_path

        

            commands.append(shlex.split(self.binary + command_args + " -l -u " + url))

        
        
        pool = ThreadPool(int(args.process_threads))

        pool.map(run_cmd, commands)    

def run_cmd(cmd):

    print("Executing: %s" % ' '.join(cmd))
        
    res = Popen(cmd).wait()