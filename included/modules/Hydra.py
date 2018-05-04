#!/usr/bin/python

from database.repositories import DomainRepository, IPRepository, PortRepository
from included.ModuleTemplate import ModuleTemplate
import subprocess
from included.utilities import which
import shlex
import os
import pdb
from multiprocessing import Pool as ThreadPool

class Module(ModuleTemplate):
    
    name = "Hydra"

    def __init__(self, db):
        self.db = db
        self.Domain = DomainRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.Port = PortRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-ho', '--host', help="Host to scan (host:port)")
        self.options.add_argument('-f', '--file', help="Import hosts from file")
        
        self.options.add_argument('-t', '--threads', help='Number of threads to run', default="1")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default="hydra")
        self.options.add_argument('-s', '--rescan', help="Rescan domains that have already been scanned", action="store_true")
    
        self.options.add_argument('--scan_defaults', help="Pull hosts out of database and scan default passwords", action="store_true")
        self.options.add_argument('--ftp_wordlist', help="Wordlist for FTP services")
        self.options.add_argument('--telnet_wordlist', help="Wordlist for Telnet")
        self.options.add_argument('--email_wordlist', help="Wordlist for email (smtp, pop3, imap)")
        self.options.add_argument('--ssh_wordlist', help="Wordlist for SSH")
        self.options.add_argument('--vnc_wordlist', help="Wordlist for VNC")
    def run(self, args):
                
        self.args = args
        if not args.binary:
            self.binary = which.run('hydra')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("hydra binary not found. Please explicitly provide path with --binary")


        if args.host:
            
            self.process_host(args.host)
        
        elif args.file:
            hosts = open(args.file).read().split('\n')
            for h in hosts:
                if h:
                    self.process_host(h)
                    
        elif args.scan_defaults:
            
            
            lists = {}
            # pdb.set_trace()
            if args.ftp_wordlist:
                for p in ['ftps', 'ftp']:
                    lists[args.ftp_wordlist] = [s for s in self.Port.all(tool=self.name, service_name=p)]           
            
            if args.telnet_wordlist:
                for p in ['telnet']:
                    lists[args.telnet_wordlist] = [s for s in self.Port.all(tool=self.name, service_name=p)]           
            
            if args.email_wordlist:
                for p in ['smtps', 'smtp', 'pop3', 'pop3s', 'imap', 'imaps']:
                    lists[args.email_wordlist] = [s for s in self.Port.all(tool=self.name, service_name=p)]           
            
            if args.ssh_wordlist:
                for p in ['ssh']:
                    lists[args.ssh_wordlist] = [s for s in self.Port.all(tool=self.name, service_name=p)]           

            if args.vnc_wordlist:
                for p in ['vnc']:
                    lists[args.vnc_wordlist] = [s for s in self.Port.all(tool=self.name, service_name=p)]           
            
            hosts = []
            for k in lists.keys():
                for s in lists[k]:
                    
                    port_number = s.port_number
                    ip_address = s.ipaddress.ip_address
                    name = s.service_name
                    
                    hosts.append("%s://%s:%s|%s" % (name, ip_address, port_number, k))

                    
            self.process_hosts(hosts)



    def process_host(self, host):

        args = self.args
        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        
        xml_path = os.path.join(output_path, "%s-sslscan.xml" % host.replace(':', '_'))

        command_args = " --xml=%s " % xml_path
        
        cmd = shlex.split(self.binary + command_args + host)
        print("Executing: %s" % ' '.join(cmd))
        
        res = subprocess.Popen(cmd).wait()
        

    def process_hosts(self, hosts):
        args = self.args
        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        commands = []
        for host in hosts:        
            host_str = host.split('|')[0]
            wordlist = host.split('|')[1]

            file_path = os.path.join(output_path, "%s.txt" % host_str.replace(':', '_').replace('/', '_'))

            command_args = " -o %s " % file_path

            command_args += " -C %s " % wordlist
        
            cmd = shlex.split(self.binary + command_args + host_str)
            commands.append(cmd)
        
        pool = ThreadPool(int(args.threads))

        pool.map(run_cmd, commands)    

def run_cmd(cmd):

    print("Executing: %s" % ' '.join(cmd))
        
    res = subprocess.Popen(cmd).wait()
