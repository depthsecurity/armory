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
    
    name = "SSLScan"
    binary_name = "sslscan"

    def __init__(self, db):
        self.db = db
        self.Domain = DomainRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.Port = PortRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-ho', '--host', help="Host to scan (host:port)")
        self.options.add_argument('-f', '--file', help="Import hosts from file")
        self.options.add_argument('-i', '--import_database', help="Import hosts from database", action="store_true")
        self.options.add_argument('-t', '--threads', help='Number of threads to run', default="1")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default="sslscan")
        self.options.add_argument('-s', '--rescan', help="Rescan domains that have already been scanned", action="store_true")
        self.options.add_argument('-b', '--binary', help="Binary name")
    def run(self, args):
                
        self.args = args
        if not args.binary:
            self.binary = which.run('sslscan')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("sslscan binary not found. Please explicitly provide path with --binary")


        if args.host:
            
            self.process_host(args.host)
        
        elif args.file:
            hosts = open(args.file).read().split('\n')
            for h in hosts:
                if h:
                    self.process_host(h)
                    
        elif args.import_database:
            
            
            hosts = []
            svc = []
            
            for p in ['https', 'ftps', 'imaps', 'sip-tls', 'imqtunnels', 'smtps']:
                svc += [(s, "") for s in self.Port.all(tool=self.name, service_name=p)]           
            for p in ['ftp', 'imap', 'irc', 'ldap', 'pop3', 'smtp', 'mysql', 'xmpp', 'psql']:
                svc += [(s, "--starttls-%s" % p) for s in self.Port.all(tool=self.name, service_name=p)]

            
            
            for s, option in svc:
                
                port_number = s.port_number
                ip_address = s.ip_address.ip_address

                hosts.append(("%s:%s" % (ip_address, port_number), option))

                for d in s.ip_address.domains:
                    hosts.append(("%s:%s" % (d.domain, port_number), option))

            


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
        for host, option in hosts:        
            xml_path = os.path.join(output_path, "%s-sslscan.xml" % host.replace(':', '_'))

            command_args = " --xml=%s " % xml_path
        
            
            cmd = shlex.split(self.binary + command_args + " %s " % option + host)
            
            commands.append(cmd)
        
        pool = ThreadPool(int(args.threads))

        pool.map(run_cmd, commands)    

def run_cmd(cmd):

    print("Executing: %s" % ' '.join(cmd))
        
    res = subprocess.Popen(cmd).wait()
