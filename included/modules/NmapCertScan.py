#!/usr/bin/python

from database.repositories import PortRepository
from included.ModuleTemplate import ToolTemplate
import subprocess
from included.utilities import which
import shlex
import os
import pdb
import xmltodict
from multiprocessing import Pool as ThreadPool
import glob

class Module(ToolTemplate):
    '''
    Runs nmap on all web hosts to pull certs and add them to the database
    '''
    name = "NmapCertScan"

    def __init__(self, db):
        self.db = db
        self.Port = PortRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-t', '--threads', help="Number of threads", default="1")
        self.options.add_argument('-o', '--output_path', help="Path which will contain program output (relative to base_path in config", default=self.name)
        self.options.add_argument('-s', '--rescan', help="Rescan domains that have already been scanned", action="store_true")
    
    def run(self, args):
                
        if not args.binary:
            self.binary = which.run('nmap')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("nmap binary not found. Please explicitly provide path with --binary")


        if args.rescan:
            services = self.Port.all(service_name='https')
        else:
            services = self.Port.all(tool=self.name, service_name='https')
        
        self.process_services(services, args)
        
        
                
    def process_services(self, services, args):

        if args.output_path[0] == "/":
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:])
        else:
            output_path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        cmds = []

        for s in services:
            ip = s.ip_address.ip_address
            domains = [d.domain for d in s.ip_address.domains]
            port = s.port_number

            hosts = [ip] + domains

            for h in hosts:
        
                file_path = os.path.join(output_path, "%s_%s-ssl.xml" % (h, port))
        
                command_args = " -p %s " % port
        
                command_args += " --script=ssl-cert -oX %s " % file_path

                cmds.append(shlex.split(self.binary + command_args + h))

        
        pool = ThreadPool(int(args.threads))

        
        
        # res = subprocess.Popen(cmd).wait()
        
        pool.map(scan_hosts, cmds)

        for s in services:
            
            p = s.ip_address.ip_address
            domains = [d.domain for d in s.ip_address.domains]
            port = s.port_number

            hosts = [ip] + domains

            data = {}

            for h in hosts:
                # pdb.set_trace()
                print("Processing %s" % file_path)
                file_path = os.path.join(output_path, "%s_%s-ssl.xml" % (h, port))

                try:
                    xmldata = xmltodict.parse(open(file_path).read())

                    cert = xmldata['nmaprun']['host']['ports']['port']['script']['@output']

                    if cert:
                        data[h] = cert



                except:
                    print("File not valid: %s" % file_path)
            # pdb.set_trace()
            s.meta['sslcert'] = data
            s.update()

        self.Port.commit()



def scan_hosts(cmd):
    print("Executing: %s" % ' '.join(cmd))
    res = subprocess.Popen(cmd, shell=False).wait()
