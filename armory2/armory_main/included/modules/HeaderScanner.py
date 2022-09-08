#!/usr/bin/python

from armory2.armory_main.models import Port, Domain, IPAddress
from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
import requests
import sys
from multiprocessing import Pool as ThreadPool
from armory2.armory_main.included.utilities.get_urls import run
from armory2.armory_main.included.utilities.header_tools import process_urls

from armory2.armory_main.included.utilities.color_display import (
    display,
    display_error,
    display_warning,
    display_new,
)
import pdb
import pickle


def check_if_ip(txt):
    try:
        int(txt.replace(".", ""))
        return True
    except ValueError:
        return False



class Module(ModuleTemplate):

    name = "HeaderScanner"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-t", "--timeout", help="Connection timeout (default 5)", default="5"
        )
        self.options.add_argument("-u", "--url", help="URL to get headers")
        self.options.add_argument("--file", help="Import URLs from file")
        self.options.add_argument(
            "-i",
            "--import_db",
            help="Import URLs from the database",
            action="store_true",
        )
        self.options.add_argument(
            "-th", "--threads", help="Number of threads to run", default="10"
        )
        self.options.add_argument(
            "--rescan", help="Rescan URLs already processed", action="store_true"
        )

    def run(self, args):
        urls = []
        if args.url:
            urls.append(args.url)
            
        if args.file:
            url = open(args.file).read().split("\n")
            for u in url:
                if u:
                    urls.append(u)

        if args.import_db:

                    
            if args.rescan:
                urls += run(scope_type="active")
            else:
                urls += run(scope_type="active", tool=self.name, args="")



        if urls:
            pool = ThreadPool(int(args.threads))
            data = [(u, args.timeout) for u in urls]
            # pdb.set_trace()
            results = pool.map(process_urls, data)
            display_new("Adding headers to the database")
            
            for headers, cookies in results:
                if len(list(headers.keys())) > 0:
                    h = list(headers.keys())[0]
                    dom, dom_type, scheme, port = get_url_data(h)
                    display("Processing headers and cookies from URL {}".format(h))
                
                    if dom_type == 'ip':
                        ip, created = IPAddress.objects.get_or_create(ip_address=dom)
                        
                        ip.add_tool_run(tool=self.name)
                        # pdb.set_trace()
                        p, created = Port.objects.get_or_create(ip_address=ip, port_number=port, service_name=scheme, proto="tcp")
                        if not p.meta.get('headers'):
                            p.meta['headers'] = {} 
                        p.meta['headers'][dom] = headers[h]
                        
                        if not p.meta.get('cookies'):
                            p.meta['cookies'] = {} 
                        
                        p.meta['cookies'][dom] = cookies.get(h, [])
                        
                        p.save()

                    else:
                        domain, created = Domain.objects.get_or_create(name=dom)

                        domain.add_tool_run(tool=self.name)

                        for ip in domain.ip_addresses.all():

                            p, created = Port.objects.get_or_create(ip_address=ip, port_number=port, service_name=scheme, proto="tcp")
                            if not p.meta.get('headers'):
                                p.meta['headers'] = {} 
                            p.meta['headers'][dom] = headers[h]
                            
                            if not p.meta.get('cookies'):
                                p.meta['cookies'] = {} 
                            p.meta['cookies'][dom] = cookies.get(h, [])
                            
                            p.save()

            


def get_url_data(url):

    scheme = url.split(':')[0]
    if url.count(':') == 2:
        port = url.split(':')[-1]
    elif scheme == 'http':
        port = 80
    elif scheme == 'https':
        port = 443
    else:
        port = 0
    
    dom = url.split('/')[2].split(':')[0]
    try:
        [int(i) for i in dom.split('.')]
        # If we made it here, it is an IP

        dom_type = 'ip'
    except:
        dom_type = "domain"

    return dom, dom_type, scheme, port
