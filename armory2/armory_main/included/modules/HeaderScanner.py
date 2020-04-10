#!/usr/bin/python

from armory2.armory_main.models import Port, Domain, IPAddress
from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
import requests
import sys
from multiprocessing import Pool as ThreadPool
from armory2.armory_main.included.utilities.get_urls import run
from armory2.armory_main.included.utilities.color_display import (
    display,
    display_error,
    display_warning,
    display_new,
)
import pdb


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
                urls += run(scope_type="active", tool=self.name)



        if urls:
            pool = ThreadPool(int(args.threads))
            data = [(u, args.timeout) for u in urls]

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

                        p, created = Port.objects.get_or_create(ip_address=ip, port_number=port, service_name=scheme, proto="tcp")
                        if not p.meta.get('headers'):
                            p.meta['headers'] = {} 
                        p.meta['headers'][dom] = headers[h]
                        
                        if not p.meta.get('cookies'):
                            p.meta['cookies'] = {} 
                        p.meta['cookies'][dom] = cookies[h]
                            
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
                            p.meta['cookies'][dom] = cookies[h]
                            
                            p.save()

            
def process_urls(data):

    u = data[0]
    timeout = data[1]
    blacklist = [
        "Date",
        "Connection",
        "Content-Type",
        "Content-Length",
        "Keep-Alive",
        "Content-Encoding",
        "Vary",
    ]
    new_headers = {}
    new_cookies = {}
    
    display("Processing %s" % u)
    try:
        res = requests.get(u, timeout=int(timeout), verify=False)

        for k in res.headers.keys():
            if k not in blacklist:
                if not new_headers.get(u, False):
                    new_headers[u] = []

                new_headers[u].append("%s: %s" % (k, res.headers[k]))
        new_cookies[u] = dict(res.cookies)

    except KeyboardInterrupt:
        display_warning("Got Ctrl+C, exiting")
        sys.exit(1)
    except Exception as e:
        display_error("%s no good, skipping: %s" % (u, e))
    return (new_headers, new_cookies)

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
