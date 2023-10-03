#!/usr/bin/python
#Original idea by Matt Burch @ Optiv https://www.optiv.com/insights/source-zero/blog/abusing-airwatch-mdm-services-bypass-mfa
#This module does simple GET requests to the known API endpoints passing in a domain. That is it. No other fancy aircross.go stuff just quick checks use OG aircross for more in depth testing

from armory2.armory_main.models import Port, Domain, IPAddress, BaseDomain, User
from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
import requests
import sys

from armory2.armory_main.included.utilities.color_display import (
    display,
    display_error,
    display_warning,
    display_new,
)
import pdb
import json

import urllib3
import urllib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_domain(domain):
    UA = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36'
    headers = {'User-Agent': UA}
    hasAirCross = False

    url = "https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v1/domainlookup/domain/"+domain
    #print(urllib.parse.quote(domain))

    res = requests.get(url, headers=headers, verify=False)
    if res.status_code == 200:
        return True
    res = requests.get("https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v2/domainlookup/domain/"+domain, headers=headers, verify=False)     
    if res.status_code == 200:
        return True

    return False
    


class Module(ModuleTemplate):
    '''
    performs basic aircross check based on aircross.go by Optiv
    '''
    name = "airCross Check"

    def set_options(self):
        super(Module, self).set_options()

        # self.options.add_argument(
        #     "-t", "--timeout", help="Connection timeout (default 5)", default="5"
        
        self.options.add_argument("--domain", help="Domain to check aircross on")
        self.options.add_argument("--file", help="Import Domains from file")
        self.options.add_argument(
            "-i",
            "--import_db",
            help="Import Domains from the database",
            action="store_true",
        )
        self.options.add_argument
        # self.options.add_argument(
        #     "-th", "--threads", help="Number of threads to run", default="10"
        # )
        self.options.add_argument(
            "--rescan", help="Rescan Domains already processed", action="store_true"
        )
        

    def run(self, args):
        domains = []
        if args.domain:
            domains.append(args.domain)
            
        if args.file:
            domain_data = open(args.file).read().split("\n")
            for i in domain_data:
                if i:
                    domains.append(i)

        if args.import_db:

                    
            if args.rescan:

                domains += [b.name for b in BaseDomain.get_set(scope_type="passive")]
            else:
                domains += [b.name for b in BaseDomain.get_set(scope_type="passive", tool=self.name)]



        if domains:
            display(f"Querying {len(domains)} domains.")
            for i in domains:
                display(f"Processing {i}")
                hasAirCross = check_domain(i)                
                if hasAirCross:
                    display_new(f"Discovered airCross on "+i)
                
                dom, created = BaseDomain.objects.get_or_create(name=i, defaults={'passive_scope': True, 'active_scope': False})
                dom.add_tool_run(self.name)
