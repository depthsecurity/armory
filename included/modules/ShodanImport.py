#!/usr/bin/python

from included.ModuleTemplate import ModuleTemplate

from database.repositories import PortRepository, IPRepository, ScopeCIDRRepository
import time
import os
import sys
import pdb
from included.utilities.color_display import display, display_error, display_warning, display_new
import shodan as shodan_api



class Module(ModuleTemplate):
    '''
    The Shodan module will either iterate through Shodan search results from net:<cidr>
    for all scoped CIDRs, or a custom search query. The resulting IPs and ports will be
    added to the database, along with a dictionary object of the API results.

    '''
    name = "ShodanImport"

    def __init__(self, db):
        self.db = db
        self.Port = PortRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.ScopeCidr = ScopeCIDRRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('-k', '--api_key', help='API Key for accessing Shodan')
        self.options.add_argument('-s', '--search', help="Custom search string")
        self.options.add_argument('-i', '--import_db', help="Import scoped IPs from the database", action="store_true")
        self.options.add_argument('--rescan', help="Rescan CIDRs already processed", action="store_true")


    def run(self, args):
        
        if not args.api_key:
            display_error("You must supply an API key to use shodan!")
            return

        if args.search:
            ranges = [args.search]

        if args.import_db:
            ranges = []
            if args.rescan:
                ranges += ["net:{}".format(c.cidr) for c in self.ScopeCidr.all()]
            else:
                ranges += ["net:{}".format(c.cidr) for c in self.ScopeCidr.all(tool=self.name)]
         
        api = shodan_api.Shodan(args.api_key)

        for r in ranges:
            time.sleep(1)
            # pdb.set_trace()
            results = api.search(r)            

            display("{} results found for: {}".format(results['total'], r))


            for res in results['matches']:
                ip_address_str = res['ip_str']
                port_str = res['port']
                transport = res['transport']
                display("Processing IP: {} Port: {}/{}".format(ip_address_str, port_str, transport))
                created, IP = self.IPAddress.find_or_create(ip_address = ip_address_str)
                created, port = self.Port.find_or_create(ip_address = IP, port_number = port_str, proto = transport)
                port.meta['shodan_data'] = res
                port.save()

        self.IPAddress.commit()
