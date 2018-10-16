#!/usr/bin/python

from included.ReportTemplate import ReportTemplate
from database.repositories import PortRepository
import pdb
import json



class Report(ReportTemplate):
    '''
    This report displays all of the hosts sorted by service.
    '''
    markdown = ['', '# ', '- ']

    name = ""
    def __init__(self, db):
        self.Ports = PortRepository(db)

    def run(self, args):
        # Cidrs = self.CIDR.
        results = {}

        ports = self.Ports.all()
        services = {}
        for p in ports:
            if (args.scope == 'active' and p.ip_address.in_scope) or \
                (args.scope == 'passive' and p.ip_address.passive_scope) or \
                (args.scope == 'all'):
                if not services.get(p.port_number, False):
                    services[p.port_number] = {}

                services[p.port_number][p.ip_address.ip_address] = [d.domain for d in p.ip_address.domains]

        
        res = []
        
        for s in sorted(services):
            res.append("\tPort: {}".format(s))
            res.append('\n')
            for ip in sorted(services[s].keys()):
                if services[s][ip]:
                    res.append("\t\t{}: {}".format(ip, ', '.join(services[s][ip])))
                else:
                    res.append("\t\t{} (No domain)".format(ip))
            res.append('\n')

        self.process_output(res, args)



    