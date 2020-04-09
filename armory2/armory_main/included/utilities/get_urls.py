#!/usr/bin/python

from armory2.armory_main.models import Port
from django.db.models import Q
import pdb


def run(tool=None, args="", scope_type=None):

    results = []
    

    ports = Port.objects.all().filter(Q(service_name="http")| Q(service_name="https"))
    

    for p in ports:

        if (
            p.ip_address
            and ((scope_type == "active" and p.ip_address.active_scope)
            or (scope_type == "passive" and p.ip_address.passive_scope)
            or not scope_type) 
            and ((not tool) or (tool not in p.ip_address.tools.keys() or "{}-{}".format(p.port_number, args) not in p.ip_address.tools[tool]))
        ):
            
            results.append(
                "%s://%s:%s" % (p.service_name, p.ip_address.ip_address, p.port_number)
            )

        domain_list = [d for d in p.ip_address.domain_set.all()]


        for d in domain_list:
            
            if (
                (scope_type == "active" and d.active_scope)
                or (scope_type == "passive" and d.passive_scope)  
                or not scope_type):   # and ((not tool) or (tool in p.tools.keys() and args in p.tools[tool]))
                
                if (not tool) or (tool not in d.tools.keys() or "{}-{}".format(p.port_number, args) not in d.tools[tool]):

            
                    results.append("%s://%s:%s" % (p.service_name, d.name, p.port_number))

    return sort_by_url(results)


def sort_by_url(data):
    d_data = {}

    for d in list(set(data)):
        host = d.split("/")[2].split(":")[0]
        scheme = d.split(":")[0]
        port = d.split(":")[2]

        if d_data.get(host, False):
            d_data[host].append([port, scheme])
        else:
            d_data[host] = [[port, scheme]]

    res = []

    for d in sorted(d_data.keys()):
        for s in sorted(d_data[d]):
            res.append("%s://%s:%s" % (s[1], d, s[0]))

    return res
