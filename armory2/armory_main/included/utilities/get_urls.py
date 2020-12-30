#!/usr/bin/python

from armory2.armory_main.models import Port, IPAddress, Domain
from django.db.models import Q
import pdb
import random as random_lib

def run(tool=None, args="", scope_type=None, random=True):

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

    if random:
        random_lib.shuffle(results)
        
        return results
    return sort_by_url(results)

def get_web_ips(tool=None, args="", scope_type=None, random=True):
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
                p.ip_address.ip_address
            )

    results = sorted(list(set(results)))

    if random:
        random_lib.shuffle(results)
        
    return results

def add_tools_urls(tool, args="", scope_type=None):

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
            
            p.ip_address.add_tool_run(tool, args="{}-{}".format(p.port_number, args))
            

        domain_list = [d for d in p.ip_address.domain_set.all()]


        for d in domain_list:
            
            if (
                (scope_type == "active" and d.active_scope)
                or (scope_type == "passive" and d.passive_scope)  
                or not scope_type):   # and ((not tool) or (tool in p.tools.keys() and args in p.tools[tool]))
                
                if (not tool) or (tool not in d.tools.keys() or "{}-{}".format(p.port_number, args) not in d.tools[tool]):

            
                    d.add_tool_run(tool, args="{}-{}".format(p.port_number, args))

    


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

def add_tool_url(url, tool, args):

    host = url.split("/")[2].split(":")[0]
    scheme = url.split(":")[0]
    port = url.split(":")[2]
    
    try:
        [int(i) for i in host.split('.')]
        ip, created = IPAddress.objects.get_or_create(ip_address=host)
        ip.add_tool_run(tool=tool, args="{}-{}".format(port, args))
    except:
        d, created = Domain.objects.get_or_create(name=host)
        d.add_tool_run(tool=tool, args="{}-{}".format(port, args))
    
def get_port_object(url):
    # pdb.set_trace()
    host = url.split("/")[2].split(":")[0]
    
    port = url.split(":")[2]
    
    try:
        [int(i) for i in host.split('.')]
        ports = Port.objects.filter(ip_address__ip_address=host, port_number=port, proto='tcp')
        
    except:
        ips = IPAddress.objects.filter(domain__name=host)

        ports = ips[0].port_set.filter(port_number=443, proto='tcp')

    if ports:
        return ports[0]
    else:
        return None
        