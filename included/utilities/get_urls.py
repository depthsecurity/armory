#!/usr/bin/python

from database.repositories import IPRepository
import pdb

    
def run(db):
    
    results = []
    IPAddress = IPRepository(db)
    
    ips = IPAddress.all()
    for ip in ips:

        domain_list = [d.domain for d in ip.domains]
        for s in ip.services:
            
            # print(s.name)
            if s.name == "http":
                results.append("http://%s:%s" % (ip.ip_address, s.port.port_number))
                for d in domain_list:
                    results.append("http://%s:%s" % (d, s.port.port_number))
            elif s.name == "https":
                results.append("https://%s:%s" % (ip.ip_address, s.port.port_number))
                for d in domain_list:
                    results.append("https://%s:%s" % (d, s.port.port_number))
            


    return sort_by_url(results)

def sort_by_url(data):
    d_data = {}

    for d in list(set(data)):
        host = d.split('/')[2].split(':')[0]
        scheme = d.split(':')[0]
        port = d.split(':')[2]

        if d_data.get(host, False):
            d_data[host].append([port, scheme])
        else:
            d_data[host] = [[port, scheme]]


    res = []

    for d in sorted(d_data.keys()):
        for s in sorted(d_data[d]):
            res.append("%s://%s:%s" % (s[1], d, s[0]))

    return res

