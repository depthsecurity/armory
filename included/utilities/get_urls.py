#!/usr/bin/python

from database.repositories import PortRepository
import pdb


def run(db, tool=None, scope_type=None):

    results = []
    Port = PortRepository(db)

    ports = Port.all(service_name="http", tool=tool)
    ports += Port.all(service_name="https", tool=tool)

    for p in ports:

        if (
            p.ip_address
            and (scope_type == "active" and p.ip_address.in_scope == True)
            or (scope_type == "passive" and p.ip_address.passive_scope == True)
            or not scope_type
        ):

            domain_list = [d.domain for d in p.ip_address.domains]

            results.append(
                "%s://%s:%s" % (p.service_name, p.ip_address.ip_address, p.port_number)
            )
            for d in domain_list:
                results.append("%s://%s:%s" % (p.service_name, d, p.port_number))

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
