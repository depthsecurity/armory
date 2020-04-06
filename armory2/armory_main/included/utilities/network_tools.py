#!/usr/bin/env python

import socket
import dns.resolver
from netaddr import IPNetwork
private_subnets = [
    IPNetwork("0.0.0.0/8"),
    IPNetwork("10.0.0.0/8"),
    IPNetwork("100.64.0.0/10"),
    IPNetwork("127.0.0.0/8"),
    IPNetwork("169.254.0.0/16"),
    IPNetwork("172.16.0.0/12"),
    IPNetwork("192.0.0.0/24"),
    IPNetwork("192.0.2.0/24"),
    IPNetwork("192.88.99.0/24"),
    IPNetwork("192.168.0.0/16"),
    IPNetwork("198.18.0.0/15"),
    IPNetwork("198.51.100.0/24"),
    IPNetwork("203.0.113.0/24"),
    IPNetwork("224.0.0.0/4"),
    IPNetwork("240.0.0.0/4"),
    IPNetwork("255.255.255.255/32"),
]


# Shamelessly stolen from https://stackoverflow.com/a/4017219/1239023
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def validate_ip(ip):
    if is_valid_ipv4_address(ip):
        return "ipv4"
    elif is_valid_ipv6_address(ip):
        return "ipv6"

    return False
    

def get_ips(domain):
    ips = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 5.0

    try:
        answers = resolver.query(domain, "A")
        for a in answers:
            ips.append(a.address)
        return ips
    except Exception:
        # print("Regular DNS Not Resolved\n")
    # Temporarily disabling - seems to cause massive delays at times.

    #     pass
    # try:
    #    ips = [ str(i[4][0]) for i in socket.getaddrinfo(domain, 443) ] 
    #    return ips
    # except Exception:
    #    print("Unable to Resolve\n")
       return ips
