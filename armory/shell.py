#!/usr/bin/env python
from IPython import embed
from .armory import initialize_database
from .armory import get_config_options
from .database.repositories import (
    BaseDomainRepository,
    DomainRepository,
    IPRepository,
    CIDRRepository,
    UserRepository,
    CredRepository,
    VulnRepository,
    PortRepository,
    UrlRepository,
    ScopeCIDRRepository,
)


def main():
    global Domains, IPAddresses, CIDRs, Users, Creds, Vulns, Ports, Urls, ScopeCIDRs, BaseDomains
    config = get_config_options()
    db = initialize_database(config)
    Domains = DomainRepository(db, "Shell Client")
    BaseDomains = BaseDomainRepository(db, "Shell Client")
    IPAddresses = IPRepository(db, "Shell Client")
    CIDRs = CIDRRepository(db, "Shell Client")
    Users = UserRepository(db, "Shell Client")
    Creds = CredRepository(db, "Shell Client")
    Vulns = VulnRepository(db, "Shell Client")
    Ports = PortRepository(db, "Shell Client")
    Urls = UrlRepository(db, "Shell Client")
    ScopeCIDRs = ScopeCIDRRepository(db, "Shell Client")
    print()
    print("Available database modules: Domains, BaseDomains, IPAddresses,")
    print(" CIDRs, Users, Creds, Vulns, Ports, Urls, ScopeCIDRs")
    print()
    print("Additional functions:")
    print("   get_domains(ip_address)                      # Get all domain names for an IP")
    print("   get_ips(domain)                              # Get all IP addresses for a domain")
    print("   unscope_base_and_children(BaseDomains list)  # Unscope all basedomains, child domains, and child ip addresses in list of BaseDomain objects")
    print()
    print("Additional ORM commands available on wiki at https://github.com/depthsecurity/armory/wiki/armory-shell")
    print()
    embed(using=False)


def get_domains(ip_addr):
    domain_list = []
    ips = IPAddresses.all(ip_address=ip_addr)
    if ips and len(ips) == 1:
        domains = ips[0].domains
        if domains:
            for d in domains:
                print(d.domain)
                domain_list.append(d.domain)
        else:
            print("No domains found for {}".format(ip_addr))

    else:
        print("No good results in database for {}".format(ip_addr))

    return domain_list


def get_ips(domain):
    d = Domains.all(domain=domain)
    ips = [i.ip_address for i in d[0].ip_addresses]
    return ips

def rescope_base_and_children(bds, active=False, passive=False):
    '''
    Takes a list of BaseDomains. Iterates through and rescopes
    BaseDomain, subdomains, and ip addresses. Example:

    rescope_base_and_children(basedomains, active=False, passive=True)

    '''

    for bd in bds:
        bd.in_scope = active
        bd.passive_scope = passive
        for d in bd.subdomains:
            d.in_scope = active
            d.passive_scope = passive
            for ip in d.ip_addresses:
                ip.in_scope = active
                ip.passive_scope = passive
                ip.save()
            d.save()
        bd.save()
    BaseDomains.commit()

def rescope_cidr_and_children(cidrs, active=False, passive=False):
    '''
    Takes a list of CIDRs. Iterates through and rescopes
    IP Address and associated domains. Useful for culling out 
    unconfigured landing pages (ie Godaddy), etc.

    Example:
    rescope_cidr_and_children(cidrs, active=False, passive=True)

    '''

    for cidr in cidrs:
        for ip in cidr.ip_addresses:
            ip.in_scope = active
            ip.passive_scope = passive
            ip.save()
            for domain in ip.domains:
                domain.in_scope = active
                domain.passive_scope = passive
                domain.save()

    CIDRs.commit()
    


