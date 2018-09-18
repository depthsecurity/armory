#!/usr/bin/python

from armory import initialize_database
from armory import get_config_options
from database.repositories import BaseDomainRepository, DomainRepository, IPRepository, CIDRRepository, UserRepository, CredRepository, VulnRepository, PortRepository, UrlRepository, ScopeCIDRRepository


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

def get_domains(ip_addr):
    ips = IPAddresses.all(ip_address=ip_addr)
    if ips and len(ips) == 1:
        domains = ips[0].domains
        if domains:
            for d in domains:
                print("Domain: {}".format(d))
        else:
            print("No domains found for {}".format(ip_addr))

    else:
        print("No good results in database for {}".format(ip_addr))

print("Make sure to use this script with ipython and -i")
print("    ipython -i shell.py")

print("Available database modules: Domains, BaseDomains, IPAddresses,")
print(" CIDRs, Users, Creds, Vulns, Services, Ports, Urls, ScopeCIDRs")