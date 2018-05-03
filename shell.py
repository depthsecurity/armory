#!/usr/bin/python

from mastertool import initialize_database
from mastertool import get_config_options
from database.repositories import BaseDomainRepository, DomainRepository, IPRepository, CIDRRepository, UserRepository, CredRepository, VulnRepository, ServiceRepository, PortRepository, UrlRepository, ScopeCIDRRepository


config = get_config_options()
db = initialize_database(config)
Domains = DomainRepository(db, "Shell Client")
BaseDomains = BaseDomainRepository(db, "Shell Client")
IPAddresses = IPRepository(db, "Shell Client")
CIDRs = CIDRRepository(db, "Shell Client")
Users = UserRepository(db, "Shell Client")
Creds = CredRepository(db, "Shell Client")
Vulns = VulnRepository(db, "Shell Client")
Services = ServiceRepository(db, "Shell Client")
Ports = PortRepository(db, "Shell Client")
Urls = UrlRepository(db, "Shell Client")
ScopeCIDRs = ScopeCIDRRepository(db, "Shell Client")


print("Make sure to use this script with ipython and -i")
print("    ipython -i shell.py")

print("Available database modules: Domains, BaseDomains, IPAddresses,")
print(" CIDRs, Users, Creds, Vulns, Services, Ports, Urls, ScopeCIDRs")