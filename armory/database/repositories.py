#!/usr/bin/env python
from .models import Models
import datetime
import pdb
import time
import tldextract
from netaddr import IPNetwork, IPAddress
from ipwhois import IPWhois
import warnings
import dns.resolver
from armory.included.utilities.color_display import display, display_warning, display_new, display_error
import sys
from armory.included.utilities.get_domain_ip import run as get_ip
if sys.version[0] == '3':
    raw_input = input
import socket

# Shut up whois warnings.

warnings.filterwarnings("ignore")

# List of invalid CIDRs for ipwhois

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


class BaseRepository(object):
    model = None

    def __init__(self, db, toolname=None):
        self.db = db
        self.toolname = toolname

    def find(self, **kwargs):
        """
        This function can be used to find an object, but won't create one.
        """
        obj = self.db.db_session.query(self.model).filter_by(**kwargs).one_or_none()

        return obj

    def find_or_create(self, only_tool=False, **kwargs):
        """
        This function can be used to look for one object. If it doesn't
        exist, it'll be created. The 'only_tool' parameter will only
        return newly created if the object has never been touched by
        that tool before.
        """

        created = False

        obj = self.db.db_session.query(self.model).filter_by(**kwargs).one_or_none()

        if only_tool:
            if obj is None:
                created = True
                obj = self.model.create(**kwargs)
                meta = {self.toolname: {"created": str(datetime.datetime.now())}}
                obj.meta = meta
                obj.save()
            else:
                # pdb.set_trace()
                meta = obj.meta
                if meta:
                    if meta.get(self.toolname, False):
                        if meta[self.toolname].get("created", False):
                            created = False
                        else:
                            meta[self.toolname]["created"] = str(
                                datetime.datetime.now()
                            )
                            created = True
                    else:
                        meta[self.toolname] = {"created": str(datetime.datetime.now())}
                        created = True
                else:
                    meta = {self.toolname: {"created": str(datetime.datetime.now())}}
                    created = True

                # pdb.set_trace()
                obj.meta = meta
                obj.save()
            return (created, obj)
        else:
            if obj is None:
                created = True
                try:
                    obj = self.model.create(**kwargs)
                except Exception as e:
                    print("Exception: {}".format(e))
                    
                meta = {self.toolname: {"created": str(datetime.datetime.now())}}
                obj.meta = meta
                obj.save()
            else:
                meta = obj.meta
                if meta:
                    if meta.get(self.toolname, False):
                        if meta[self.toolname].get("created", False):
                            created = False
                        else:
                            meta[self.toolname]["created"] = str(
                                datetime.datetime.now()
                            )
                            created = False
                    else:
                        meta[self.toolname] = {"created": str(datetime.datetime.now())}
                        created = False
                else:
                    meta = {self.toolname: {"created": str(datetime.datetime.now())}}
                    created = False

                    obj.meta = meta
                    obj.save()
            return (created, obj)

    def get_query(self):
        return self.db.db_session.query(self.model), self.model

    def all(self, tool=False, scope_type="", **kwargs):
        # obj = self.db.db_session.query(self.model).all()
        
        if scope_type == "passive":
            obj = (
                self.db.db_session.query(self.model)
                .filter_by(passive_scope=True, **kwargs)
                .all()
            )
        elif scope_type == "active":
            obj = (
                self.db.db_session.query(self.model)
                .filter_by(in_scope=True, **kwargs)
                .all()
            )
        else:
            obj = self.db.db_session.query(self.model).filter_by(**kwargs).all()
        if not tool:

            return obj

        else:
            objects = []
            for o in obj:
                if (
                    o.meta
                    and o.meta.get(tool, False)  # noqa: W503
                    and o.meta[tool].get("created", False)  # noqa: W503
                ):
                    pass
                else:
                    objects.append(o)
            # for o in objects:
            #     if not o.meta.get(tool, False):
            #         o.meta[tool] = {}

            #     o.meta[tool]["created"] = str(datetime.datetime.now())
            return objects
    

    def commit(self):
        return self.db.db_session.commit()


class DomainRepository(BaseRepository):
    model = Models.Domain

    def find_or_create(
        self, only_tool=False, in_scope=False, passive_scope=False, **kwargs
    ):

        created, d = super(DomainRepository, self).find_or_create(only_tool, **kwargs)
        display("Processing %s" % d.domain)

        if created:
            # If this is a new subdomain, set scoping info based on what is passed to the function initially.
            d.in_scope = in_scope
            d.passive_scope = passive_scope

            base_domain = ".".join([t for t in tldextract.extract(d.domain)[1:] if t])
            BaseDomains = BaseDomainRepository(self.db, "")
            # If the base domain is new, it'll inherit the same scoping permissions.

            created, bd = BaseDomains.find_or_create(
                only_tool,
                passive_scope=d.passive_scope,
                in_scope=in_scope,
                domain=base_domain,
            )
            if created:
                display_new(
                    "The base domain %s is being added to the database. Active Scope: %s Passive Scope: %s"
                    % (base_domain, bd.in_scope, bd.passive_scope)
                )
            else:
                # If the base domain already exists, then the subdomain inherits the scope info from the base domain.
                d.passive_scope = bd.passive_scope
                d.in_scope = bd.in_scope

            d.base_domain = bd

            # Get all IPs that this domain resolves to.
            
            #use utility....
            
            ips = get_ip(d.domain)

            if not ips:
                display_warning("No IPs discovered for %s" % d.domain)

            for i in ips:
                IPAddresses = IPRepository(self.db, "")
                if ':' not in i:
                    display("Processing IP address %s" % i)

                    created, ip = IPAddresses.find_or_create(
                        only_tool,
                        in_scope=d.in_scope,
                        passive_scope=d.passive_scope,
                        ip_address=i,
                    )

                    # If the IP is in scope, then the domain should be
                    if ip.in_scope:
                        d.in_scope = ip.in_scope
                        ip.passive_scope = True
                        d.passive_scope = True

                        # display("%s marked active scope due to IP being marked active." % d.domain)

                    elif ip.passive_scope:
                        d.passive_scope = ip.passive_scope

                    d.ip_addresses.append(ip)

                    display_new(
                        "%s is being added to the database. Active Scope: %s Passive Scope: %s"
                        % (d.domain, d.in_scope, d.passive_scope)
                    )

            # Final sanity check - if a domain is active scoped, it should also be passively scoped.
            if d.in_scope:
                d.passive_scope = True

        return created, d

class ScopeCIDRRepository(BaseRepository):
    model = Models.ScopeCIDR

    def find_or_create(
        self, only_tool=False, label=None, **kwargs
    ):
        
        created, scidr = super(ScopeCIDRRepository, self).find_or_create(only_tool, **kwargs)
        if created:
            CIDRs = CIDRRepository(self.db, "")

            if label:
                created, rcidr = CIDRs.find_or_create(ip_str=scidr.cidr.split('/')[0], label=label, force_cidr=scidr.cidr)
            else:
                created, rcidr = CIDRs.find_or_create(ip_str=scidr.cidr.split('/')[0])

        return created, scidr

class IPRepository(BaseRepository):
    model = Models.IPAddress

    def find_or_create(
        self, only_tool=False, in_scope=False, passive_scope=True, **kwargs
    ):


        created, ip = super(IPRepository, self).find_or_create(only_tool, **kwargs)
        if created:
            # If newly created then will determine scoping based on parent options and if in a scoped cidr.

            ip_str = ip.ip_address
            ip.passive_scope = passive_scope

            # If the parent domain is active scope, then this also is.
            if in_scope:
                ip.in_scope = in_scope

            else:
                # Go through ScopeCIDR table and see if this IP is in a CIDR in scope
                ScopeCidrs = ScopeCIDRRepository(self.db, "")
                addr = IPAddress(ip.ip_address)

                cidrs = ScopeCidrs.all()
                # pdb.set_trace()
                for c in cidrs:
                    if addr in IPNetwork(c.cidr):
                        ip.in_scope = True
            # Final sanity check - if an IP is active scoped, it should also be passive scoped.

            if ip.in_scope:
                ip.passive_scope = True
            ip.update()

            # Build CIDR info - mainly for reporting
            CIDR = CIDRRepository(self.db, "")

            created, cidr = CIDR.find_or_create(only_tool=True, ip_str=ip.ip_address)
        
            ip.cidr = cidr

            ip.update()

            display_new(
                "IP address %s added to database. Active Scope: %s Passive Scope: %s"
                % (ip.ip_address, ip.in_scope, ip.passive_scope)
            )

        return created, ip


class CIDRRepository(BaseRepository):
    model = Models.CIDR

    def find_or_create(
        self, ip_str, only_tool=False, in_scope=False, passive_scope=True, label=None, force_cidr=None, **kwargs
    ):
        res = False
        if label and force_cidr:
            res = ([force_cidr, label],)
        for cidr in private_subnets:

            if IPAddress(ip_str) in cidr:
                res = ([str(cidr), "Non-Public Subnet"],)
        
        
        for cidr in CIDRRepository(self.db, "").all():
            if IPAddress(ip_str) in IPNetwork(cidr.cidr):
                res = ([str(cidr.cidr), cidr.org_name],)
                display(
                    "Subnet already in database, not rechecking whois.")
    
        if res:
            cidr_data = res
        else:
            while True:
                try:
                    res = IPWhois(ip_str).lookup_whois(get_referral=True)
                except Exception:
                    try:
                        res = IPWhois(ip_str).lookup_whois()
                    except Exception as e:
                        display_error("Error trying to resolve whois: {}".format(e))
                        res = {}
                if "nets" in res.keys():
                    break
                else:
                    display_warning(
                        "The networks didn't populate from whois. Defaulting to a /24."
                    )
                    # again = raw_input("Would you like to try again? [Y/n]").lower()
                    # if again == 'y':
                    #     time.sleep(5)
                    # else:
                    res = {'nets': [{'cidr': '{}.0/24'.format('.'.join(ip_str.split('.')[:3])), 'description': 'Whois failed to resolve.'}]}
                    break

            cidr_data = []

            for n in res["nets"]:
                if "," in n["cidr"]:
                    for cidr_str in n["cidr"].split(", "):
                        cidr_data.append([cidr_str, n["description"]])
                else:
                    cidr_data.append([n["cidr"], n["description"]])

            cidr_data = [
                cidr_d
                for cidr_d in cidr_data
                if IPAddress(ip_str) in IPNetwork(cidr_d[0])
            ]
        if cidr_data:
            try:
                cidr_len = len(IPNetwork(cidr_data[0][0]))
            except Exception:
                pdb.set_trace()
            matching_cidr = cidr_data[0]
            for c in cidr_data:
                if len(IPNetwork(c[0])) < cidr_len:
                    matching_cidr = c

            
            display(
            "Processing CIDR from whois: %s - %s"
            % (str(matching_cidr[1]).split('\n')[0], matching_cidr[0])
            )
        
            created, cidr = super(CIDRRepository, self).find_or_create(only_tool, cidr=matching_cidr[0])

            if created:
                display_new("CIDR %s added to database" % cidr.cidr)
                cidr.org_name = str(matching_cidr[1]).split('\n')[0]
                cidr.update()

            return created, cidr

                
            

class BaseDomainRepository(BaseRepository):
    model = Models.BaseDomain

    def find_or_create(
        self, only_tool=False, passive_scope=True, in_scope=False, **kwargs
    ):

        created, bd = super(BaseDomainRepository, self).find_or_create(
            only_tool, **kwargs
        )
        if created:
            bd.in_scope = in_scope
            bd.passive_scope = passive_scope

            if bd.in_scope:
                bd.passive_scope = True
            bd.update()

        return created, bd


class UserRepository(BaseRepository):
    model = Models.User


class CredRepository(BaseRepository):
    model = Models.Cred


class VulnRepository(BaseRepository):
    model = Models.Vulnerability


class PortRepository(BaseRepository):
    model = Models.Port

    def find_or_create(
        self, only_tool=False, passive_scope=True, in_scope=False, **kwargs
    ):

        created, port = super(PortRepository, self).find_or_create(only_tool, **kwargs)
        if created:
            display_new(
                "Port {} added to database for IP {}".format(
                    port.port_number, port.ip_address.ip_address
                )
            )

        return created, port


class UrlRepository(BaseRepository):
    model = Models.Url


class CVERepository(BaseRepository):
    model = Models.CVE
