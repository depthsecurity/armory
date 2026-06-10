from django.db import models
from picklefield.fields import PickledObjectField
from .base_model import BaseModel
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
import json
import pdb
from django.db.models.signals import pre_save, post_save
from django.db.models import Q
from django.dispatch import receiver
from armory2.armory_main.included.utilities.color_display import (
    display,
    display_warning,
    display_new,
    display_error,
)
from armory2.armory_main.included.utilities.network_tools import (
    validate_ip,
    get_ips,
    private_subnets,
)

from netaddr import IPNetwork, IPAddress as IPAddr, IPRange
# from ipwhois import IPWhois

import whoisit
from datetime import datetime, date, time

import tldextract
import re

_PTR_IP_RE = re.compile(r'^\d{1,3}[.\-]\d{1,3}[.\-]\d{1,3}[.\-]\d{1,3}\.')

class ToolRun(BaseModel):
    args = models.CharField(max_length=1024, default="")
    port = models.IntegerField(default=0)
    port_obj = models.ForeignKey(
        "Port", on_delete=models.CASCADE, blank=True, null=True
    )
    tool = models.CharField(max_length=128)
    virtualhost = models.ForeignKey(
        "VirtualHost", on_delete=models.CASCADE, blank=True, null=True
    )

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    object_id = models.PositiveIntegerField(null=True)
    content_object = GenericForeignKey()


class BaseDomain(BaseModel):
    name = models.CharField(max_length=64)
    dns = PickledObjectField(default=dict)
    toolrun = GenericRelation(ToolRun, related_query_name="base_domains")
    tags = models.ManyToManyField(
        'Tag', blank=True, limit_choices_to={'type__in': ['domain', 'any']}
    )

    def __str__(self):
        return self.name


class CIDR(BaseModel):
    name = models.CharField(max_length=44, unique=True)
    org_name = models.CharField(max_length=256, unique=False, null=True)
    size = models.IntegerField(default=256)
    cloud = models.BooleanField(default=False)
    toolrun = GenericRelation(ToolRun, related_query_name="cidrs")

    def __str__(self):
        return "{}: {}".format(self.name, self.org_name)

    @property
    def domain_count(self):
        # Total domains across every IP in this CIDR (matches the per-IP
        # "N Domains" counts summed together).
        from django.db.models import Count

        return self.ipaddress_set.aggregate(n=Count("domain"))["n"]

    def _scope_state(self, scope_attr):
        from django.db.models import Count, Q
        ips = self.ipaddress_set.all()
        if not ips.exists():
            return "none"
        total_ips = ips.count()
        scoped_ips = ips.filter(**{scope_attr: True}).count()
        domain_total = ips.aggregate(n=Count("domain"))["n"]
        domain_scoped = ips.aggregate(
            n=Count("domain", filter=Q(**{f"domain__{scope_attr}": True}))
        )["n"]
        total = total_ips + domain_total
        scoped = scoped_ips + domain_scoped
        if scoped == 0:
            return "none"
        if scoped == total:
            return "all"
        return "some"

    @property
    def active_scope_state(self):
        return self._scope_state("active_scope")

    @property
    def passive_scope_state(self):
        return self._scope_state("passive_scope")


class Domain(BaseModel):
    name = models.CharField(max_length=128, unique=True)
    ip_addresses = models.ManyToManyField("IPAddress")
    basedomain = models.ForeignKey(BaseDomain, on_delete=models.CASCADE)
    whois = models.TextField()
    toolrun = GenericRelation(ToolRun, related_query_name="domains")
    dynamic_ip = models.BooleanField(default=False)
    is_ptr = models.BooleanField(default=False)
    tags = models.ManyToManyField(
        'Tag', blank=True, limit_choices_to={'type__in': ['domain', 'any']}
    )

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.id:
            self.name = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', self.name)
            
            domain_name = "".join(
                [
                    i
                    for i in self.name.lower()
                    if i in "abcdefghijklmnopqrstuvwxyz.-0123456789"
                ]
            )
            if domain_name.count(".") < 1:
                domain_name = domain_name + ".badfqdn.local"

            if domain_name.count(".") > 1:
                base_domain = domain_name.partition(".")[2]
                if BaseDomain.objects.filter(name=base_domain).exists():
                    self.basedomain = BaseDomain.objects.get(name=base_domain)
                    
            try:
                bd = self.basedomain
            except BaseDomain.DoesNotExist:
                bd = None
            if not bd:        
                try:
                    # Disable PSL fetching by giving an empty suffix list
                    ext = tldextract.TLDExtract(suffix_list_urls=())
                    result = ext(domain_name)
                    base_domain = f"{result.domain}.{result.suffix}"
                except Exception as e:
                    # if tld fails try to extract the basedomain out of the hostname
                    if domain_name.count(".") == 1:
                        base_domain = domain_name
                    elif domain_name.count(".") == 2:
                        base_domain = domain_name.partition(".")[2]
                    elif domain_name.count(".") == 3:
                        base_domain = domain_name.partition(".")[2].partition(".")[2]
                    else:
                        base_domain = "local"


                bd, created = BaseDomain.objects.get_or_create(
                    name=base_domain,
                    defaults={
                        "active_scope": self.active_scope,
                        "passive_scope": self.passive_scope,
                    },
                )
                self.basedomain = bd

                if not created:
                    self.passive_scope = self.basedomain.passive_scope
                    self.active_scope = self.basedomain.active_scope

            if not Domain.objects.filter(name=self.name).exists():
                super().save(*args, **kwargs)
            else:
                return Domain.objects.get(name=self.name)
            display_new(
                "New domain added: {}  Active Scope: {}    Passive Scope: {}".format(
                    self.name, self.active_scope, self.passive_scope
                )
            )

            return self
        else:
            super().save(*args, **kwargs)

class IPAddress(BaseModel):
    ip_address = models.CharField(max_length=39, unique=True)
    cidr = models.ForeignKey(CIDR, on_delete=models.CASCADE)
    os = models.CharField(max_length=512)
    whois = models.TextField()
    version = models.IntegerField()
    notes = models.TextField(default="")
    completed = models.BooleanField(default=False, null=True)
    toolrun = GenericRelation(ToolRun, related_query_name="ip_addresses")
    tags = models.ManyToManyField(
        'Tag', blank=True, limit_choices_to={'type__in': ['ip', 'any']}
    )

    def __str__(self):
        return self.ip_address

    def add_tool_run(self, tool, args="", port=None, virtualhost=None):
        port_obj = None
        if port:
            port_objs = Port.objects.filter(
                ip_address=self, port_number=port, proto="tcp"
            )
            if port_objs.exists():
                port_obj = port_objs[0]
        if virtualhost:
            vhost, created = VirtualHost.objects.get_or_create(
                name=virtualhost, ip_address=self, port=port_obj
            )
        else:
            vhost = None
        self.toolrun.get_or_create(
            tool=tool, args=args, port_obj=port_obj, virtualhost=vhost
        )

    def _scope_state(self, scope_attr):
        domains = self.domain_set.all()
        if not domains.exists():
            return "all" if getattr(self, scope_attr) else "none"
        total = domains.count()
        scoped = domains.filter(**{scope_attr: True}).count()
        if scoped == 0:
            return "none"
        if scoped == total:
            return "all"
        return "some"

    @property
    def active_scope_state(self):
        return self._scope_state("active_scope")

    @property
    def passive_scope_state(self):
        return self._scope_state("passive_scope")

    def get_virtualhosts(self):
        return sorted(
            list(
                set(
                    [
                        vh.name
                        for vh in VirtualHost.objects.filter(
                            ip_address=self, active=True
                        )
                    ]
                )
            )
        )

    @classmethod
    def get_sorted(
        cls, scope_type=None, search=None, display_zero=False, page_num=1, entries=50
    ):
        if scope_type == "active":
            qry = cls.objects.filter(active_scope=True)
        elif scope_type == "passive":
            qry = cls.objects.filter(passive_scope=True)
        else:
            qry = cls.objects.all()

        if not display_zero:
            qry = qry.filter(port__port_number__gt=0).distinct()

        if search:
            qry = qry.filter(
                Q(ip_address__icontains=search) | Q(domain__name__icontains=search)
            )

        res = []
        total = qry.count()

        # pdb.set_trace()
        return (
            qry.order_by("ip_address")[(page_num - 1) * entries : page_num * entries],
            total,
        )


class VirtualHost(BaseModel):
    ip_address = models.ForeignKey(IPAddress, on_delete=models.CASCADE)
    name = models.CharField(max_length=256)
    port = models.ForeignKey("Port", on_delete=models.CASCADE, blank=True, null=True)
    active = models.BooleanField(default=True)
    domain = models.ForeignKey(
        Domain, on_delete=models.SET_NULL, blank=True, null=True, related_name="virtualhosts"
    )

    def __str__(self):
        return f"{self.ip_address}[{self.name}]"

    def save(self, *args, **kwargs):
        if not self.domain_id and self.name and not validate_ip(self.name):
            domain = Domain.objects.filter(name=self.name).first()
            if not domain:
                d = Domain(
                    name=self.name,
                    active_scope=self.active_scope,
                    passive_scope=self.passive_scope,
                    whois="",
                )
                d.save()
                domain = Domain.objects.filter(name=self.name).first()
            self.domain = domain
        super().save(*args, **kwargs)


class Port(BaseModel):
    port_number = models.IntegerField(unique=False)
    proto = models.CharField(max_length=32)
    status = models.CharField(max_length=32, default="open")
    service_name = models.CharField(max_length=256)
    ip_address = models.ForeignKey(IPAddress, on_delete=models.CASCADE)
    cert = models.TextField(unique=False, null=True)
    certs = PickledObjectField(default=dict)
    info = PickledObjectField(default=dict)
    toolrun = GenericRelation(ToolRun, related_query_name="ports")
    tags = models.ManyToManyField(
        'Tag', blank=True, limit_choices_to={'type__in': ['ip', 'any']}
    )

    def __str__(self):
        return "{} / {} / {}".format(self.proto, self.port_number, self.service_name)

    def get_active_virtualhosts(self):
        return self.virtualhost_set.filter(active=True).order_by("name")

    class Meta:
        ordering = ["port_number"]

    def save(self, *args, **kwargs):
        if not self.id:

            
            self.service_name = self.service_name.lower()
            if self.port_number in [5985, 5986, 47001]:
                self.service_name = "winrm"
            elif 'https' in self.service_name and self.service_name != 'https':
                self.service_name = 'https'
            elif 'http' in self.service_name and self.service_name != 'http' and self.service_name != 'https':
                self.service_name = 'http'
            
        super().save(*args, **kwargs)
# pre_save.connect(Domain.pre_save, sender=Domain)


@receiver(pre_save, sender=BaseDomain)
def pre_save_basedomain(sender, instance, *args, **kwargs):
    if not instance.id:
        display_new(
            "New base domain added: {}  Active Scope: {}    Passive Scope: {}".format(
                instance.name, instance.active_scope, instance.passive_scope
            )
        )


# @receiver(pre_save, sender=Domain)
# def pre_save_domain(sender, instance, *args, **kwargs):



@receiver(post_save, sender=Domain)
def post_save_domain(sender, instance, created, *args, **kwargs):
    if "offlinedns" in instance.meta:
        return
    if created:
        domain_name = instance.name
        if (domain_name.endswith('.in-addr.arpa') or domain_name.endswith('.ip6.arpa')
                or _PTR_IP_RE.match(domain_name)):
            if not instance.is_ptr:
                instance.is_ptr = True
                instance.save()
            return
        ips = get_ips(domain_name)

        for i in ips:
            ip, created = IPAddress.objects.get_or_create(ip_address=i)

            if ip.active_scope or instance.active_scope:
                instance.active_scope = True
                ip.active_scope = True

            if instance.passive_scope or ip.passive_scope:
                instance.passive_scope = True
                ip.passive_scope = True

            for p in ip.port_set.all():
                vh, created = VirtualHost.objects.get_or_create(
                    ip_address=ip, port=p, name=domain_name
                )
            display_new(
                "IP and Domain {}/{} scope updated to:  Active Scope: {}     Passive Scope: {}".format(
                    i, domain_name, ip.active_scope, ip.passive_scope
                )
            )

            ip.save()
            vh, created = VirtualHost.objects.get_or_create(
                ip_address=ip, port=None, name=instance.name
            )
            if created:
                display_new(
                    f"Added {instance.name} to virtualhosts for {ip.ip_address}"
                )
            instance.ip_addresses.add(ip)
            for p in ip.port_set.filter(service_name__icontains="http"):
                vh, created = VirtualHost.objects.get_or_create(
                    ip_address=ip, port=p, name=instance.name
                )
                if created:
                    display_new(
                        f"Added {instance.name} to virtualhosts for {ip.ip_address}:{p.port_number}"
                    )
            instance.save()


@receiver(pre_save, sender=IPAddress)
def pre_save_ip(sender, instance, *args, **kwargs):
    if not instance.id:
        res = validate_ip(instance.ip_address)
        if res == "ipv4":
            instance.version = 4
        elif res == "ipv6":
            instance.version = 6
        else:
            raise Exception("Not a valid IPv4 or IPv6 address.")

        # addr = IPAddress(instance.ip_address)

        cidrs = CIDR.objects.all().order_by("size")

        for c in cidrs:
            if instance.ip_address in IPNetwork(c.name):
                instance.active_scope = c.active_scope
                instance.passive_scope = c.passive_scope
                instance.cidr = c
                break

        try:
            cidr = instance.cidr
        except CIDR.DoesNotExist:
            cidr_name, org_name, cidr_data = get_cidr_info(instance.ip_address)

            # org_name = cidr_data["entities"][0]["handle"]
            
            size = IPNetwork(cidr_name).size

            cidr, created = CIDR.objects.get_or_create(
                name=cidr_name, defaults={"org_name": org_name, "size": size}
            )
            instance.cidr = cidr
            cidr.meta['rdap'] = cidr_data
            try:
                json.dumps(cidr_data)
            except Exception as e:
                pdb.set_trace()
            cidr.save()
        display_new(
            "New IP added: {}  Active Scope: {}    Passive Scope: {}".format(
                instance.ip_address, instance.active_scope, instance.passive_scope
            )
        )


@receiver(post_save, sender=Port)
def post_save_port(sender, instance, created, *args, **kwargs):
    if created:
        for vhost in instance.ip_address.virtualhost_set.all():
            vh, created = VirtualHost.objects.get_or_create(
                ip_address=instance.ip_address, port=instance, name=vhost.name
            )


@receiver(pre_save, sender=CIDR)
def pre_save_cidr(sender, instance, *args, **kwargs):
    if not instance.id and not instance.org_name:
        cidr_name, org_name,cidr_data = get_cidr_info(instance.name.split("/")[0])
        
        instance.org_name = org_name
        instance.size = IPNetwork(cidr_name).size

    if not instance.id:
        display_new(
            "New CIDR added: {} - {} Active Scope: {}    Passive Scope: {}".format(
                instance.name,
                instance.org_name,
                instance.active_scope,
                instance.passive_scope,
            )
        )


def get_cidr_info(ip_address):
    for p in private_subnets:
        if ip_address in p:
            return str(p), 'Non-Public Subnet',{}
    
    try:
        whoisit.bootstrap()

        res = whoisit.ip(ip_address)
        # res = whodap.lookup_ipv4(ip_address)
        cidr = str(res['network'])

        if len(res['description']) > 0:
            org_name = res['description'][0]
        else:
            org_name = res['entities']['registrant'][0]['name']

        res['network'] = cidr

        
        return (
            cidr, org_name, convert_datetime_to_string(res)
        )

    except Exception as e:
        display_error("Error trying to resolve whois: {}".format(e))
        res = {}
        return str(p), "Not resolved", {}
    

def convert_datetime_to_string(data: dict) -> dict:
    """
    Recursively traverse a dictionary/list structure and convert any datetime objects to strings.
    
    Args:
        data: The data structure to process (dict, list, or any other type)
        
    Returns:
        The same data structure with datetime objects converted to ISO format strings
    """
    if isinstance(data, dict):
        return {key: convert_datetime_to_string(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_datetime_to_string(item) for item in data]
    elif isinstance(data, (datetime, date, time)):
        # Convert datetime objects to ISO format strings
        if isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, date):
            return data.isoformat()
        elif isinstance(data, time):
            return data.isoformat()
    else:
        # Return other types unchanged
        return data