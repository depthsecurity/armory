from django.db import models
from picklefield.fields import PickledObjectField
from .base_model import BaseModel


class BaseDomain(BaseModel):
    name = models.CharField(max_length=64)
    dns = PickledObjectField(default=dict)

class CIDR(BaseModel):

    name = models.CharField(max_length=19, unique=True)
    org_name = models.CharField(max_length=256)

class Domain(BaseModel):
    name = models.CharField(max_length=128, unique=True)
    ip_addresses = models.ManyToManyField('IPAddress')
    basedomain = models.ForeignKey(BaseDomain, on_delete=models.CASCADE)
    whois = models.TextField()

class IPAddress(BaseModel):
    ip_address = models.CharField(max_length=15, unique=True)
    cidr = models.ForeignKey(CIDR, on_delete=models.CASCADE)
    os = models.CharField(max_length=512)
    whois = models.TextField()
    
class Port(BaseModel):

    port_number = models.IntegerField(unique=False)
    proto = models.CharField(max_length=32)
    status = models.CharField(max_length=32, default="open")
    service_name = models.CharField(max_length=256)
    ip_address = models.ForeignKey(IPAddress, on_delete=models.CASCADE)
    
    certs = models.TextField()
    info = PickledObjectField(default=dict)