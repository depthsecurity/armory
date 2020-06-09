from django.db import models
from picklefield.fields import PickledObjectField
from .base_model import BaseModel
from .network import Port

class CVE(BaseModel):
    name = models.CharField(max_length=128)
    
    temporal_score = models.FloatField(default=0.0)
    description = models.TextField()
    updated = models.BooleanField(default=True)



class Vulnerability(BaseModel):
    name = models.CharField(max_length=256, unique=True)
    ports = models.ManyToManyField(Port)
    description = models.TextField()
    remediation = models.TextField()
    severity = models.IntegerField()
    exploitable = models.BooleanField(default=False)
    exploit_reference = PickledObjectField(default=dict)
    cves = models.ManyToManyField(CVE)


class URL(BaseModel):
    name = models.CharField(max_length=256, unique=True)
    port = models.ForeignKey(Port, on_delete=models.CASCADE)