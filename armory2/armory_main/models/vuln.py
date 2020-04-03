from django.db import models
from picklefield.fields import PickledObjectField
from .base_model import BaseModel

from .network import Port

class CVE(BaseModel):
    name = models.CharField(max_length=128)
    
    temporal_score = models.FloatField()
    description = models.TextField()



class Vulnerability(BaseModel):
    name = models.CharField(max_length=256, unique=True)
    ports = models.ManyToManyField(Port)
    description = models.TextField()
    remediation = models.TextField()
    severity = models.IntegerField()
    exploitable = models.BooleanField(default=False)
    exploit_reference = PickledObjectField(default=dict)
    cves = models.ManyToManyField(CVE)