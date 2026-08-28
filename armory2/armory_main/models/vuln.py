from django.db import models
from picklefield.fields import PickledObjectField
from .base_model import BaseModel
from .network import Port

class CVE(BaseModel):
    name = models.CharField(max_length=128)
    
    temporal_score = models.FloatField(default=0.0)
    description = models.TextField()
    updated = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class Vulnerability(BaseModel):
    name = models.CharField(max_length=256, unique=True)
    ports = models.ManyToManyField(Port)
    description = models.TextField()
    remediation = models.TextField()
    severity = models.IntegerField()
    exploitable = models.BooleanField(default=False)
    exploit_reference = PickledObjectField(default=dict)
    cves = models.ManyToManyField(CVE)
    source = models.CharField(max_length=16, default="nessus")

    def __str__(self):
        return self.name

class VulnOutput(BaseModel):
    port = models.ForeignKey(Port, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    data = models.TextField()    


class Url(BaseModel):
    name = models.CharField(max_length=256, unique=False)
    method = models.CharField(max_length=32, unique=False, default="get")
    port = models.ForeignKey(Port, on_delete=models.CASCADE, related_name="urls")

    # Optional link to the finding output this URL is evidence for. Many urls
    # to one VulnOutput; clearing the output row leaves the urls in place, since
    # a discovered URL is attack surface in its own right.
    vuln_output = models.ForeignKey(
        VulnOutput,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="urls",
    )

    def __str__(self):
        return self.name


