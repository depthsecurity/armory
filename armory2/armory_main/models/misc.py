from .base_model import BaseModel
from .network import IPAddress, Domain
from django.db import models

class ToolRun(BaseModel):

    ip_address = models.ForeignKey(IPAddress, on_delete=models.CASCADE, blank=True, null=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, blank=True, null=True)
    args = models.CharField(max_length=1024, default="")
    tool = models.CharField(max_length=128)
    virtualhost = models.CharField(max_length=128, default="")

    