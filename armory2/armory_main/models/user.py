from django.db import models
from picklefield.fields import PickledObjectField
from .base_model import BaseModel

from .network import BaseDomain

class User(BaseModel):
    email = models.CharField(max_length=128, unique=True)
    first_name = models.CharField(max_length=128)
    last_name = models.CharField(max_length=128)
    user_name = models.CharField(max_length=128)
    domain = models.ForeignKey(BaseDomain, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=256)
    location = models.CharField(max_length=128)



class Cred(BaseModel):
    password = models.CharField(max_length=64, null=True)
    passhash = models.CharField(max_length=128, null=True)
    source = models.CharField(max_length=128)
    user = models.ForeignKey(User, on_delete=models.CASCADE)