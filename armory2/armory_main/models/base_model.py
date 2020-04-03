#!/usr/bin/env python

from django.db import models
from picklefield.fields import PickledObjectField


class BaseModel(models.Model):

    meta = PickledObjectField(default=dict)
    active_scope = models.BooleanField(default=False)
    passive_scope = models.BooleanField(default=False)
    source_tool = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    def set_tool(self, tool):
        self.source_tool = tool
        self.save()
        

    class Meta:
        abstract=True

