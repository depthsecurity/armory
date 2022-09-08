#!/usr/bin/env python

from django.db import models
from picklefield.fields import PickledObjectField


class BaseModel(models.Model):

    meta = PickledObjectField(default=dict)
    tools = PickledObjectField(default=dict)
    active_scope = models.BooleanField(default=False)
    passive_scope = models.BooleanField(default=False)
    source_tool = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    def set_source_tool(self, tool):
        self.source_tool = tool
        self.save()

    def add_tool_run(self, tool, args=""):

        self.toolrun.get_or_create(tool=tool, args=args)

    @classmethod
    def get_set(cls, tool=None, args="", scope_type=None):
        qry = cls.objects.all()
        if scope_type == "active":
            qry = qry.filter(active_scope=True)
        elif scope_type == "passive":
            qry = qry.filter(passive_scope=True)

        if tool:
            qry = qry.exclude(toolrun__tool=tool, toolrun__args=args)

        return qry

    class Meta:
        abstract = True
