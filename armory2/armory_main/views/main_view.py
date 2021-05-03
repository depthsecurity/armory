from armory2.armory_main.models import *
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.conf import settings
from django.template.defaulttags import register
from django.apps import apps
import pdb
import os
import glob
import json

# from armory2.

# register.filter
# def clean_whois(dictionary, key):
#     return dictionary.get(key)

@register.filter
def get_context_idx(i):
    contexts = [
        "primary",
        "info",
        "dark",
        "secondary",
        "success",
        "warning",
        "danger"
    ]
    return contexts[i] if i < len(contexts) else contexts[0]

@register.filter
def title_item(s):
    return s.title().replace('_', ' ')

@register.filter
def format_string(f, d):
    return f % d

@register.filter
def get_value_by_key(key, dictionary):
    if key in dictionary.keys():
        return dictionary[key]
    return None

@register.filter
def get_page_path(path):
    return path.replace('/', '')

@register.simple_tag
def append_str_if_equal(s1, s2, source_str, append_str, delimeter=" "):
    if s1 == s2:
        return "%s%s%s" % (source_str, delimeter, append_str)
    else:
        return source_str

@register.simple_tag(takes_context=True)
def get_page_path(context):
    return context.request.path.replace('/', '')

def get_obj_stats(obj_name):
    stats = {}
    if obj_name == "Domains":
        stats['total'] = {
            "display": "%d domains",
            "data": Domain.objects.count()
        }
        stats['active'] = {
            "display": "%d active",
            "data": Domain.objects.filter(active_scope=True).count()
        }
        stats['passive'] = {
            "display": "%d passive",
            "data": Domain.objects.filter(passive_scope=True).count()
        }
    elif obj_name == "Hosts":
        stats['total'] = {
            "display": "%d hosts",
            "data": IPAddress.objects.count()
        }
        stats['active'] = {
            "display": "%d active",
            "data": IPAddress.objects.filter(active_scope=True).count()
        }
        stats['passive'] = {
            "display": "%d passive",
            "data": IPAddress.objects.filter(passive_scope=True).count()
        }
    elif obj_name == "User":
        stats['total'] = {
            "display": "%d domains",
            "data": User.objects.count()
        }
    else:
        return None    
    return stats


def index(request):
    webapps_stats = {}
    webapps_grouped = apps.app_configs['armory_main'].webapps_grouped

    for category in webapps_grouped:
        stats = get_obj_stats(category)
        if not stats:
            stats = { 
                "total":{
                    "display": "%d total",
                    "data": len(webapps_grouped[category])
                } 
            }
        webapps_stats[category] = stats
            
    return render(request, 'armory_main/index.html', {'webapp_stats': webapps_stats, 'title': 'Armory Web - Dashboard', 'hide_nav':""})

