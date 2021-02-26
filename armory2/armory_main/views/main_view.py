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
            "display": "%d domains",
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

    # Going to repeat the logic in urls.py to get a dynamic list of webapps to display.
    
    webapps = {}

    app_paths = glob.glob(f"{'/'.join(os.path.realpath(__file__).split('/')[:-2])}/included/webapps/*/config.json")

    if settings.ARMORY_CONFIG['ARMORY_CUSTOM_WEBAPPS']:
        for path in settings.ARMORY_CONFIG['ARMORY_CUSTOM_WEBAPPS']:
            for webapp in glob.glob(f"{'/'.join(os.path.realpath(path).split('/'))}/*/config.json"):
                app_paths.append(webapp)

    for app_config in app_paths:
        with open(app_config, 'r') as f:
                app_config = json.load(f)
                apps_key = app_config['name'] if app_config['name'] else module_config_path.split("/")[-2]
                webapps[apps_key] = app_config

    # pdb.set_trace()

    webapps_grouped = {}

    for a in webapps:
        a_category = webapps[a]['category']
        if a_category in webapps_grouped:
            webapps_grouped[a_category]["apps"].append(webapps[a])
        else:
            webapps_grouped[a_category] = {
                "apps":[webapps[a]]
            }

    for category in webapps_grouped:
        stats = get_obj_stats(category)
        if not stats:
            stats = { 
                "total":{
                    "display": "%d total",
                    "data": len(webapps_grouped[category]["apps"])
                } 
            }
        webapps_grouped[category]["stats"] = stats
            
    return render(request, 'armory_main/index.html', {'apps': webapps_grouped})

