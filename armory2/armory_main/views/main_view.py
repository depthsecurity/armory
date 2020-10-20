from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from django.template.defaulttags import register
import pdb
import os
import glob

# from armory2.

# register.filter
# def clean_whois(dictionary, key):
#     return dictionary.get(key)

@register.filter
def title_item(s):
    return s.title().replace('_', ' ')


def index(request):

    # Going to repeat the logic in urls.py to get a dynamic list of webapps to display.
    
    apps = []

    for module_path in glob.glob(f"{'/'.join(os.path.realpath(__file__).split('/')[:-2])}/included/webapps/*/"):
        module_name = module_path.split("/")[-2]
        apps.append(module_name)    
    if settings.ARMORY_CONFIG.get('ARMORY_CUSTOM_WEBAPPS'):
        for module_template in settings.ARMORY_CONFIG['ARMORY_CUSTOM_WEBAPPS']:
            for module_path in glob.glob(f"{module_template}/*/"):
                module_name = module_path.split("/")[-2]
                apps.append(module_name)        
    apps.sort()

    # pdb.set_trace()

    return render(request, 'armory_main/index.html', {'apps': apps})

