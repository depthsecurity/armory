from django.shortcuts import render
from django.http import HttpResponse
from armory2.armory_main.models import *
from django.shortcuts import render, get_object_or_404
from django.template.defaulttags import register
from django.template import loader
from django.views.decorators.csrf import csrf_exempt
import pdb
import os
from base64 import b64encode
import json

# from armory2.

# register.filter
# def clean_whois(dictionary, key):
#     return dictionary.get(key)

def index(request):

    cidrs = CIDR.objects.all().order_by('name')

    return render(request, 'host_scoping/index.html', {'cidrs': cidrs})

def change_scope(request, item_type, scope_type, pkid):

    if item_type == 'cidr':
        obj = get_object_or_404(CIDR, pk=pkid)
    elif item_type == 'ip':
        obj = get_object_or_404(IPAddress, pk=pkid)
    elif item_type == 'domain':
        obj = get_object_or_404(Domain, pk=pkid)

    if scope_type == 'active':
        if obj.active_scope:
            obj.active_scope = False
        else:
            obj.active_scope = True

        obj.save()
        return HttpResponse("Success")
    elif scope_type == 'passive':
        if obj.passive_scope:
            obj.passive_scope = False
        else:
            obj.passive_scope = True

        obj.save()
        return HttpResponse("Success")

    return HttpResponse("Nooope")

def clear_scope(request, act, item_type, scope_type, pkid):

    if item_type == 'cidr':
        obj = get_object_or_404(CIDR, pk=pkid)
    
        if act == 'set':
            setting = True

        else:
            setting = False
        if scope_type == 'active':

            obj.active_scope = setting

            obj.save()
            for i in obj.ipaddress_set.all():
                i.active_scope = setting

                i.save()

                for dom in i.domain_set.all():
                    dom.active_scope = setting
                    dom.save()
        else:
            obj.passive_scope = setting

            obj.save()
            for i in obj.ipaddress_set.all():
                i.passive_scope = setting

                i.save()

                for dom in i.domain_set.all():
                    dom.passive_scope = setting
                    dom.save()
        return render(request, 'host_scoping/cidr.html', {'cidr':obj})

    elif item_type == 'ip':
        obj = get_object_or_404(IPAddress, pk=pkid)
    
        
        if act == 'set':
            setting = True

        else:
            setting = False

        if scope_type == 'active':
            obj.active_scope = setting

            obj.save()
            
            for dom in obj.domain_set.all():
                dom.active_scope = setting
                dom.save()
        else:
            obj.passive_scope = setting

            obj.save()
            
            for dom in obj.domain_set.all():
                dom.passive_scope = setting
                dom.save()

        return render(request, 'host_scoping/ip.html', {'ip':obj})


def get_ips(request, pkid):
    obj = get_object_or_404(CIDR, pk=pkid)

    ips = obj.ipaddress_set.all().order_by('ip_address')

    return render(request, 'host_scoping/ips.html', {'ips': ips})


def get_domains(request, pkid):
    obj = get_object_or_404(IPAddress, pk=pkid)

    domains = obj.domain_set.all().order_by('name')

    return render(request, 'host_scoping/domains.html', {'domains': domains})