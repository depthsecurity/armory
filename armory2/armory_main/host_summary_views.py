from django.shortcuts import render
from django.http import HttpResponse
from armory2.armory_main.models import *
from django.shortcuts import render
from django.template.defaulttags import register
import pdb
import os
from base64 import b64encode

# from armory2.

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@register.filter
def file_exists(file_name):
    return os.path.exists(file_name)

@register.filter
def get_file_data(file_name):
    return "data:image/png;base64," + b64encode(open(file_name, 'rb').read()).decode()

def index(request):

    ips_object = {}
    ips = IPAddress.get_sorted()

    data = {}

    for ip in ips:
        for p in ip.port_set.all():
            data[p.id] = []

            if len(p.vulnerability_set.all()) > 0:
                data[p.id].append("Nessus")

            # Look for FFuF and Gowitness - these should be done by the tools themselves and have the data stored in meta

            if p.meta.get('Gowitness'):
                data[p.id].append('Gowitness')

            if p.meta.get('FFuF'):
                data[p.id].append('FFuF')



    return render(request, 'armory_main/index.html', {'ips':ips, 'data':data})


def get_nessus(request, port_id):

    vulns = Vulnerability.objects.filter(ports__id=port_id).order_by('severity')[::-1]
    sev_map = {0: 'Informational', 1: 'Low', 2:'Medium', 3:'High', 4:'Critical'}

    return render(request, 'host_summary/nessus.html', {'vulns':vulns, 'sev_map':sev_map})

def get_nessus_detail(request, vuln_id):
    pass

def get_gowitness(request, port_id):

    port = Port.objects.get(id=port_id)

    return render(request, 'host_summary/gowitness.html', {'port':port})


def get_cidr_ips(request):
    pass
