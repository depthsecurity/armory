from django.shortcuts import render
from django.http import HttpResponse
from armory2.armory_main.models import *
from django.shortcuts import render
from django.template.defaulttags import register
import pdb
import os
from base64 import b64encode
import json

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

def get_ffuf(request, port_id):

    max_status = 10
    port = Port.objects.get(id=port_id)

    ffuf_data = {}

    for f in port.meta['FFuF']:
        if os.path.exists(f):
            data = json.loads(open(f).read())
            # pdb.set_trace()
            for r in data['results']:
                if not ffuf_data.get(r['host']):
                    ffuf_data[r['host']] = {}
                if not ffuf_data[r['host']].get(data['config']['url']):
                    ffuf_data[r['host']][data['config']['url']] = {}

                if not ffuf_data[r['host']][data['config']['url']].get(r['status']):
                    ffuf_data[r['host']][data['config']['url']][r['status']] = []

                if len(ffuf_data[r['host']][data['config']['url']][r['status']]) < max_status:
                    ffuf_data[r['host']][data['config']['url']][r['status']].append(r)
    # pdb.set_trace()
    return render(request, 'host_summary/ffuf.html', {'ffuf_data':ffuf_data})

                

def get_cidr_ips(request):
    pass
