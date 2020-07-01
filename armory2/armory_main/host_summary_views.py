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

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@register.filter
def file_exists(file_name):
    return os.path.exists(file_name)

@register.filter
def get_file_data(file_name):
    return "data:image/png;base64," + b64encode(open(file_name, 'rb').read()).decode()

@register.filter
def unique_ffuf(l):
    res = []

    endpoints = []

    for item in l:
        endpoint = item['input']['FUZZ']

        if endpoint not in endpoints:
            res.append(item)
            endpoints.append(endpoint)

    return res

def index(request):

    return render(request, 'host_summary/index.html', {})

def get_hosts(request):

    scope_type = request.POST.get('scope', 'active')

    search = request.POST.get('search')

    if request.POST.get('display_notes'):
        display_notes = "collapse show"
    else:
        display_notes = "collapse"


    ffuf = False
    gowitness = False
    nessus = False

    if request.POST.get('display_all'):
        ffuf = True
        gowitness = True
        nessus = True

    else:
        if request.POST.get('display_ffuf'):
            ffuf = True
        if request.POST.get('display_gowitness'):
            gowitness = True
        if request.POST.get('display_nessus'):
            nessus = True

    display_zero = request.POST.get('display_zero')

    display_complete = request.POST.get('display_completed')

    ips_object = {}
    ips = IPAddress.get_sorted(scope_type=scope_type, search=search)

    data = {}
    good_ips = []
    for ip in ips:
        if display_complete or not ip.completed:

            for p in ip.port_set.all():
                if p.port_number > 0 or display_zero:
                    if ip not in good_ips:
                        good_ips.append(ip)
                    data[p.id] = []

                    if nessus and len(p.vulnerability_set.all()) > 0:
                        highest_severity = 0

                        for v in p.vulnerability_set.all():
                            if v.severity > highest_severity:
                                highest_severity = v.severity

                        

                        data[p.id].append("Nessus{}".format(highest_severity))


                    # Look for FFuF and Gowitness - these should be done by the tools themselves and have the data stored in meta

                    if gowitness and p.meta.get('Gowitness'):
                        data[p.id].append('Gowitness')

                    if ffuf and p.meta.get('FFuF'):
                        ffuf_good = False

                        for f in p.meta.get('FFuF'):
                            if os.path.exists(f):
                                res = json.load(open(f))
                                if len(res['results']) > 0:
                                    ffuf_good = True

                        if ffuf_good:
                            data[p.id].append('FFuF')
                        else:
                            if 'FFuF-empty' not in data[p.id]:
                                data[p.id].append('FFuF-empty')


    host_html = loader.get_template('host_summary/host_summary_data.html').render({'ips':good_ips, 'data':data, 'display_notes':display_notes, 'display_zero': display_zero})
    sidebar_html = loader.get_template('host_summary/sidebar.html').render({'ips':good_ips})

    return HttpResponse(json.dumps({'hostdata':host_html, 'sidebardata': sidebar_html}))


def toggle_completed(request, ip_id):

    
    ip = get_object_or_404(IPAddress, pk=ip_id)
    if ip.completed:
        ip.completed = False
    else:
        ip.completed = True

    ip.save()

    return HttpResponse("IP address completed: {}".format(ip.completed))


@csrf_exempt
def save_notes(request, ip_id):

    data = request.POST['data']
    ip = get_object_or_404(IPAddress, pk=ip_id)
    ip.notes = data
    ip.save()

    return HttpResponse("Success")
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

                if len(ffuf_data[r['host']][data['config']['url']][r['status']]) < max_status and r not in ffuf_data[r['host']][data['config']['url']][r['status']]:
                    ffuf_data[r['host']][data['config']['url']][r['status']].append(r)
                    # pdb.set_trace()
    return render(request, 'host_summary/ffuf.html', {'ffuf_data':ffuf_data})

                

def get_cidr_ips(request):
    pass
