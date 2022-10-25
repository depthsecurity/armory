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
import uuid
import re


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

def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def index(request):

    return render(request, 'host_summary/index.html', {'title': 'Armory Web - Host Summary'})

@csrf_exempt
def get_hosts(request):

    scope_type = request.POST.get('scope', 'active')

    search = request.POST.get('search')

    page = int(request.POST.get('page', '0'))
    entries = int(request.POST.get('entries', '50'))
    # entries = 50

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
    # pdb.set_trace()
    ips, total = IPAddress.get_sorted(scope_type=scope_type, search=search, display_zero=display_zero, page_num=page, entries=entries)

    total_pages = int((total - 1) / entries) + 1

    

    page_data = {'prev': True if page > 1 else False,
                 'next': True if page < total_pages else False,
                 'pages_high': [i for i in range(page+1, page+6) if i <= total_pages],
                 'pages_low':  [i for i in range(page - 5, page) if i >= 1],
                 'current_page': page,
                 'last_page':total_pages,
                 'prev_page': page - 1 if page > 1 else 1,
                 'next_page': page + 1 if page < total_pages else total_pages,
                 }



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
                    if p.meta.get('nmap_scripts'):
                        data[p.id].append('Nmap')
                    if p.meta.get('Nikto'):
                        data[p.id].append('Nikto')
                    if gowitness and p.meta.get('Gowitness'):
                        
                        data[p.id].append('Gowitness')
                    if p.meta.get('Xsscrapy'):
                        data[p.id].append('Xsscrapy')
                    if p.meta.get('Xsstrike'):
                        data[p.id].append('Xsstrike')
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

    # pdb.set_trace()
    host_html = loader.get_template('host_summary/host_summary_data.html').render({'ips':good_ips, 'data':data, 'display_notes':display_notes, 'display_zero': display_zero, 'page_data':page_data})
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

def get_nmap(request, port_id):
    port_db = get_object_or_404(Port, pk=port_id)
    data = {}

    # nmap returns a lot of failed info that isn't really useful, so we are going to filter out what we can
    failed_strings = [
        "Couldn't find any comments.",
        "Couldn't find any CSRF vulnerabilities.",
        "Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.",
        "Couldn't find any DOM based XSS.",
        "ERROR: Script execution failed (use -d to debug)",
        "Couldn't find any feeds.",
        "Please enter the complete path of the directory to save data in.",
        "No mobile version detected.",
        "Couldn't find any cross-domain scripts.",
        "false",
        "Couldn't find any stored XSS vulnerabilities.",
        "No previously reported XSS vuln.",
        "No reply from server (TIMEOUT)",
        "Failed to specify credentials and command to run.",
        "FAILED: No domain specified (use ntdomain argument)",
        'Path "/" does not require authentication',
        "Couldn't find any error pages.",
          

        ]

    for d, v in port_db.meta['nmap_scripts'].items():
        if v and v.strip() not in failed_strings:
            data[d] = {'text': v, 'id': str(uuid.uuid1())}
            

    return render(request, 'host_summary/nmap.html', {'data':data})


def get_nessus(request, port_id):

    vuln_data = []
    vulns = Vulnerability.objects.filter(ports__id=port_id).order_by('severity')[::-1]

    vulns_obj = {}

    for v in vulns:
        vulns_obj[v.name] = {'id': v.id,
                             'severity': v.severity,
                             'description': v.description,}

        vuln_output = v.vulnoutput_set.filter(port_id=port_id)

        if vuln_output:
            vulns_obj[v.name]['detail'] = vuln_output[0].data
        else:
            vulns_obj[v.name]['detail'] = ""
    
    # pdb.set_trace()


    # for v in vulns:
    #     vuln_output_item = v.vulnoutput_set.filter(port__id=port_id)
    #     vo = "" if not vuln_output_item else vuln_output_item[0].data

    #     vuln_data.append( {"id": v.id, "name": v.name, "severity": v.severity, "description": v.description, "vulnoutput": vo })

    sev_map = {0: 'Informational', 1: 'Low', 2:'Medium', 3:'High', 4:'Critical'}

    return render(request, 'host_summary/nessus.html', {'vulns':vulns_obj, 'sev_map':sev_map})

def get_nessus_detail(request, vuln_id, port_id):
    pass

def get_gowitness(request, port_id):

    port = Port.objects.get(id=port_id)

    return render(request, 'host_summary/gowitness.html', {'port':port})

def get_nikto(request, port_id):

    port = get_object_or_404(Port, pk=port_id)
    data = {}
    for f, v in port.meta['Nikto'].items():
        text = ''
        for fl in v:
            if os.path.exists(fl):
                text += open(fl).read() + '\n'
        data[f] = {'text': text, 'id' : str(uuid.uuid1())}

    return render(request, 'host_summary/nikto.html', {'data':data})

def get_xsstrike(request, port_id):

    port = get_object_or_404(Port, pk=port_id)
    data = {}
    for f, v in port.meta['Xsstrike'].items():
        text = ''
        for fl in v:
            if os.path.exists(fl):
                text += escape_ansi(open(fl).read()) + '\n'
        data[f] = {'text': text}

    return render(request, 'host_summary/xsstrike.html', {'data':data})

def get_xsscrapy(request, port_id):

    port = get_object_or_404(Port, pk=port_id)
    data = {}
    for f, v in port.meta['Xsscrapy'].items():
        text = ''
        for fl in v:
            if os.path.exists(fl):
                text += open(fl).read() + '\n'
        data[f] = {'text': text, 'id' : str(uuid.uuid1())}

    return render(request, 'host_summary/xsscrapy.html', {'data':data})


def get_ffuf(request, port_id):

    max_status = 10
    port = Port.objects.get(id=port_id)

    ffuf_data = {}

    for f in port.meta['FFuF']:
        if os.path.exists(f):
            data = json.loads(open(f).read())
            
            for r in data['results']:
                url = data['config']['url']
                url_orig = r['url']
                r['host_url'] = '/'.join(url_orig.split('/')[:2] + [r['host']] + url_orig.split('/')[3:])
                
                if not ffuf_data.get(r['host']):
                    ffuf_data[r['host']] = {}
                if not ffuf_data[r['host']].get(url):
                    ffuf_data[r['host']][url] = {}

                if not ffuf_data[r['host']][url].get(r['status']):
                    ffuf_data[r['host']][url][r['status']] = []

                if len(ffuf_data[r['host']][url][r['status']]) < max_status and r not in ffuf_data[r['host']][url][r['status']]:
                    

                    if r.get('host') and r.get('host') not in r['url']:
                        r['url'] = get_virtualhost_url(r['url'], r['host'])
                    
                    ffuf_data[r['host']][url][r['status']].append(r)
                    
    # pdb.set_trace()            
    return render(request, 'host_summary/ffuf.html', {'ffuf_data':ffuf_data})

                

def get_cidr_ips(request):
    pass

def get_virtualhost_url(url, vhost):

    tail = '.oastify.com'
    delim = '.vhost-proxy.'
    host_raw = url.split('/')[2]
    host = host_raw.split(':')[0]

    if ':' in host_raw:
        port = f":{host_raw.split(':')[1]}"
    else:
        port = ""

    new_host = f"{host}{delim}{vhost}{delim}{tail}{port}"

    new_url = url.replace(host_raw, new_host)

    return new_url
    