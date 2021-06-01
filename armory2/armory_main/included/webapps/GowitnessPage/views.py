from django.shortcuts import render
from django.http import HttpResponse
from armory2.armory_main.models import *
from django.shortcuts import render, get_object_or_404
from django.template.defaulttags import register
from django.template import loader
from django.views.decorators.csrf import csrf_exempt
from pathlib import Path
from base64 import b64encode
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
#from armory2.armory_main.included.utilities import get_urls

# from armory2.

def index(request):

    data = {} #holds all of the port data and gowitness flag. this is a dictionary of lists
    ips = IPAddress.objects.all()
    good_ips = [] #weeds out port zeros and such
    #using code from get_sorted...
    port_ids = []
    domains = Domain.objects.all()
    #for x in domains:
    for ip in ips:
        for p in ip.port_set.all():
            if p.port_number > 0:
                if ip not in good_ips:
                    good_ips.append(ip)
                if p.meta.get('Gowitness'):
                    data[p.id] = []
                    #data[p.id].append('Gowitness')
                    #data[p.id].append(p.service_name + '://' + str(ip.ip_address) + ':' + str(p.port_number))
                    for gw in p.meta['Gowitness']:
                        data[p.id].append(get_file_data(gw['screenshot_file']))
                    port_ids.append(p.id)
                    #now we need to get domains to make the hrefs later on
                    if ip.domain_set.all().exists():
                        #print("made it!")
                        for domain in ip.domain_set.all():
                            data[p.id].append(p.service_name + "://" + domain.name + ":" + str(p.port_number))
                    else:
                        data[p.id].append(p.service_name + '://' + str(ip.ip_address) + ':' + str(p.port_number))

    #trying pagination stuffs
    #data_list = range(1,1000)

    
    data_t = tuple(data.items())
    #print(data_t)
    paginator = Paginator(data_t, 20)
    page = request.GET.get('page', 1)

    #print(page)
    #print(data_t)
    try:
        data2 = paginator.get_page(page)
    except PageNotAnInteger:
        data2 = paginator.get_page(1)
    except EmptyPage:
        data2 = paginator.get_page(paginator.num_pages)
    return render(request, 'gowitnessPage/index.html', {'data': data2})   #, 'port_ids':port_ids})

def get_ips(request, pkid):
    obj = get_object_or_404(CIDR, pk=pkid)

    ips = obj.ipaddress_set.all().order_by('ip_address')

    return render(request, 'host_scoping/ips.html', {'ips': ips})

def get_file_data(file_name):
    try:
        return "data:image/png;base64," + b64encode(open(file_name, 'rb').read()).decode()
    except:
        print("Image File Not Found!")
        return None 


#This alows dictionary lookups within the template
@register.filter
def get_item(dictionary, key):
    #print(dictionary.get(key))
    return dictionary.get(key)

def get_gowitness2(request, port_id):
    port = Port.objects.get(id=port_id)
    print('hello!')
    return render(request, 'gowitnessPage/gowitness.html', {'port':port})