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

def index(request):
    # Get filter parameter from URL
    status_filter = request.GET.get('status', 'all')

    # Use select_related and prefetch_related to reduce queries
    ports = Port.objects.filter(
        port_number__gt=0
    ).select_related('ip_address').prefetch_related('ip_address__domain_set')

    # Build data dictionary and collect all unique status codes
    data = {}
    all_status_codes = set()

    for port in ports:
        # Skip ports without Gowitness data
        if not port.meta.get('Gowitness'):
            continue

        # Get the response code from the first Gowitness entry
        response_code = port.meta['Gowitness'][0].get('response_code_string', 'Unknown')
        all_status_codes.add(response_code)

        # Apply filter if not 'all'
        if status_filter != 'all' and response_code != status_filter:
            continue

        ip = port.ip_address
        data[port.id] = []

        # Add response code as first item
        data[port.id].append(response_code)

        # Add screenshot paths
        for gw in port.meta['Gowitness']:
            data[port.id].append(gw['screenshot_file'].split("/output")[1])

        # Add domain or IP URL
        domains = list(ip.domain_set.all())
        if domains:
            for domain in domains:
                data[port.id].append(f"{port.service_name}://{domain.name}:{port.port_number}")
        else:
            data[port.id].append(f"{port.service_name}://{ip.ip_address}:{port.port_number}")

    # Paginate
    data_items = list(data.items())
    paginator = Paginator(data_items, 20)
    page = request.GET.get('page', 1)

    try:
        data_page = paginator.get_page(page)
    except (PageNotAnInteger, EmptyPage):
        data_page = paginator.get_page(1)

    return render(request, 'GowitnessPage/index.html', {
        'data': data_page,
        'status_codes': sorted(all_status_codes),
        'current_filter': status_filter
    })

def get_ips(request, pkid):
    obj = get_object_or_404(CIDR, pk=pkid)

    ips = obj.ipaddress_set.all().order_by('ip_address')

    return render(request, 'host_scoping/ips.html', {'ips': ips})

def get_file_data(file_name):
    return "data:image/png;base64," + b64encode(open(file_name, 'rb').read()).decode()

#This alows dictionary lookups within the template
@register.filter
def get_item(dictionary, key):
    #print(dictionary.get(key))
    return dictionary.get(key)

def get_test(request, port_id):
    port = Port.objects.get(id=port_id)
    print('hello!')
    return render(request, 'test_app/test.html', {'port':port})
