#!/usr/bin/python
# -*- coding: utf-8 -*-

from armory.included.ReportTemplate import ReportTemplate
from armory.database.repositories import IPRepository
import pdb
import json
from fuzzywuzzy import process
import datetime
import glob
import xmltodict
import os
from jinja2 import Template
from base64 import b64encode
import shutil

sev_map = {0: 'Informational', 1: 'Low', 2:'Medium', 3:'High', 4:'Critical'}

class Report(ReportTemplate):
    '''
    This report displays the various HTTP header findings we have
    '''

    name = "HostSummary"

    markdown = ['', '-', '--']

    def __init__(self, db):
        
        self.db = db
        self.IPAddress = IPRepository(db, self.name)


    def set_options(self):
        
        super(Report, self).set_options()
        
        self.options.add_argument('--output_html', help="Output HTML file", default="output.html")
        self.options.add_argument('-g', '--include_gowitness', help="Include Gowitness data and screenshots", action="store_true")
        self.options.add_argument('-f', '--include_ffuf', help="Include FFuF results", action="store_true")
    def run(self, args):
        
        ip_port_result_data = {}

        ip_data = {}

        gowitness_data = {}
        gowitness_databases = []

        ffuf_data = {}

        if args.include_ffuf:
            path = os.path.join(self.base_config["PROJECT"]["base_path"],'output', 'FFuF')
            for (dirpath, dirnames, filenames) in os.walk(path):
                
                for f in filenames:
                    # pdb.set_trace()
                    if f[:4] == 'http' and f.count('_') == 4:
                        proto, _, _, domain, dirty_port = f.split('_')
                        port = dirty_port.split('-')[0]

                        data = json.loads(open(os.path.join(dirpath, f)).read())
                        url = "{}:{}".format(domain, port)
                        
                        attack = data['commandline'].split(' -u ')[1].split(' ')[0]
                        wordlist = data['commandline'].split(' -w ')[1].split(' ')[0]

                        if not ffuf_data.get(url, False) or not ffuf_data[url].get(attack, False):

                            ffuf_data[url] = {attack: {'wordlist':wordlist, 'status':{}}}
                        status = ffuf_data[url][attack]['status']
                        status_count = {}
                        for r in data['results']:
                            if not status.get(r['status']):
                                status[r['status']] = {}
                            if not status_count.get(r['status'], False):
                                status_count[r['status']] = 1
                            status_count[r['status']] += 1
                            if status_count[r['status']] < 11:
                                status[r['status']][r['input']] = r['words']
        

        if args.include_gowitness:
            
            path = os.path.join(self.base_config["PROJECT"]["base_path"],'output', 'Gowitness')
            for (dirpath, dirnames, filenames) in os.walk(path):
                
                if 'gowitness.db' in filenames:
                    gowitness_databases.append(os.path.join(dirpath, 'gowitness.db'))

            for database in gowitness_databases:
                data = open(database).read().split('\n')
                for d in data:
                    if '{"url"' in d:
                        
                        j = json.loads(d)
                        try:
                            j['image_data'] = b64encode(open(j['screenshot_file'], 'rb').read()).decode()
                        except Exception as e:
                            print("Could not get image: {}. Error: {}".format(j['screenshot_file'], e))
                        url = j['url'].split('/')[-1]
                        
                        if not gowitness_data.get(url, False):
                            gowitness_data[url] = []
                        gowitness_data[url].append(j)


        
        for i in self.IPAddress.all(scope_type="active"):
            if  i.domains or [p for p in i.ports if p.port_number > 0]:
                ip_data[i.ip_address] = {'domains':[], "ports":{}}
                

                domains = [d.domain for d in i.domains]
                ip_data[i.ip_address]['domains'] = domains

                for p in i.ports:
                    if p.port_number > 0:
                        hosts = ["{}:{}".format(i.ip_address, p.port_number)] + ["{}:{}".format(d, p.port_number) for d in domains]

                        port_data = {'vulns':{}, 'gw':[], 'service':p.service_name}
                        for h in hosts:
                            if gowitness_data.get(h):
                                port_data['gw'].append(gowitness_data[h])

                        ip_data[i.ip_address]['ports'][p.port_number] = port_data
                        for v in p.vulnerabilities:
                            try:
                              output = v.meta['plugin_output'][i.ip_address][str(p.port_number)]
                            except Exception as e:
                              
                              output = []
                            port_data['vulns'][v.name] = {'desc':v.description, 'sev':sev_map[v.severity], 'exploitable':v.exploitable, "output":list(set(output))}

        
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        t = Template(open(os.path.join(template_path, 'main_template.html')).read())
        # ports = Template(open(os.path.join(template_path, 'ports_template.html')).read())
        nessus = Template(open(os.path.join(template_path, 'nessus_template.html')).read())
        gowit = Template(open(os.path.join(template_path, 'gowitness_template.html')).read())
        ffuf = Template(open(os.path.join(template_path, 'ffuf_template.html')).read())
        data_path = os.path.join(os.path.dirname(args.output_html), 'data')
        static_path = os.path.join(os.path.dirname(args.output_html), 'static')
        static_source = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
        # data_path = os.path.dirname(args.output_html)
        if data_path and not os.path.isdir(data_path):
            os.mkdir(data_path)
        if static_path and not os.path.isdir(static_path):
            os.mkdir(static_path)

        static_files = ['bootstrap.min.css','bootstrap.min.css.map','bootstrap.min.js','jquery-3.3.1.min.js','popper.min.js']

        for s in static_files:
            shutil.copyfile(os.path.join(static_source, s), os.path.join(static_path, s))

        new_ips = {}
        ip_domains = {}
        
        for ips, data in ip_data.items():
            if not new_ips.get(ips, False):
                new_ips[ips] = {'ports':{}, 'domains':[]}
            if data['ports']:
                # pdb.set_trace()
                port_data = data['ports']
                
                port_res = {}
                
                
                for p, pdata in port_data.items():
                    if not port_res.get(p, False):
                        
                        port_res[p] = {'service':pdata['service'], 'data':[]}

                    if pdata['vulns']:
                        open(os.path.join(data_path, "nessus-{}-{}.html".format(ips, p)), 'w').write(nessus.render(vulns=pdata['vulns'], ip_address=ips, port=p))
                        port_res[p]['data'].append('nessus')
                    if pdata['gw']:
                        open(os.path.join(data_path, "gowitness-{}-{}.html".format(ips, p)), 'w').write(gowit.render(gw_data=pdata['gw']))
                        port_res[p]['data'].append('gowitness')
                    ffuf_d = {}
                    
                    if ffuf_data.get("{}:{}".format(ips, p), False) :
                        f = False
                        for v in [v['status'] for k, v in ffuf_data["{}:{}".format(ips, p)].items()]:
                            if v:
                                f = True

                        if f:    
                            ffuf_d[ips] = ffuf_data["{}:{}".format(ips, p)]
                    for d in data['domains']:
                        
                        if ffuf_data.get("{}:{}".format(d, p), False):
                            f = False
                            for v in  [v['status'] for k, v in ffuf_data["{}:{}".format(d, p)].items()]:
                                if v:
                                    f = True
                            if f:
                                ffuf_d[d] = ffuf_data["{}:{}".format(d, p)]

                    if ffuf_d:
                        open(os.path.join(data_path, "ffuf-{}-{}.html".format(ips, p)), 'w').write(ffuf.render(ffuf_data=ffuf_d))
                        port_res[p]['data'].append('ffuf')
                    
                    # open(os.path.join(data_path, "{}-{}.html".format(ips, p)), 'w').write(ports.render(ip=ips, port = port_res[p], port_num=p))
                new_ips[ips]['ports'] = port_res

            if data['domains']:
                new_ips[ips]['domains'] = data['domains']

        
         
        open(args.output_html, 'w').write(t.render(ips=new_ips))


        


