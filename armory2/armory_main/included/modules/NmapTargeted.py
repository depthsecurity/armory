#!/usr/bin/python
from armory2.armory_main.models import BaseDomain, Domain, IPAddress, Port, CIDR, Vulnerability, CVE

from armory2.armory_main.included.ModuleTemplate import ToolTemplate
import os
from armory2.armory_main.included.utilities.get_urls import add_tool_url
from armory2.armory_main.included.utilities.nmap import import_nmap

import datetime
import json
import os
import re
import tempfile
import requests
import sys
import pdb
import xml.etree.ElementTree as ET


class Module(ToolTemplate):

    name = "NmapTargeted"
    binary_name = "nmap"


    def set_options(self):
        super(Module, self).set_options()

        
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import hosts from database",
            action="store_true",
        )
        self.options.add_argument(
            "-s",
            "--rescan",
            help="Rescan IPs that have already been scanned",
            action="store_true",
        )

    def get_targets(self, args):

        targets = []
        
        if args.import_database:

            if args.rescan:
                ips = IPAddress.objects.filter(active_scope=True)
            else:
                ips = IPAddress.get_set(scope_type="active", tool=self.name, args=self.args.tool_args)

            if args.output_path[0] == "/":
                output_path = os.path.join(
                    self.base_config["ARMORY_BASE_PATH"], args.output_path[1:]
                )
            else:
                output_path = os.path.join(
                    self.base_config["ARMORY_BASE_PATH"], args.output_path
                )

            if not os.path.exists(output_path):
                os.makedirs(output_path)

            
            for i in ips:
                
                tcp_ports = ','.join([str(p.port_number) for p in i.port_set.filter(proto='tcp').filter(status='open') if p.port_number > 0])
                udp_ports = ','.join([str(p.port_number) for p in i.port_set.filter(proto='udp').filter(status='open') if p.port_number > 0])

                output = os.path.join(
                    output_path, "{}".format(i.ip_address.replace(":", "_")))
                
                if tcp_ports:
                    targets.append({'host': i.ip_address, 
                                    'cmd_str': f"-sT -p {tcp_ports}",
                                    'output': f"{output}-tcp"})


                elif udp_ports:
                    targets.append({'host': i.ip_address, 
                                    'cmd_str': f"-sU -p {udp_ports}",
                                    'output': f"{output}-udp"})

                
                

                
            

        return targets

    def build_cmd(self, args):

        cmd = "sudo " + self.binary + " {cmd_str} -oA {output} {host} -Pn "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, targets):
        
        for t in targets:
            #add_tool_url(url="url://{}".format(t['target']), tool=self.name, args="")
            import_nmap(f"{t['output']}.xml", self.args)
            
            try:
                ip_address = IPAddress.objects.get(ip_address=t['host'])
                ip_address.add_tool_run(self.name, self.args.tool_args)
            except Exception as e:
                # pdb.set_trace()
                print(f"There is no reason this should error out: {e}")


    