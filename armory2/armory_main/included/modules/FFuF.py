#!/usr/bin/python

from armory2.armory_main.models import (
    IPAddress,
    Domain,
    Port,
    
)
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities import get_urls
from armory2.armory_main.included.utilities.color_display import display_warning, display, display_error
import os
import time
import pdb

class Module(ToolTemplate):
    '''
    This module uses Fuzz Faster U Fool (FFuF) for directory fuzzing. It can be installed from:

    https://github.com/ffuf/ffuf

    '''
    name = "FFuF"
    binary_name = "ffuf"


    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-u", "--url", help="URL to brute force")
        self.options.add_argument("--file", help="Import URLs from file")

        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Rescan domains that have already been brute forced",
            action="store_true",
        )
        self.options.set_defaults(timeout=0)  # Disable the default timeout.

    def get_targets(self, args):
        targets = []

        if args.url:

            targets.append(args.url)

        if args.file:
            urls = open(args.file).read().split("\n")
            for u in urls:
                if u:
                    targets.append(u)

        if args.import_database:
            if args.rescan:
                targets += get_urls.run(scope_type="active")
            else:
                targets += get_urls.run(tool=self.name, args=args.tool_args, scope_type="active")

        if args.output_path[0] == "/":
            output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path[1:],
                str(int(time.time())),
            )

        else:
            output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path,
                str(int(time.time())),
            )

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        res = []
        for t in targets:
            res.append(
                {
                    "target": t,
                    "output": os.path.join(
                        output_path,
                        t.replace(":", "_")
                        .replace("/", "_")
                        .replace("?", "_")
                        .replace("&", "_")
                        + "-dir.txt",  # noqa: W503
                    ),
                }
            )

        return res

    def build_cmd(self, args):

        cmd = self.binary
        cmd += " -o {output} -u {target}/FUZZ "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, cmds):

        for cmd in cmds:
            
            target = cmd['target']
            proto = target.split('/')[0]
            url = target.split('/')[2]

            if ':' in url:
                port_num = url.split(':')[1]
                url = url.split(':')[0]
            elif proto == 'http':
                port_num = "80"
            elif proto == 'https':
                port_num = "443"
            else:
                port_num = "0"

            try:
                [int(i) for i in url.split('.')]
                ip, created = IPAddress.objects.get_or_create(ip_address=url, defaults={'active_scope':True})
                
                ip.add_tool_run(tool=self.name, args="{}-{}".format(port_num, self.args.tool_args))
            except:
                display("Domain found: {}".format(url))
                domain, created = Domain.objects.get_or_create(name=url)
                domain.add_tool_run(tool=self.name, args="{}-{}".format(port_num, self.args.tool_args))

            
            port = get_urls.get_port_object("blah://{}:{}".format(url, port_num))
            if port:
                if not port.meta.get('FFuF'):
                    port.meta['FFuF'] = []

                port.meta['FFuF'].append(cmd['output'])

                port.save()

            

        
        