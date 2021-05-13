#!/usr/bin/python

from armory2.armory_main.models import (
    IPAddress,
    Domain,
    Port,
    
)
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities import get_urls
import os
import re
import pdb
from multiprocessing import Pool as ThreadPool
from armory2.armory_main.included.utilities.color_display import display, display_warning, display_new
import time
import glob

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


class Module(ToolTemplate):

    name = "Xsscrapy"
    binary_name = "xsscrapy.py"


    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-d", "--domain", help="Base domain to start crawling. ")
        self.options.add_argument("--file", help="Import URLs from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Run xsscrapy on hosts that have already been processed.",
            action="store_true",
        )
        self.options.set_defaults(timeout=600)  # Kick the default timeout to 10 minutes

    def get_targets(self, args):
        targets = []

        if args.domain:

            targets.append(args.domain)

        if args.file:
            urls = open(args.file).read().split("\n")
            for u in urls:
                if u:
                    targets.append(u)

        if args.import_database:
            if args.rescan:
                targets += get_urls.run(scope_type="active", args=self.args.tool_args)
            else:
                targets += get_urls.run(tool=self.name, scope_type="active", args=self.args.tool_args)

        if args.output_path[0] == "/":
            self.output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path[1:],
                str(int(time.time())),
            )

        else:
            self.output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path,
                str(int(time.time())),
            )

        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path)

        res = []
        for t in targets:
            res.append(
                {
                    "target": t,
                }
            )

        return res

    def build_cmd(self, args):

        cmd = self.binary + " -u {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def pre_run(self, args):

        self.orig_path = os.getcwd()
        os.chdir(os.path.dirname(self.binary))

    def process_output(self, cmds):
        
        for c in cmds:
            
            get_urls.add_tool_url(c['target'], self.name, self.args.tool_args)
        # Xsscrapy dumps results in its current directory.
        hosts = {}
        
        for f in [g for g in glob.glob(os.path.dirname(self.binary) + '/*.txt') if 'requirements.txt' not in g]:
            res = open(f).read()

            if res[1:4] == 'URL': # This looks like results
                data = res[1:].split('\n\n')
                for d in data:
                    host = d.split('\n')[0].split(' ')[1]
                    if not hosts.get(host, False):
                        hosts[host] = []

                    hosts[host].append(d)
                os.unlink(f)
        # pdb.set_trace()
        for h, v in hosts.items():
            
            display_new("Found data for {}".format(h))
            output = os.path.join(self.output_path, "{}.txt".format(h.replace(':', '_').replace('/', '_')))
            f = open(output, 'w')

            for d in v:
                display("URL: {}".format(d.split('\n')[0].split(' ')[1]))
                f.write(d + '\n\n')

            port = get_urls.get_port_object(h)
            if not port:
                display_warning(f"Port object for {h} not found")
            else:
                if not port.meta.get('Xsscrapy'):
                    port.meta['Xsscrapy'] = {}
                if not port.meta['Xsscrapy'].get(h):
                    port.meta['Xsscrapy'][h] = []
                if output not in port.meta['Xsscrapy'][h]:

                    port.meta['Xsscrapy'][h].append(output)
                port.save()
                
        display_warning(
            "There is currently no post-processing for this module. For the juicy results, refer to the output file paths."
        )

    def post_run(self, args):

        os.chdir(self.orig_path)