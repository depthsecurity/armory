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

from urllib.parse import urlparse



class Module(ToolTemplate):

    name = "Xsstrike"
    binary_name = "xsstrike.py"


    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-u", "--url", help="Base domain to start crawling. ")
        self.options.add_argument("--file", help="Import URLs from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Run xsstrike on hosts that have already been processed.",
            action="store_true",
        )
        self.options.add_argument(
            "-l", "--log_level", help="File log level (default is GOOD)", default="GOOD"
        )
        self.options.set_defaults(timeout=600)  # Kick the default timeout to 10 minutes

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
                    "output": os.path.join(self.output_path, "{}.txt".format(t.replace(':', '_').replace('/', '_')))
                    
                }
            )

        return res

    def build_cmd(self, args):

        cmd = self.binary + " --crawl --log-file {output} -u {target} --file-log-level " + self.args.log_level + ' '

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def pre_run(self, args):

        self.orig_path = os.getcwd()
        os.chdir(os.path.dirname(self.binary))

    def process_output(self, cmds):
        
        for c in cmds:
            
            get_urls.add_tool_url(c['target'], self.name, self.args.tool_args)
        
            
            # display_new("Processing data for {}".format(c['target']))
            data = open(c['output']).read()

            if data:
                port = get_urls.get_port_object(c['target'])
                if not port:
                    display_warning(f"Port object for {c['target']} not found")
                else:
                    if not port.meta.get('Xsstrike'):
                        port.meta['Xsstrike'] = {}
                    if not port.meta['Xsstrike'].get(c['target']):
                        port.meta['Xsstrike'][c['target']] = []
                    if c['output'] not in port.meta['Xsstrike'][c['target']]:

                        port.meta['Xsstrike'][c['target']].append(c['output'])
                    port.save()
            
        display_warning(
            "There is currently no post-processing for this module. For the juicy results, refer to the output file paths."
        )

    def post_run(self, args):

        os.chdir(self.orig_path)