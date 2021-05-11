#!/usr/bin/python
from armory2.armory_main.models import (
    IPAddress,
    Domain,
    Port,
 
)
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities.get_urls import run, add_tool_url, get_port_object
from armory2.armory_main.included.utilities.color_display import display_warning
import os
import time
import pdb


class Module(ToolTemplate):

    name = "Nikto"
    binary_name = "nikto"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-u", "--url", help="URL to scan")
        self.options.add_argument("--file", help="Import URLs from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Rescan URLs that have already been brute forced",
            action="store_true",
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
                targets += run(scope_type="active")
            else:
                targets += run(tool=self.name, args=self.args.tool_args, scope_type="active")

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

        cmd = self.binary + " -output {output} -host {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, cmds):

        for t in cmds:
            add_tool_url(url=t['target'], tool=self.name, args=self.args.tool_args)
            # pdb.set_trace()
            port = get_port_object(t['target'])
            if not port:
                display_warning(f"Port object for {t['target']} not found")
            else:
                if not port.meta.get('Nikto'):
                    port.meta['Nikto'] = {}
                if not port.meta['Nikto'].get(t['target']):
                    port.meta['Nikto'][t['target']] = []
                if t['output'] not in port.meta['Nikto'][t['target']]:

                    port.meta['Nikto'][t['target']].append(t['output'])
                port.save()

        display_warning(
            "There is currently no post-processing for this module. For the juicy results, refer to the output file paths."
        )

