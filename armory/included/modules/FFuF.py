#!/usr/bin/python

from armory.database.repositories import (
    IPRepository,
    DomainRepository,
    PortRepository,
    UrlRepository,
)
from armory.included.ModuleTemplate import ToolTemplate
from armory.included.utilities import get_urls
from armory.included.utilities.color_display import display_warning
import os
import time


class Module(ToolTemplate):
    '''
    This module uses Fuzz Faster U Fool (FFuF) for directory fuzzing. It can be installed from:

    https://github.com/ffuf/ffuf

    '''
    name = "FFuF"
    binary_name = "ffuf"

    def __init__(self, db):
        self.db = db
        self.IPAddress = IPRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.Port = PortRepository(db, self.name)
        self.Url = UrlRepository(db, self.name)

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
                targets += get_urls.run(self.db, scope_type="active")
            else:
                targets += get_urls.run(self.db, tool=self.name, scope_type="active")

        if args.output_path[0] == "/":
            output_path = os.path.join(
                self.base_config["PROJECT"]["base_path"],
                args.output_path[1:],
                str(int(time.time())),
            )

        else:
            output_path = os.path.join(
                self.base_config["PROJECT"]["base_path"],
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
                created, ip = self.IPAddress.find_or_create(ip_address=url)
                port = [p for p in ip.ports if p.port_number == int(port_num) and p.proto == 'tcp'][0]
                port.set_tool(self.name)
            except:
                created, domain = self.Domain.find_or_create(domain=url)
                for ip in self.ip_addresses:
                    port = [p for p in ip.ports if p.port_number == int(port_num) and p.proto == 'tcp'][0]
                    port.set_tool(self.name) 

            
            

        self.Port.commit()
        