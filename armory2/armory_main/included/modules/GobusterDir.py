#!/usr/bin/python

from armory.database.repositories import (
    IPRepository,
    DomainRepository,
    PortRepository,
    UrlRepository,
)
from ..ModuleTemplate import ToolTemplate
from ..utilities import get_urls
from ..utilities.color_display import display_warning
import os
import time


class Module(ToolTemplate):
    '''
    This module uses Gobuster in the directory brute forcing mode. Gobuster can be installed from:

    https://github.com/OJ/gobuster
    '''

    name = "GobusterDir"
    binary_name = "gobuster"

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

        cmd = self.binary + " dir -k "
        cmd += " -o {output} -u {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, cmds):

        display_warning(
            "There is currently no post-processing for this module. For the juicy results, refer to the output file paths."
        )
