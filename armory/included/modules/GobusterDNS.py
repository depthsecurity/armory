#!/usr/bin/python
from armory.database.repositories import BaseDomainRepository, DomainRepository
from ..ModuleTemplate import ToolTemplate
from ..utilities.color_display import display_error
import os


class Module(ToolTemplate):
    '''
    This module uses Gobuster in the DNS brute forcing mode. Gobuster can be installed from:

    https://github.com/OJ/gobuster
    '''
    
    name = "GobusterDNS"
    binary_name = "gobuster"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-d", "--domain", help="Domain to brute force")
        self.options.add_argument("-f", "--file", help="Import domains from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import domains from database",
            action="store_true",
        )
        self.options.add_argument(
            "-s",
            "--rescan",
            help="Rescan domains that have already been brute forced",
            action="store_true",
        )
        self.options.set_defaults(timeout=600)  # Kick the default timeout to 10 minutes

    def get_targets(self, args):
        targets = []

        if args.domain:

            targets.append(args.domain)

        if args.file:
            domains = open(args.file).read().split("\n")
            for d in domains:
                if d:
                    targets.append(d)

        if args.import_database:
            if args.rescan:
                targets += [b.domain for b in self.BaseDomain.all(scope_type="passive")]
            else:
                targets += [
                    b.domain
                    for b in self.BaseDomain.all(scope_type="passive", tool=self.name)
                ]

        if args.output_path[0] == "/":
            output_path = os.path.join(
                self.base_config["PROJECT"]["base_path"], args.output_path[1:]
            )

        else:
            output_path = os.path.join(
                self.base_config["PROJECT"]["base_path"], args.output_path
            )

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        res = []
        for t in targets:
            res.append(
                {
                    "target": t,
                    "output": os.path.join(
                        output_path, t.replace("/", "_") + "-dns.txt"
                    ),
                }
            )

        return res

    def build_cmd(self, args):

        cmd = self.binary + " dns "
        cmd += " -o {output} -d {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, cmds):

        for c in cmds:
            output_path = c["output"]
            if os.path.isfile(output_path):
                data = open(output_path).read().split("\n")
                for d in data:
                    if "Found: " in d:
                        new_domain = d.split(" ")[1].lower()
                        created, subdomain = self.Domain.find_or_create(
                            domain=new_domain
                        )
            else:
                display_error("{} not found.".format(output_path))

        self.Domain.commit()
