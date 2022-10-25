#!/usr/bin/python

import pdb
from armory2.armory_main.models import BaseDomain, Domain
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities.color_display import display_error
import os


class Module(ToolTemplate):

    name = "Sublist3r"
    binary_name = "sublist3r"

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
            help="Rescan domains that have already been scanned",
            action="store_true",
        )

    def get_targets(self, args):

        targets = []
        if args.domain:
            targets.append(args.domain)

        elif args.file:
            domains = open(args.file).read().split("\n")
            for d in domains:
                if d:
                    targets.append(d)

        elif args.import_database:
            if args.rescan:
                domains = BaseDomain.get_set(scope_type="passive")
            else:
                domains = BaseDomain.get_set(
                    tool=self.name, scope_type="passive", args=self.args.tool_args
                )
            for d in domains:

                targets.append(d.name)

        res = []

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

        for t in targets:

            output = os.path.join(output_path, "%s-sublist3r.txt" % t)
            res.append({"target": t, "output": output})

        return res

    def build_cmd(self, args):

        cmd = "env python3 " + self.binary + " -o {output} -d {target} "
        if args.tool_args:
            cmd += args.tool_args
        return cmd

    def process_output(self, cmds):

        for cmd in cmds:
            output_path = cmd["output"]

            bd, created = BaseDomain.objects.get_or_create(name=cmd["target"])
            bd.add_tool_run(tool=self.name, args=self.args.tool_args)

            if os.path.isfile(output_path):
                data = open(output_path).read().split("\n")
                for d in data:
                    for ds in d.split("<BR>"):  # Sublist3r is spitting out <BR>s now...
                        if ds:
                            new_domain = ds.split(":")[0].lower()
                            if new_domain:
                                # print("Checking {}".format(new_domain))
                                subdomain, created = Domain.objects.get_or_create(
                                    name=new_domain
                                )
            else:
                display_error(
                    "{} not found, probably no subdomains discovered.".format(
                        output_path
                    )
                )
                next

        # except IOError:
        #     display_error("No results found.")

        # else:
        # print("%s already in database." % new_domain)
