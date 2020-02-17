#!/usr/bin/python

from armory.database.repositories import BaseDomainRepository, DomainRepository
from armory.included.ModuleTemplate import ToolTemplate
from armory.included.utilities.color_display import display_error
import os


class Module(ToolTemplate):

    name = "Sublist3r"
    binary_name = "sublist3r"

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
                domains = self.BaseDomain.all(scope_type="passive")
            else:
                domains = self.BaseDomain.all(tool=self.name, scope_type="passive")
            for d in domains:

                targets.append(d.domain)

        res = []

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

        for t in targets:

            output = os.path.join(output_path, "%s-sublist3r.txt" % t)
            res.append({"target": t, "output": output})

        return res

    def build_cmd(self, args):

        cmd = self.binary + " -o {output} -d {target} "
        if args.tool_args:
            cmd += args.tool_args
        return cmd

    def process_output(self, cmds):

        for cmd in cmds:
            output_path = cmd["output"]

            if os.path.isfile(output_path):
                data = open(output_path).read().split("\n")
                for d in data:
                    for ds in d.split('<BR>'):  # Sublist3r is spitting out <BR>s now...
                        if ds:
                            new_domain = ds.split(":")[0].lower()
                            if new_domain:
                                created, subdomain = self.Domain.find_or_create(
                                    domain=new_domain
                                )
            else:
                display_error("{} not found.".format(output_path))
                next

        self.Domain.commit()
        # except IOError:
        #     display_error("No results found.")

        # else:
        # print("%s already in database." % new_domain)
