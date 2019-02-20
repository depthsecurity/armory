#!/usr/bin/python

from armory.database.repositories import BaseDomainRepository, ScopeCIDRRepository
from ..ModuleTemplate import ToolTemplate
from ..utilities.color_display import display
from ..utilities.readFile import read_file
import os


class Module(ToolTemplate):

    name = "Whois"
    binary_name = "whois"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.ScopeCidr = ScopeCIDRRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-d", "--domain", help="Domain to query")
        self.options.add_argument("-c", "--cidr", help="CIDR to query")

        self.options.add_argument(
            "-s",
            "--rescan",
            help="Rescan domains that have already been scanned",
            action="store_true",
        )
        self.options.add_argument(
            "-a",
            "--all_data",
            help="Scan all data in database, regardless of scope",
            action="store_true",
        )
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Run WHOIS on all domains and CIDRs in database",
            action="store_true",
        )

    def get_targets(self, args):

        targets = []
        if args.domain:

            targets.append({"domain": args.domain, "cidr": ""})

        elif args.cidr:

            targets.append({"domain": "", "cidr": args.cidr.split("/")[0]})

        elif args.import_database:

            if args.all_data:
                scope_type = ""
            else:
                scope_type = "passive"
            if args.rescan:
                domains = self.BaseDomain.all(scope_type=scope_type)
                cidrs = self.ScopeCidr.all()
            else:
                domains = self.BaseDomain.all(scope_type=scope_type, tool=self.name)
                cidrs = self.ScopeCidr.all(tool=self.name)

            for domain in domains:
                targets.append({"domain": domain.domain, "cidr": ""})
            for cidr in cidrs:
                targets.append({"domain": "", "cidr": cidr.cidr.split("/")[0]})

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
            t["output"] = os.path.join(output_path, t["domain"] + t["cidr"])

        return targets

    def build_cmd(self, args):

        if not args.tool_args:
            args.tool_args = ""
        cmd = (
            'bash -c "'
            + self.binary  # noqa: W503
            + " {domain}{cidr} "  # noqa: W503
            + args.tool_args  # noqa: W503
            + '> {output}" '  # noqa: W503
        )

        return cmd

    def process_output(self, cmds):

        display("Importing data to database")

        for cmd in cmds:
            if cmd["cidr"]:
                _, cidr = self.ScopeCidr.find_or_create(cidr=cmd["cidr"])
                cidr.meta["whois"] = read_file(cmd["output"])
                display(cidr.meta["whois"])
                cidr.update()

            elif cmd["domain"]:
                _, domain = self.BaseDomain.find_or_create(domain=cmd["domain"])
                domain.meta["whois"] = read_file(cmd["output"])
                display(domain.meta["whois"])
                domain.update()

        self.BaseDomain.commit()
