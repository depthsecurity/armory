#!/usr/bin/python

from database.repositories import BaseDomainRepository, ScopeCIDRRepository
from included.ModuleTemplate import ToolTemplate
from included.utilities import which
import shlex
import os
import pdb
from included.utilities.color_display import display, display_error
import json


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
            "--import_database",
            help="Run WHOIS on all domains and CIDRs in database",
            action="store_true",
        )

    def get_targets(self, args):

        targets = []
        if args.domain:
            created, domain = self.BaseDomain.find_or_create(domain=args.domain)

            targets.append({"domain": domain.domain, "cidr": ""})

        elif args.cidr:
            created, cidr = self.ScopeCIDR.find_or_create(cidr=args.cidr)

            targets.append({"domain": "", "cidr": cidr.cidr.split("/")[0]})

        elif args.import_database:
            if args.all_data:
                scope_type = ""
            else:
                scope_type = "passive"
            if args.rescan:
                domains = self.BaseDomain.all(scope_type=scope_type)
                cidrs = self.ScopeCidr.all(scope_type=scope_type)
            else:
                domains = self.BaseDomain.all(scope_type=scope_type, tool=self.name)
                cidrs = self.ScopeCidr.all(scope_type=scope_type, tool=self.name)

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
            + self.binary
            + " {domain}{cidr} "
            + args.tool_args
            + '> {output}" '
        )

        return cmd

    def process_output(self, cmds):

        display("Importing data to database")

        for cmd in cmds:
            if cmd["cidr"]:
                _, cidr = self.ScopeCidr.find_or_create(cidr=cmd["cidr"])
                cidr.meta["whois"] = open(cmd["output"]).read()
                display(cidr.meta["whois"])
                cidr.update()

            elif cmd["domain"]:
                _, domain = self.BaseDomain.find_or_create(domain=cmd["domain"])
                domain.meta["whois"] = open(cmd["output"]).read()
                display(domain.meta["whois"])
                domain.update()

        self.BaseDomain.commit()
