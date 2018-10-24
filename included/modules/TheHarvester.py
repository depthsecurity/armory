#!/usr/bin/python

from database.repositories import BaseDomainRepository, DomainRepository, UserRepository
from included.ModuleTemplate import ToolTemplate

from included.utilities import which
import shlex
import os
import pdb
import xmltodict
from tld import get_tld


class Module(ToolTemplate):

    name = "TheHarvester"
    binary_name = "theharvester"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.User = UserRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-d", "--domain", help="Domain to harvest")
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
            created, domain = self.BaseDomain.find_or_create(domain=args.domain)
            targets.append({"target": domain.domain})

        elif args.file:
            domains = open(args.file).read().split("\n")
            for d in domains:
                if d:
                    created, domain = self.BaseDomain.find_or_create(domain=d)
                    targets.append({"target": domain.domain})

        elif args.import_database:
            if args.rescan:
                domains = self.BaseDomain.all(scope_type="passive")
            else:
                domains = self.BaseDomain.all(tool=self.name, scope_type="passive")
            for d in domains:

                targets.append({"target": d.domain})

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
            t["output"] = os.path.join(
                output_path, "%s-theharvester" % t["target"].replace(".", "_")
            )

        return targets

    def build_cmd(self, args):

        cmd = self.binary + " -f {output} -b all -d {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, cmds):

        for cmd in cmds:

            try:
                data = xmltodict.parse(open(cmd["output"] + ".xml").read())
            except:
                data = None

            if data:

                if data["theHarvester"].get("email", False):
                    if type(data["theHarvester"]["email"]) == list:
                        emails = data["theHarvester"]["email"]
                    else:
                        emails = [data["theHarvester"]["email"]]
                    for e in emails:

                        created, user = self.User.find_or_create(email=e)
                        _, domain = self.BaseDomain.find_or_create(e.split("@")[1])
                        user.domain = domain
                        user.update()

                        if created:
                            display_new("New email: %s" % e)
                if data["theHarvester"].get("host", False):
                    if type(data["theHarvester"]["host"]) == list:
                        hosts = data["theHarvester"]["host"]
                    else:
                        hosts = [data["theHarvester"]["host"]]

                    for d in hosts:
                        created, domain = self.Domain.find_or_create(
                            domain=d["hostname"]
                        )

            if data["theHarvester"].get("vhost", False):
                if type(data["theHarvester"]["vhost"]) == list:
                    hosts = data["theHarvester"]["vhost"]
                else:
                    hosts = [data["theHarvester"]["vhost"]]

                for d in hosts:
                    created, domain = self.Domain.find_or_create(domain=d["hostname"])
        self.BaseDomain.commit()
