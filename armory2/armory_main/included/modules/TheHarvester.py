#!/usr/bin/python
from armory2.armory_main.models import (
    Domain,
    User,
    BaseDomain,
)
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities.color_display import display_new, display_error, display
import os
import xmltodict
import pdb

class Module(ToolTemplate):

    name = "TheHarvester"
    binary_name = "theHarvester"

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

            targets.append({"target": args.domain})

        elif args.file:
            domains = open(args.file).read().split("\n")
            for d in domains:
                if d:
                    
                    targets.append({"target": d})

        elif args.import_database:
            if args.rescan:
                domains = BaseDomain.get_set(scope_type="passive")
            else:
                domains = BaseDomain.get_set(tool=self.name, args=args.tool_args, scope_type="passive")
            for d in domains:

                targets.append({"target": d.name})

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
            t["output"] = os.path.join(
                output_path, "%s-theharvester" % t["target"].replace(".", "_")
            )

        return targets

    def build_cmd(self, args):

        cmd = self.binary + " -f {output} -d {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, cmds):

        for cmd in cmds:

            try:
                data = xmltodict.parse(open(cmd["output"] + ".xml").read())
            except Exception as e:
                # display_error("Error with {}: {}".format(cmd["output"], e))
                data = None

            if data and data.get('theHarvester'):
                
                if data["theHarvester"].get("email", False):
                    if type(data["theHarvester"]["email"]) == list:
                        emails = data["theHarvester"]["email"]
                    else:
                        emails = [data["theHarvester"]["email"]]
                    for e in emails:
                        display("Processing E-mail: {}".format(e))
                        domain, created = BaseDomain.objects.get_or_create(name=e.split("@")[1])
                        user, created = User.objects.get_or_create(email=e, domain=domain)
                        
                        
                        
                        user.save()

                        if created:
                            display_new("New email: %s" % e)
                if data["theHarvester"].get("host", False):
                    if type(data["theHarvester"]["host"]) == list:
                        hosts = data["theHarvester"]["host"]
                    else:
                        hosts = [data["theHarvester"]["host"]]

                    for d in hosts:
                        if type(d) == str:
                            hostname = d
                        else:
                            hostname = d["hostname"]

                        domain, created = Domain.objects.get_or_create(
                            name=hostname
                        )

                if data["theHarvester"].get("vhost", False):
                    if type(data["theHarvester"]["vhost"]) == list:
                        hosts = data["theHarvester"]["vhost"]
                    else:
                        hosts = [data["theHarvester"]["vhost"]]

                    for d in hosts:
                        
                        if type(d) == str:
                            hostname = d
                        else:
                            hostname = d["hostname"]

                        domain, created = Domain.objects.get_or_create(
                            name=hostname
                        )        
