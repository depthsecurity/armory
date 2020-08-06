#!/usr/bin/python

from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
from armory2.armory_main.models import Domain
from armory2.armory_main.included.utilities import which
from armory2.armory_main.included.utilities.color_display import display, display_error, display_new
import os
import pdb
import shlex
import subprocess
from netaddr import IPNetwork
import argparse

class Module(ModuleTemplate):
    '''
    Uses DomLink from: 
    https://github.com/vysec/DomLink
    By: Vincent Yu
    
    '''
    name = "DomLink"
    binary_name = "domLink.py"

    
    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("--binary", help="Path to binary")
        self.options.add_argument(
            "-o",
            "--output_path",
            help="Path which will contain program output (relative to base_path in config",
            default=self.name,
        )
        self.options.add_argument(
            "--tool_args",
            help="Additional arguments to be passed to the tool",
            nargs=argparse.REMAINDER,
        )

        self.options.add_argument("-d", "--domain", help="Domain to search.")
        self.options.add_argument("-a", "--api", help="API key to use.", required=True)
        self.options.add_argument('-s', '--scope', help="How to scope results (Default passive)", choices=["active", "passive", "none"], default="passive")
        self.options.add_argument(
            "--no_binary",
            help="Runs through without actually running the binary. Useful for if you already ran the tool and just want to process the output.",
            action="store_true",
        )
    def run(self, args):
        
        if not args.domain:
            display_error("You need to supply a domain to search for.")
            return

        if not args.binary:
            self.binary = which.run(self.binary_name)

        else:
            self.binary = args.binary
        
        if not self.binary:
            display_error(
                "{} binary not found. Please explicitly provide path with --binary".format(self.binary_name)
            )

        if args.output_path[0] == "/":
            output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"], 'output', args.output_path[1:]
            )
        else:
            output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"], 'output', args.output_path
            )

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        output_path = os.path.join(output_path, "{}.txt".format(args.domain))
        
        
        command_args = " {} -o {} -A {} ".format(args.domain, output_path, args.api)
        if args.tool_args:
            command_args += ' '.join(args.tool_args)

        if not args.no_binary:
            current_dir = os.getcwd()

            new_dir = "/".join(self.binary.split("/")[:-1])

            os.chdir(new_dir)

            cmd = shlex.split("python3 " + self.binary + command_args)
            print("Executing: %s" % " ".join(cmd))

            subprocess.Popen(cmd).wait()

            os.chdir(current_dir)


        results = open(output_path).read().split('\n')


        cur_type = None

        for r in results:
            if r:
                if '### Company Names' in r:
                    cur_type = "company"
                elif '### Domain Names' in r:
                    cur_type = "domain"
                elif '### Email Addresses' in r:
                    cur_type = "email"

                else:
                    if cur_type == "domain":

                        if args.scope == "active":
                            d, created = Domain.objects.get_or_create(name=r, defaults={"active_scope":True, "passive_scope":True})
                        elif args.scope == "passive":
                            d, created = Domain.objects.get_or_create(name=r, defaults={"active_scope":False, "passive_scope":True})
                        else:
                            d, created = Domain.objects.get_or_create(name=r, defaults={"active_scope":False, "passive_scope":False})
                

        