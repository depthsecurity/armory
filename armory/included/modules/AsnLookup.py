#!/usr/bin/python

from armory.included.ModuleTemplate import ModuleTemplate
from armory.database.repositories import ScopeCIDRRepository
from armory.included.utilities import which
from armory.included.utilities.color_display import display, display_error, display_new
import os
import pdb
import shlex
import subprocess
from netaddr import IPNetwork

class Module(ModuleTemplate):
    '''
    Uses modified Asnlookup.py tool. Originally from: 
    https://github.com/yassineaboukir/Asnlookup
    By: Yassine Aboukir
    Modified version:
    https://github.com/fang0654/Asnlookup

    '''
    name = "Asnlookup"
    binary_name = "asnlookup.py"

    def __init__(self, db):
        self.db = db
        self.ScopeCIDRs = ScopeCIDRRepository(db, self.name)
    
    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-k", "--keyword", help="Keyword to search for")
        self.options.add_argument("--binary", help="Path to binary")
        self.options.add_argument(
            "-o",
            "--output_path",
            help="Path which will contain program output (relative to base_path in config",
            default=self.name,
        )
        

    def run(self, args):
        
        if not args.keyword:
            display_error("You need to supply a keyword to search for.")
            return

        if not args.binary:
            self.binary = which.run(self.binary_name)

        else:
            self.binary = args.binary
        
        if not self.binary:
            display_error(
                "Asnlookup binary not found. Please explicitly provide path with --binary"
            )

        if args.output_path[0] == "/":
            output_path = os.path.join(
                self.base_config["PROJECT"]["base_path"], 'output', args.output_path[1:]
            )
        else:
            output_path = os.path.join(
                self.base_config["PROJECT"]["base_path"], 'output', args.output_path
            )

        if not os.path.exists(output_path):
            os.makedirs(output_path)

        
        
        command_args = " -o {} --output {} ".format(args.keyword, output_path)

        current_dir = os.getcwd()

        new_dir = "/".join(self.binary.split("/")[:-1])

        os.chdir(new_dir)

        cmd = shlex.split("python3 " + self.binary + command_args)
        print("Executing: %s" % " ".join(cmd))

        subprocess.Popen(cmd).wait()

        os.chdir(current_dir)

        ip_ranges = open(os.path.join(output_path, "{}_ipv4.txt".format(args.keyword))).read().split('\n')



        for r in ip_ranges:
            if r:
                display("Processing {}".format(r))
                current_cidrs = [c.cidr for c in self.ScopeCIDRs.all()]

                new_cidr = True

                for nc in current_cidrs:
                    if IPNetwork(r) in IPNetwork(nc):
                        new_cidr = False
                if new_cidr:
                    created, SC = self.ScopeCIDRs.find_or_create(cidr=r)
                    
                    if created:
                        display_new("New CIDR added to ScopeCIDRS: {}".format(r))

        self.ScopeCIDRs.commit()
