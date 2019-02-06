#!/usr/bin/python

from armory.database.repositories import BaseDomainRepository, UserRepository
from ..ModuleTemplate import ToolTemplate
from ..utilities.color_display import display_error
import os
import csv
import pdb
import sys

if sys.version[0] == '3':
    raw_input = input
class Module(ToolTemplate):
'''
PyMeta is a tool used for searching domains on various search engines, finding all of the relevant
documents, and raiding the exif data to find users.

'''
    name = "PyMeta"
    binary_name = "pymeta"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.User = UserRepository(db, self.name)

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

            output = os.path.join(output_path)
            res.append({"target": t, "output": output})

        return res

    def build_cmd(self, args):

        cmd = self.binary + " -o {output} -d {target} -csv -f full "
        if args.tool_args:
            cmd += args.tool_args
        return cmd

    def process_output(self, cmds):

        for cmd in cmds:
            output_path = cmd["output"]

            created, domain_obj = self.BaseDomain.find_or_create(domain=cmd["target"])

            try:
                csvreader = csv.reader(open(os.path.join(cmd["output"], "pymeta_{}.csv".format(cmd["target"]))))
                
                if sys.version[0] == '2':
                    headers = csvreader.next()
                    
                else:
                    headers = csvreader.__next__()

                searchable_headers = ["Author", "Creator", "Producer"]
                indexes = [headers.index(s) for s in searchable_headers if s in headers]

                data = []
                for row in csvreader:
                    for i in indexes:
                        data.append(row[i])

                data = list(set(data))  # Dedup

                for d in data:
                    # pdb.set_trace()
                    if d.strip() and len(d.split(' '))==2:

                        res = raw_input("Is %s a valid name? [y/N] " % d)
                        if res and res[0].lower() == "y":
                            if " " in d:
                                if ", " in d:
                                    first_name = d.split(", ")[1]
                                    last_name = d.split(", ")[0]
                                else:
                                    first_name = d.split(" ")[0]
                                    last_name = " ".join(d.split(" ")[1:])

                                created, user = self.User.find_or_create(
                                    first_name=first_name, last_name=last_name
                                )
                                if created:
                                    print("New user created")
                                user.domain = domain_obj
                    elif '@' in d:
                        res = raw_input("Is %s a valid email address? [y/N] " % d)
                        if res and res[0].lower() == 'y':
                            created, user = self.User.find_or_create(
                                email=d.strip())
                            if created:
                                print("New user created")
                            user.domain = domain_obj

            except IOError:
                pass
            except Exception as e:
                
                display_error("Error processing pymeta_{}.csv: {}".format(cmd["target"], e))
            
        self.User.commit()

