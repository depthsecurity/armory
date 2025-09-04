#!/usr/bin/env python
from armory2.armory_main.models import (
    Domain,
    BaseDomain,
    IPAddress,
)
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities.network_tools import get_ips
from armory2.armory_main.included.utilities.color_display import display, display_error, display_warning
import io
import os


class Module(ToolTemplate):
    name = "snrublist3r"
    binary_name = "snrublist3r"

    def set_options(self):
        super(Module, self).set_options()
        self.options.add_argument(
            "-d", "--domain", help="Domain to run snrublist3r against."
        )
        self.options.add_argument(
            "-dL",
            "--domain_list",
            help="Read in a list of domains within the given file.",
        )
        self.options.add_argument(
            "-i",
            "--db_domains",
            help="Import the domains from the database.",
            action="store_true",
        )

        self.options.add_argument(
            "--rescan", help="Overwrite files without asking", action="store_true"
        )

    def get_targets(self, args):
        targets = []
        outpath = ""
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

        if args.domain:
            out_file = os.path.join(outpath, "{}.snrublist3r".format(args.domain))
            targets.append(
                {"target": args.domain, "output": os.path.join(output_path, out_file)}
            )

        if args.db_domains:
            if args.rescan:
                domains = BaseDomain.get_set(scope_type="passive")
            else:
                domains = BaseDomain.get_set(tool=self.name, args=self.args.tool_args, scope_type="passive")
            for d in domains:
                out_file = os.path.join(outpath, "{}.snrublist3r".format(d.name))
                targets.append(
                    {"target": d.name, "output": os.path.join(output_path, out_file)}
                )

        elif args.domain_list:
            domains = io.open(args.domain_list, encoding="utf-8").read().split("\n")
            for d in domains:
                if d:
                    targets.append(
                        {
                            "target": d,
                            "output": os.path.join(
                                output_path, "{}.snrublist3r".format(d)
                            ),
                        }
                    )

        return targets

    def build_cmd(self, args):

        cmd = "env python3 " + self.binary + " -o {output} -d {target} "

        if args.tool_args:
            cmd += args.tool_args
        else:
            cmd += "-pf /opt/src/snrublist3r/lists/permutation-strings.txt" #we must always pass in the pf arg as the tool is coded to expect it to be run inside it's src dir

        return cmd

    def process_output(self, targets):
        for target in targets:
            try:
                with io.open(target["output"], encoding="utf-8") as fd:
                    for line in fd:
                        domain = line.strip()
                        if domain[0] == '.':
                            domain = domain[1:]
                        ips = get_ips(domain)
                        ip_obj = None
                        dom, created = Domain.objects.get_or_create(name=domain)
                        if ips:
                            for ip in ips:
                                ip_obj, created = IPAddress.objects.get_or_create(ip_address=ip)
                                if ip_obj:
                                    dom.ip_addresses.add(ip_obj)
                            dom.save()
            except FileNotFoundError:
                display_error("File doesn't exist for {}".format(target["output"]))
        
            bd, created = BaseDomain.objects.get_or_create(name=target["target"])
            bd.add_tool_run(tool=self.name, args=self.args.tool_args)
    def post_run(self, args):
        # Remove the temporary db file if it was created.
        if getattr(self, "db_domain_file", None):
            try:
                os.unlink(self.db_domain_file)
            except IOError as e:
                print("Failed to remove the Subfinder db temp file: '{}'.".format(e))

    def __get_tempfile(self, domain=None, args=None):
        # Create a temporary file and place all of the current database domains within the file.
        from tempfile import NamedTemporaryFile

        with NamedTemporaryFile(delete=False) as fd:
            if domain:
                fd.write("{}\n".format(domain).encode("utf-8"))
            else:
                # Go through the database and grab the domains adding them to the file.
                if args.rescan:
                    domains = BaseDomains.all(passive_scope=True)
                else:
                    domains = BaseDomains.all(tool=self.name, passive_scope=True)
                if domains:
                    for domain in domains:
                        fd.write("{}\n".format(domain.domain).encode("utf-8"))
                else:
                    return None
        return fd.name
