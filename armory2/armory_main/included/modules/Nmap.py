from armory2.armory_main.included.utilities.get_urls import add_tool_url
from armory2.armory_main.models import (
    BaseDomain,
    Domain,
    IPAddress,
    Port,
    CIDR,
    Vulnerability,
    CVE,
)

from armory2.armory_main.included.utilities.nmap import import_nmap

from netaddr import IPNetwork
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
import datetime
import json
import os
import re
import tempfile
import requests
import sys
import xml.etree.ElementTree as ET
import pdb

if sys.version_info[0] >= 3:
    raw_input = input


def check_if_ip(txt):
    try:
        int(txt.replace(".", ""))
        return True
    except ValueError:
        return False


class Module(ToolTemplate):
    """
    Module for running nmap. Make sure to pass all nmap-specific arguments at the end, after --tool_args

    """

    name = "Nmap"
    binary_name = "nmap"

    def set_options(self):
        super(Module, self).set_options()
        self.options.add_argument(
            "--hosts",
            help="Things to scan separated by a space. DO NOT USE QUOTES OR COMMAS",
            nargs="+",
        )
        self.options.add_argument("--hosts_file", help="File containing hosts")
        self.options.add_argument(
            "-i",
            "--hosts_database",
            help="Use unscanned hosts from the database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan", help="Overwrite files without asking", action="store_true"
        )
        self.options.add_argument(
            "--filename",
            help="Output filename. By default will use the current timestamp.",
        )
        self.options.add_argument(
            "--ssl_cert_mode",
            help="Scan only SSL enabled hosts to collect SSL certs (and domain names)",
            action="store_true",
        )
        self.options.add_argument(
            "--filter_ports",
            help="Comma separated list of protoPort to filter out of results. Useful if firewall returns specific ports open on every host. Ex: t80,u5060",
        )

        self.options.set_defaults(timeout=None)
        self.options.add_argument(
            "--import_file", help="Import results from an Nmap XML file."
        )

    def get_targets(self, args):

        
        if args.import_file:
            args.no_binary = True
            return [{"target": "", "output": args.import_file}]

        targets = []

        if args.hosts:

            if type(args.hosts) == list:
                for h in args.hosts:
                    if check_if_ip(h):
                        targets.append(h)
                    else:
                        domain = Domain.objects.get_or_create(name=h)
                        targets += [i.ip_address for i in domain.ip_addresses.all()]

            else:
                if check_if_ip(h):
                    targets.append(h)
                else:
                    domain = Domain.objects.get_or_create(name=h)
                    targets += [i.ip_address for i in domain.ip_addresses.all()]

        if args.hosts_database:
            if args.rescan:
                targets += [
                    h.ip_address for h in IPAddress.get_set(scope_type="active")
                ]
                targets += [h.name for h in CIDR.get_set(scope_type="active")]
            else:
                targets += [
                    h.ip_address
                    for h in IPAddress.get_set(tool=self.name, args=args.tool_args, scope_type="active")
                ]
                targets += [h.name for h in CIDR.get_set(tool=self.name, args=args.tool_args, scope_type="active")]

        if args.hosts_file:
            for h in [l for l in open(args.hosts_file).read().split("\n") if l]:
                if check_if_ip(h):
                    targets.append(h)
                else:
                    domain, created = Domain.objects.get_or_create(name=h)
                    targets += [i.ip_address for i in domain.ip_addresses.all()]

        data = []
        if args.ssl_cert_mode:
            ports = Port.objects.all().filter(service_name="https")

            data = list(set([p.ip_address.ip_address for p in ports]))

            port_numbers = list(set([str(p.port_number) for p in ports]))
            args.tool_args += " -sV -p {} --script ssl-cert ".format(
                ",".join(port_numbers)
            )

        else:

            # Here we should deduplicate the targets, and ensure that we don't have IPs listed that also exist inside CIDRs
            for t in targets:
                ips = [str(i) for i in list(IPNetwork(t))]
                data += ips

        _, file_name = tempfile.mkstemp()
        open(file_name, "w").write("\n".join(list(set(data))))

        if args.output_path[0] == "/":
            self.path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"], args.output_path[1:]
            )
        else:
            self.path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"], args.output_path
            )

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        if args.filename:
            output_path = os.path.join(self.path, args.filename)
        else:
            output_path = os.path.join(
                self.path,
                "nmap-scan-%s.xml"
                % datetime.datetime.now().strftime("%Y.%m.%d-%H.%M.%S"),
            )

        return [{"target": file_name, "output": output_path}]

    def build_cmd(self, args):

        command = "sudo " + self.binary + " -oX {output} -iL {target} "

        if args.tool_args:
            command += args.tool_args

        return command

    def process_output(self, cmds):

        import_nmap(cmds[0]["output"], self.args)
        if cmds[0]['target']:
            for t in open(cmds[0]['target']).read().split('\n'):
                if t:
                    ip_address, created = IPAddress.objects.get_or_create(ip_address=t)
                    ip_address.add_tool_run(tool=self.name, args=self.args.tool_args)
                    
 
        if cmds[0]["target"]:
            os.unlink(cmds[0]["target"])

 