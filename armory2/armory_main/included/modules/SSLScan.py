#!/usr/bin/python
from armory2.armory_main.models import Domain, IPAddress, Port
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
import os
from armory2.armory_main.included.utilities.get_urls import add_tool_url

import pdb

class Module(ToolTemplate):

    name = "SSLScan"
    binary_name = "sslscan"


    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("--host", help="Host to scan (host:port)")
        self.options.add_argument("-f", "--file", help="Import hosts from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import hosts from database",
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
        if args.host:
            if "http" in args.host:
                if args.host.count(":") == 2:
                    service, host, port = args.host.split(":")
                else:
                    service, host = args.host.split(":")
                    port = "443"
                host = host.split("/")[-1]
                targets.append({"option": "", "target": "{}:{}".format(host, port)})
            else:
                targets.append({"option": "", "target": args.host})

        if args.file:
            hosts = open(args.file).read().split("\n")
            for h in hosts:
                if h:
                    if "http" in h:
                        if h.count(":") == 2:
                            service, host, port = h.split(":")
                        else:
                            service, host = h.split(":")
                            port = "443"
                        host = host.split("/")[-1]
                        targets.append(
                            {"option": "", "target": "{}:{}".format(host, port)}
                        )
                    else:
                        targets.append({"option": "", "target": h})

        if args.import_database:

            hosts = []
            svc = []

            if args.rescan:

                for p in ["https", "ftps", "imaps", "sip-tls", "imqtunnels", "smtps"]:
                    svc += [
                        (s, "")
                        for s in Port.objects.all().filter(service_name=p, status="open")
                        if s.ip_address.active_scope
                    ]
                for p in [
                    "ftp",
                    "imap",
                    "irc",
                    "ldap",
                    "pop3",
                    "smtp",
                    "mysql",
                    "xmpp",
                    "psql",
                ]:
                    svc += [
                        (s, "--starttls-%s" % p)
                        for s in Port.objects.all().filter(service_name=p, status="open")
                        if s.ip_address.active_scope
                    ]
            else:
                for p in ["https", "ftps", "imaps", "sip-tls", "imqtunnels", "smtps"]:
                    for s in Port.objects.all().filter(service_name=p, status="open"):

                        if ((self.ip_address.active_scope) and (self.name not in s.ip_address.tools.keys() or "{}-".format(s.port_number) not in s.ip_address.tools[self.name])):
                            svc.append([s, ""])
                        
                        
                for p in [
                    "ftp",
                    "imap",
                    "irc",
                    "ldap",
                    "pop3",
                    "smtp",
                    "mysql",
                    "xmpp",
                    "psql",
                ]:
                    for s in Port.objects.all().filter(service_name=p, status="open"):

                        if ((self.ip_address.active_scope) and (self.name not in s.ip_address.tools.keys() or "{}-".format(s.port_number) not in s.ip_address.tools[self.name])):
                            svc.append([s, "--starttls-%s" % p])
                    
            
            for s, option in svc:

                port_number = s.port_number
                ip_address = s.ip_address.ip_address

                targets.append(
                    {"target": "%s:%s" % (ip_address, port_number), "option": option}
                )

                for d in s.ip_address.domain_set.all():
                    targets.append(
                        {"target": "%s:%s" % (d.name, port_number), "option": option}
                    )

        for t in targets:
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

            output_path = os.path.join(
                output_path, "{}-sslscan.xml".format(t["target"].replace(":", "_"))
            )
            t["output"] = output_path

        return targets

    def build_cmd(self, args):

        cmd = self.binary + " --xml={output} {option} {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, targets):
        
        for t in targets:
            add_tool_url(url="url://{}".format(t['target']), tool=self.name, args="")

