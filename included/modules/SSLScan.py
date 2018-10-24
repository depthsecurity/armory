#!/usr/bin/python

from database.repositories import DomainRepository, IPRepository, PortRepository
from included.ModuleTemplate import ToolTemplate
import subprocess
from included.utilities import which
import shlex
import os
import pdb
from multiprocessing import Pool as ThreadPool


class Module(ToolTemplate):

    name = "SSLScan"
    binary_name = "sslscan"

    def __init__(self, db):
        self.db = db
        self.Domain = DomainRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.Port = PortRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-ho", "--host", help="Host to scan (host:port)")
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
            targets.append(args.host)

        elif args.file:
            hosts = open(args.file).read().split("\n")
            for h in hosts:
                if h:
                    targets.append(h)

        elif args.import_database:

            hosts = []
            svc = []

            if args.rescan:

                for p in ["https", "ftps", "imaps", "sip-tls", "imqtunnels", "smtps"]:
                    svc += [
                        (s, "")
                        for s in self.Port.all(service_name=p, status="open")
                        if s.ip_address.in_scope
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
                        for s in self.Port.all(service_name=p, status="open")
                        if s.ip_address.in_scope
                    ]
            else:
                for p in ["https", "ftps", "imaps", "sip-tls", "imqtunnels", "smtps"]:
                    svc += [
                        (s, "")
                        for s in self.Port.all(
                            tool=self.name, service_name=p, status="open"
                        )
                        if s.ip_address.in_scope
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
                        for s in self.Port.all(
                            tool=self.name, service_name=p, status="open"
                        )
                        if s.ip_address.in_scope
                    ]

            for s, option in svc:

                port_number = s.port_number
                ip_address = s.ip_address.ip_address

                targets.append(
                    {"target": "%s:%s" % (ip_address, port_number), "option": option}
                )

                for d in s.ip_address.domains:
                    targets.append(
                        {"target": "%s:%s" % (d.domain, port_number), "option": option}
                    )

        for t in targets:
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
