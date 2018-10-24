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

    name = "Hydra"
    binary_name = "hydra"

    def __init__(self, db):
        self.db = db
        self.Domain = DomainRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.Port = PortRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-ho", "--host", help="Host to scan (service://host:port)"
        )
        self.options.add_argument(
            "-hw", "--host_wordlist", help="Wordlist to use for one off host"
        )
        self.options.add_argument("-f", "--file", help="Import hosts from file")
        self.options.add_argument(
            "-s",
            "--rescan",
            help="Rescan domains that have already been scanned",
            action="store_true",
        )

        self.options.add_argument(
            "--scan_defaults",
            help="Pull hosts out of database and scan default passwords",
            action="store_true",
        )

        self.options.add_argument("--ftp_wordlist", help="Wordlist for FTP services")
        self.options.add_argument("--telnet_wordlist", help="Wordlist for Telnet")
        self.options.add_argument(
            "--email_wordlist", help="Wordlist for email (smtp, pop3, imap)"
        )
        self.options.add_argument("--ssh_wordlist", help="Wordlist for SSH")
        self.options.add_argument("--vnc_wordlist", help="Wordlist for VNC")

    def get_targets(self, args):
        targets = []

        if args.host:
            service, hp = args.host.split("://")
            host, port = hp.split(":")[-2:]
            targets.append(
                {
                    "target": host,
                    "service": service,
                    "port": port,
                    "wordlist": args.host_wordlist,
                }
            )

        elif args.file:
            hosts = open(args.file).read().split("\n")
            for h in hosts:
                if h:
                    targets.append(h)

        elif args.scan_defaults:
            lists = {}
            if args.ftp_wordlist:
                for p in ["ftps", "ftp"]:
                    lists[args.ftp_wordlist] = [
                        s for s in self.Port.all(tool=self.name, service_name=p)
                    ]

            if args.telnet_wordlist:
                for p in ["telnet"]:
                    lists[args.telnet_wordlist] = [
                        s for s in self.Port.all(tool=self.name, service_name=p)
                    ]

            if args.email_wordlist:
                for p in ["smtps", "smtp", "pop3", "pop3s", "imap", "imaps"]:
                    lists[args.email_wordlist] = [
                        s for s in self.Port.all(tool=self.name, service_name=p)
                    ]

            if args.ssh_wordlist:
                for p in ["ssh"]:
                    lists[args.ssh_wordlist] = [
                        s for s in self.Port.all(tool=self.name, service_name=p)
                    ]

            if args.vnc_wordlist:
                for p in ["vnc"]:
                    lists[args.vnc_wordlist] = [
                        s for s in self.Port.all(tool=self.name, service_name=p)
                    ]

            for k in lists.keys():
                for s in lists[k]:

                    port_number = s.port_number
                    ip_address = s.ip_address.ip_address
                    name = s.service_name

                    targets.append(
                        {
                            "service": name,
                            "target": ip_address,
                            "port": port_number,
                            "wordlist": k,
                        }
                    )

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
                output_path, "{}-{}.txt".format(t["target"], t["port"])
            )

        return targets

    def build_cmd(self, args):

        cmd = self.binary + " -o {output} -C {wordlist} "
        if args.tool_args:
            cmd += args.tool_args

        cmd += " {service}://{target}:{port} "

        return cmd
