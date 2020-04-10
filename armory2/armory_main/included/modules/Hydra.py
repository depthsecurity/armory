#!/usr/bin/python
from armory2.armory_main.models import Domain, IPAddress, Port
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
import os
import pdb

class Module(ToolTemplate):

    name = "Hydra"
    binary_name = "hydra"


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
            if args.rescan:
                all_hosts = Port.get_set(scope_type="Active")
            else:
                all_hosts = Port.get_set(scope_type="Active", tool=self.name)


            if args.ftp_wordlist:
                lists[("ftps", "ftp")] = {'wordlist':args.ftp_wordlist, 'hosts':[]}

            if args.telnet_wordlist:
                lists[("telnet",)] = {'wordlist':args.telnet_wordlist, 'hosts':[]}
                    

            if args.email_wordlist:
                lists[("smtps", "smtp", "pop3", "pop3s", "imap", "imaps")] = {'wordlist':args.email_wordlist, 'hosts':[]}
                    

            if args.ssh_wordlist:
                lists[('ssh',)] = {'wordlist':args.ssh_wordlist, 'hosts':[]}

            if args.vnc_wordlist:
                lists[("vnc",)] = {'wordlist':args.vnc_wordlist, 'hosts':[]}

            for a in all_hosts:
                for k in lists.keys():
                    if a.service_name in k:
                        lists[k]["hosts"].append(a)
                        targets.append({
                            "service": a.service_name,
                            "target": a.ip_address.ip_address,
                            "port": a.port_number,
                            "wordlist": lists[k]['wordlist'],

                            })
                        
                        a.add_tool_run(tool=self.name)

            
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
                output_path, "{}-{}.txt".format(t["target"], t["port"])
            )

        return targets

    def build_cmd(self, args):

        cmd = self.binary + " -o {output} -C {wordlist} "
        if args.tool_args:
            cmd += args.tool_args

        cmd += " {service}://{target}:{port} "

        return cmd
