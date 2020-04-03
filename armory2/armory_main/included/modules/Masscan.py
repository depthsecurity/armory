from armory.database.repositories import (
    BaseDomainRepository,
    DomainRepository,
    IPRepository,
    PortRepository,
    ScopeCIDRRepository,
    VulnRepository,
    CVERepository,
)
from netaddr import IPNetwork
from ..ModuleTemplate import ToolTemplate
import datetime
import os
import re
import tempfile
import sys
import xml.etree.ElementTree as ET

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
    Module for running masscan. Make sure to pass all masscan-specific arguments at the end, after --tool_args

    """

    name = "Masscan"
    binary_name = "masscan"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.Port = PortRepository(db, self.name)

        self.Vulnerability = VulnRepository(db, self.name)
        self.CVE = CVERepository(db, self.name)
        self.ScopeCIDR = ScopeCIDRRepository(db, self.name)

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
        self.options.set_defaults(timeout=None)
        self.options.add_argument(
            "--import_file", help="Import results from an Masscan/Nmap XML file."
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
                        created, domain = self.Domain.find_or_create(domain=h)
                        targets += [i.ip_address for i in domain.ip_addresses]

            else:
                if check_if_ip(h):
                    targets.append(h)
                else:
                    created, domain = self.Domain.find_or_create(domain=h)
                    targets += [i.ip_address for i in domain.ip_addresses]

        if args.hosts_database:
            if args.rescan:
                targets += [
                    h.ip_address for h in self.IPAddress.all(scope_type="active")
                ]
                targets += [h.cidr for h in self.ScopeCIDR.all()]
            else:
                targets += [
                    h.ip_address
                    for h in self.IPAddress.all(tool=self.name, scope_type="active")
                ]
                targets += [h.cidr for h in self.ScopeCIDR.all(tool=self.name)]

        if args.hosts_file:
            for h in [l for l in open(args.hosts_file).read().split("\n") if l]:
                if check_if_ip(h):
                    targets.append(h)
                else:
                    created, domain = self.Domain.find_or_create(domain=h)
                    targets += [i.ip_address for i in domain.ip_addresses]

        # Here we should deduplicate the targets, and ensure that we don't have IPs listed that also exist inside CIDRs
        data = []
        for t in targets:
            ips = [str(i) for i in list(IPNetwork(t))]
            data += ips

        _, file_name = tempfile.mkstemp()
        open(file_name, "w").write("\n".join(set(data)))

        if args.output_path[0] == "/":
            self.path = os.path.join(
                self.base_config["PROJECT"]["base_path"], args.output_path[1:]
            )
        else:
            self.path = os.path.join(
                self.base_config["PROJECT"]["base_path"], args.output_path
            )

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        if args.filename:
            output_path = os.path.join(self.path, args.filename)
        else:
            output_path = os.path.join(
                self.path,
                "masscan-%s.xml"
                % datetime.datetime.now().strftime("%Y.%m.%d-%H.%M.%S"),
            )

        return [{"target": file_name, "output": output_path}]

    def build_cmd(self, args):

        command = "sudo " + self.binary + " -oX {output} -iL {target} "

        if args.tool_args:
            command += args.tool_args

        return command

    def process_output(self, cmds):

        self.import_masscan(cmds[0]["output"])
        if cmds[0]["target"]:
            os.unlink(cmds[0]["target"])

    def import_masscan(
        self, filename
    ):  # domains={}, ips={}, rejects=[] == temp while no db
        nFile = filename

        try:
            tree = ET.parse(nFile)
            root = tree.getroot()
            hosts = root.findall("host")

        except Exception:
            print(nFile + " doesn't exist somehow...skipping")
            return

        for host in hosts:
            hostIP = host.find("address").get("addr")

            created, ip = self.IPAddress.find_or_create(ip_address=hostIP)

            for hostname in host.findall("hostnames/hostname"):
                hostname = hostname.get("name")
                hostname = hostname.lower().replace("www.", "")

                # reHostname = re.search(
                #     r"\d{1,3}\-\d{1,3}\-\d{1,3}\-\d{1,3}", hostname
                # )  # attempt to not get PTR record
                # if not reHostname:

                created, domain = self.Domain.find_or_create(domain=hostname)
                if ip not in domain.ip_addresses:
                    domain.ip_addresses.append(ip)
                    domain.save()

            for port in host.findall("ports/port"):

                if port.find("state").get("state"):
                    portState = port.find("state").get("state")
                    hostPort = port.get("portid")
                    portProto = port.get("protocol")

                    created, db_port = self.Port.find_or_create(
                        port_number=hostPort,
                        status=portState,
                        proto=portProto,
                        ip_address=ip,
                    )
                    info = db_port.info
                    if not info:
                        info = {}

                    if port.find("service") is not None:
                        service = port.find("service")
                        portName = service.get("name")
                        if portName == "http" and hostPort == "443":
                            portName = "https"
                        banner = service.get("banner", None)
                        if banner:
                            print("Found banner: {}".format(banner))
                            info["banner"] = banner
                    else:
                        portName = "Unknown"

                    if created:
                        db_port.service_name = portName
                    db_port.info = info
                    db_port.save()

            self.IPAddress.commit()

    def get_domains_from_cert(self, cert):
        # Shamelessly lifted regex from stack overflow
        regex = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"

        domains = list(set([d for d in re.findall(regex, cert) if "*" not in d]))

        return domains
