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

        self.args = args
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

        data = []
        if args.ssl_cert_mode:
            ports = self.Port.all(service_name="https")

            data = list(set([i.ip_address.ip_address for i in ports]))

            port_numbers = list(set([str(i.port_number) for i in ports]))
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

        self.import_nmap(cmds[0]["output"])
        if cmds[0]["target"]:
            os.unlink(cmds[0]["target"])

    def parseHeaders(self, httpHeaders):
        bsHeaders = [
            "Pragma",
            "Expires",
            "Date",
            "Transfer-Encoding",
            "Connection",
            "X-Content-Type-Options",
            "Cache-Control",
            "X-Frame-Options",
            "Content-Type",
            "Content-Length",
            "(Request type",
        ]
        keepHeaders = {}
        for i in range(0, len(httpHeaders)):
            if httpHeaders[i].strip() != "" and httpHeaders[i].split(":")[
                0
            ].strip() not in " ".join(bsHeaders):
                hName = httpHeaders[i].split(":")[0].strip()
                hValue = "".join(httpHeaders[i].split(":")[1:]).strip()
                keepHeaders[hName] = hValue

        if keepHeaders == {}:
            keepHeaders = ""

        return keepHeaders

    def import_nmap(
        self, filename
    ):  # domains={}, ips={}, rejects=[] == temp while no db
        nFile = filename
        # pdb.set_trace()
        try:
            tree = ET.parse(nFile)
            root = tree.getroot()
            hosts = root.findall("host")

        except Exception as e:
            print("Error: {}".format(e))
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
                    # pdb.set_trace()
                    if not self.args.filter_ports or int(hostPort) not in [
                        int(p) for p in self.args.filter_ports.split(",")
                    ]:
                        created, db_port = self.Port.find_or_create(
                            port_number=hostPort,
                            status=portState,
                            proto=portProto,
                            ip_address=ip,
                        )

                        if port.find("service") is not None:
                            portName = port.find("service").get("name")
                            if portName == "http" and hostPort == "443":
                                portName = "https"
                        else:
                            portName = "Unknown"

                        if created:
                            db_port.service_name = portName
                        info = db_port.info
                        if not info:
                            info = {}

                        for script in port.findall(
                            "script"
                        ):  # just getting commonName from cert
                            if script.get("id") == "ssl-cert":
                                db_port.cert = script.get("output")
                                cert_domains = self.get_domains_from_cert(
                                    script.get("output")
                                )

                                for hostname in cert_domains:
                                    hostname = hostname.lower().replace("www.", "")
                                    created, domain = self.Domain.find_or_create(
                                        domain=hostname
                                    )
                                    if created:
                                        print("New domain found: %s" % hostname)

                            elif script.get("id") == "vulners":
                                print(
                                    "Gathering vuln info for {} : {}/{}\n".format(
                                        hostIP, portProto, hostPort
                                    )
                                )
                                self.parseVulners(script.get("output"), db_port)

                            elif script.get("id") == "banner":
                                info["banner"] = script.get("output")

                            elif script.get("id") == "http-headers":

                                httpHeaders = script.get("output")
                                httpHeaders = httpHeaders.strip().split("\n")
                                keepHeaders = self.parseHeaders(httpHeaders)
                                info["http-headers"] = keepHeaders

                            elif script.get("id") == "http-auth":
                                info["http-auth"] = script.get("output")

                            elif script.get("id") == "http-title":
                                info["http-title"] = script.get("output")

                        db_port.info = info
                        db_port.save()

            self.IPAddress.commit()

    def parseVulners(self, scriptOutput, db_port):
        urls = re.findall(r"(https://vulners.com/cve/CVE-\d*-\d*)", scriptOutput)
        for url in urls:
            vuln_refs = []
            exploitable = False
            cve = url.split("/cve/")[1]
            vulners = requests.get("https://vulners.com/cve/%s" % cve).text
            exploitdb = re.findall(
                r"https://www.exploit-db.com/exploits/\d{,7}", vulners
            )
            for edb in exploitdb:
                exploitable = True

                if edb.split("/exploits/")[1] not in vuln_refs:
                    vuln_refs.append(edb.split("/exploits/")[1])

            if not self.CVE.find(name=cve):
                # print "Gathering CVE info for", cve
                try:
                    res = json.loads(
                        requests.get("http://cve.circl.lu/api/cve/%s" % cve).text
                    )
                    cveDescription = res["summary"]
                    cvss = float(res["cvss"])
                    findingName = res["oval"][0]["title"]
                    if int(cvss) <= 3:
                        severity = 1

                    elif (int(cvss) / 2) == 5:
                        severity = 4

                    else:
                        severity = int(cvss) / 2

                    if not self.Vulnerability.find(name=findingName):
                        # print "Creating", findingName
                        created, db_vuln = self.Vulnerability.find_or_create(
                            name=findingName,
                            severity=severity,
                            description=cveDescription,
                        )
                        db_vuln.ports.append(db_port)
                        db_vuln.exploitable = exploitable
                        if vuln_refs:
                            db_vuln.exploit_reference = {"edb-id": vuln_refs}
                            db_vuln.save()

                    else:
                        # print "modifying",findingName
                        db_vuln = self.Vulnerability.find(name=findingName)
                        db_vuln.ports.append(db_port)
                        db_vuln.exploitable = exploitable

                        if vuln_refs:
                            db_vuln.exploitable = exploitable
                            if db_vuln.exploit_reference is not None:
                                if "edb-id" in db_vuln.exploit_reference:
                                    for ref in vuln_refs:
                                        if (
                                            ref
                                            not in db_vuln.exploit_reference["edb-id"]
                                        ):
                                            db_vuln.exploit_reference["edb-id"].append(
                                                ref
                                            )

                                else:
                                    db_vuln.exploit_reference["edb-id"] = vuln_refs
                            else:
                                db_vuln.exploit_reference = {"edb-id": vuln_refs}

                        db_vuln.save()

                    if not self.CVE.find(name=cve):
                        created, db_cve = self.CVE.find_or_create(
                            name=cve, description=cveDescription, temporal_score=cvss
                        )
                        db_cve.vulnerabilities.append(db_vuln)
                        db_cve.save()

                    else:
                        db_cve = self.CVE.find(name=cve)
                        db_cve.vulnerabilities.append(db_vuln)
                        db_cve.save()

                    self.Vulnerability.commit()
                    self.CVE.commit()
                except Exception:
                    print("something went wrong with the vuln/cve info gathering")
                    if vulners:
                        print(
                            "Vulners report was found but no exploit-db was discovered"
                        )
                        # "Affected vulners items"
                        # print vulners
                    print("Affected CVE")
                    print(cve)
                    pass

            else:
                db_cve = self.CVE.find(name=cve)
                for db_vulns in db_cve.vulnerabilities:
                    if db_port not in db_vulns.ports:
                        db_vulns.ports.append(db_port)
        return

    def get_domains_from_cert(self, cert):
        # Shamelessly lifted regex from stack overflow
        regex = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"

        domains = list(set([d for d in re.findall(regex, cert) if "*" not in d]))

        return domains
