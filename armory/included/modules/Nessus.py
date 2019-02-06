from ..ModuleTemplate import ModuleTemplate
from armory.database.repositories import (
    BaseDomainRepository,
    DomainRepository,
    IPRepository,
    PortRepository,
    VulnRepository,
    CVERepository,
    ScopeCIDRRepository,
)
from ..utilities.color_display import display, display_new, display_error
from ..utilities.nessus import NessusRequest
from ..utilities.sort_ranges import merge_ranges
import json
import os
import requests
import time
import xml.etree.cElementTree as ET
import pdb


class Module(ModuleTemplate):

    name = "Nessus"

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
            "--import_file",
            help="Import separated Nessus files separated by a space. DO NOT USE QUOTES OR COMMAS",
            nargs="+",
        )
        self.options.add_argument(
            "--launch",
            help="Launch Nessus scan using Actively scoped IPs and domains in the database",
            action="store_true",
        )
        self.options.add_argument(
            "--job_name", help="Job name inside Nessus", default="Armory Job"
        )
        self.options.add_argument("--username", help="Nessus Username")
        self.options.add_argument("--password", help="Nessus Password")
        self.options.add_argument(
            "--host", help="Hostname:Port of Nessus web interface (ie localhost:8835"
        )
        self.options.add_argument("--uuid", help="UUID of Nessus Policy to run")
        self.options.add_argument("--policy_id", help="Policy ID to use")
        self.options.add_argument("--folder_id", help="ID for folder to store job in")
        self.options.add_argument(
            "--download",
            help="Download Nessus job from server and import",
            action="store_true",
        )
        self.options.add_argument("--job_id", help="Job ID to download and import")
        self.options.add_argument(
            "--output_path",
            help="Path to store downloaded file (Default: Nessus)",
            default=self.name,
        )

    def run(self, args):
        if args.import_file:
            for nFile in args.import_file:
                self.process_data(nFile, args)
        elif args.launch:
            if (
                not args.username  # noqa: W503
                and not args.password  # noqa: W503
                and not args.host  # noqa: W503
                and not args.uuid  # noqa: W503
                and not args.policy_id  # noqa: W503
                and not args.folder_id  # noqa: W503
            ):
                display_error(
                    "You must supply a username, password, and host to launch a Nessus job"
                )

            else:
                n = NessusRequest(
                    args.username,
                    args.password,
                    args.host,
                    uuid=args.uuid,
                    policy_id=args.policy_id,
                    folder_id=args.folder_id,
                )

                ips = [
                    ip.ip_address
                    for ip in self.IPAddress.all(scope_type="active", tool=self.name)
                ]
                cidrs = [cidr.cidr for cidr in self.ScopeCIDR.all(tool=self.name)]
                domains = [
                    domain.domain
                    for domain in self.Domain.all(scope_type="active", tool=self.name)
                ]
                targets = ", ".join(merge_ranges(ips + cidrs) + domains)

                res = n.launch_job(targets, args.job_name)
                display("New Nessus job launched with ID {}".format(res))
                display(
                    "Remember this number! You'll need it to download the job once it is done."
                )

        elif args.download:
            if (
                not args.username  # noqa: W503
                and not args.password  # noqa: W503
                and not args.host  # noqa: W503
                and not args.job_id  # noqa: W503
            ):
                display_error(
                    "You must supply host, username, password and job_id to download a report to import"
                )

            else:
                n = NessusRequest(
                    args.username,
                    args.password,
                    args.host,
                    proxies={"https": "127.0.0.1:8080"},
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
                output_path = os.path.join(
                    output_path, "Nessus-export-{}.nessus".format(int(time.time()))
                )
                n.export_file(args.job_id, output_path)

                self.process_data(output_path, args)

    def nessCheckPlugin(self, tag):
        nessPlugins = [
            "10759",
            "77026",
            "20089",
            "56984",
            "71049",
            "70658",
            "40984",
            "11411",
        ]

        pluginID = tag.get("pluginID")

        if pluginID in nessPlugins:
            # print pluginID + " is in the list"
            if pluginID == "10759":
                if tag.find("plugin_output") is not None:
                    return (
                        tag.find("plugin_output").text.split("\n\n")[3].strip()
                    )  # returns IP for Web Server HTTP Header INternal IP disclosure
                else:
                    return ""

            if pluginID == "77026":
                if tag.find("plugin_output") is not None:
                    return (
                        tag.find("plugin_output").text.split("\n\n")[3].strip()
                    )  # Microsoft Exchange Client Access Server Information Disclosure (IP addy)
                else:
                    return ""

            if pluginID == "71049" or pluginID == "70658":
                output = ""
                if tag.find("plugin_output") is not None:
                    tmp = tag.find("plugin_output").text.split(":")[
                        1
                    ]  # SSH Weak MAC & CBC Algorithms Enabled
                    # print "#"*5
                    tmp = tmp.split("\n\n")[1].replace("  ", "")
                    # print "#"*5
                    output = tmp.split("\n")
                    # print ", ".join(output)
                return ", ".join(output)

            if pluginID == "56984":
                if tag.find("plugin_output") is not None:
                    tmp = (
                        tag.find("plugin_output")
                        .text.split("This port supports ")[1]
                        .strip()
                    )  # SSL / TLS Versions Supported
                    tmp = tmp.split("/")
                    bad = []
                    for i in tmp:
                        # print i
                        if "SSLv" in i:
                            bad.append(i)
                        elif "TLSv1.0" in i:
                            bad.append(i)
                    if bad != []:
                        return ", ".join(bad).rstrip(".")
                    else:
                        return ""
                else:
                    return ""

            if pluginID == "40984":  # browsable web dirs
                if tag.find("plugin_output") is not None:
                    tmp = (
                        tag.find("plugin_output")
                        .text.split("The following directories are browsable :")[1]
                        .strip()
                    )
                    directories = tmp.split("\n")

                    return "\n".join(directories)

            if pluginID == "11411":  # Backup Files Disclosure
                if tag.find("plugin_output") is not None:
                    urls = []
                    
                    tmp = (
                        tag.find("plugin_output")
                        .text.split(
                            "It is possible to read the following backup file"
                        )[1]
                        .strip()
                    )
                    tmpUrls = tmp.split("\n")
                    for url in tmpUrls:
                        if "URL" in url:
                            urls.append(url.split(":")[1].lstrip())
                    if urls:
                        return "\n".join(urls)
                    else:
                        return ""

            if pluginID == "20089":  # F5 cookie
                if tag.find("plugin_output") is not None:
                    f5Output = []
                    cookieVal = []
                    output = tag.find("plugin_output").text.strip().split("\n")
                    for line in output:
                        # print line
                        line = line.split(":")
                        for i, item in enumerate(line):
                            item = item.strip()
                            if "Cookie" in item:
                                line.pop(i)  # Pop to remove the first?
                                tmp = line.pop(i)
                                tmp.strip()
                                cookieVal.append(tmp)
                            else:
                                item = "".join(item)
                                f5Output.append(item)

                    f5Output = " : ".join(f5Output)
                    f5Output = f5Output.replace(" :  : ", ", ")
                    f5Output += " [" + ", ".join(cookieVal) + "]"
                    c = 0
                    tmpF5Output = f5Output.split()
                    for i, letter in enumerate(tmpF5Output):
                        if letter == ":":
                            c += 1
                            if (c % 2) == 0:
                                tmpF5Output[i] = " "
                                return "".join(tmpF5Output).replace("[", " [")
                else:

                    return ""
        else:

            return False

    def getVulns(self, ip, ReportHost):
        """Gets vulns and associated services"""
        for tag in ReportHost.iter("ReportItem"):
            exploitable = False
            cves = []
            vuln_refs = {}
            proto = tag.get("protocol")
            port = tag.get("port")
            svc_name = tag.get("svc_name").replace("?", "")

            tmpPort = proto + "/" + port
            if tmpPort.lower() == "tcp/443":
                portName = "https"
            elif tmpPort.lower() == "tcp/80":
                portName = "http"
            elif svc_name == "www":
                plugin_name = tag.get("pluginName")
                if "tls" in plugin_name.lower() or "ssl" in plugin_name.lower():
                    portName = "https"
                else:
                    portName = "http"
            else:
                portName = svc_name

            created, db_port = self.Port.find_or_create(
                port_number=port, status="open", proto=proto, ip_address_id=ip.id
            )

            if db_port.service_name == "http":
                if portName == "https":
                    db_port.service_name = portName
            elif db_port.service_name == "https":
                pass
            else:
                db_port.service_name = portName
            db_port.save()

            if tag.get("pluginID") == "56984":
                severity = 1
            elif tag.get("pluginID") == "11411":
                severity = 3
            else:
                severity = int(tag.get("severity"))

            findingName = tag.get("pluginName")
            description = tag.find("description").text

            if tag.find("solution") is not None and tag.find("solution") != "n/a":
                solution = tag.find("solution").text
            else:
                solution = "No Remediation From Nessus"

            nessCheck = self.nessCheckPlugin(tag)

            if nessCheck:
                if not db_port.info:
                    db_port.info = {findingName: nessCheck}
                else:
                    db_port.info[findingName] = nessCheck

                db_port.save()

            if tag.find("exploit_available") is not None:
                exploitable = True

            metasploits = tag.findall("metasploit_name")
            if metasploits:
                vuln_refs["metasploit"] = []
                for tmp in metasploits:
                    vuln_refs["metasploit"].append(tmp.text)

            edb_id = tag.findall("edb-id")
            if edb_id:
                vuln_refs["edb-id"] = []
                for tmp in edb_id:
                    vuln_refs["edb-id"].append(tmp.text)

            tmpcves = tag.findall("cve")
            for c in tmpcves:
                if c.text not in cves:
                    cves.append(c.text)

            if not self.Vulnerability.find(name=findingName):
                created, db_vuln = self.Vulnerability.find_or_create(
                    name=findingName,
                    severity=severity,
                    description=description,
                    remediation=solution,
                )
                db_vuln.ports.append(db_port)
                db_vuln.exploitable = exploitable
                if exploitable:
                    display_new("exploit avalable for " + findingName)

                if vuln_refs:
                    db_vuln.exploit_reference = vuln_refs

            else:
                db_vuln = self.Vulnerability.find(name=findingName)
                db_vuln.ports.append(db_port)
                db_vuln.exploitable = exploitable
                if vuln_refs:
                    if db_vuln.exploit_reference is not None:
                        for key in vuln_refs.keys():
                            if key not in db_vuln.exploit_reference.keys():
                                db_vuln.exploit_reference[key] = vuln_refs[key]
                            else:
                                for ref in vuln_refs[key]:
                                    if ref not in db_vuln.exploit_reference[key]:
                                        db_vuln.exploit_reference[key].append(ref)
                    else:
                        db_vuln.exploit_reference = vuln_refs

            for cve in cves:
                if not self.CVE.find(name=cve):
                    try:
                        res = json.loads(
                            requests.get(
                                "http://cve.circl.lu/api/cve/%s" % cve
                            ).text
                        )
                        cveDescription = res["summary"]
                        cvss = float(res["cvss"])

                    except Exception:
                        cveDescription = None
                        cvss = None

                    if not self.CVE.find(name=cve):
                        created, db_cve = self.CVE.find_or_create(
                            name=cve,
                            description=cveDescription,
                            temporal_score=cvss,
                        )
                        db_cve.vulnerabilities.append(db_vuln)
                    else:
                        db_cve = self.CVE.find(name=cve)
                        if (
                            db_cve.description is None
                            and cveDescription is not None  # noqa: W503
                        ):
                            db_cve.description = cveDescription
                        if db_cve.temporal_score is None and cvss is not None:
                            db_cve.temporal_score = cvss
                        db_cve.vulnerabilities.append(db_vuln)

    def process_data(self, nFile, args):
        display("Reading " + nFile)
        tree = ET.parse(nFile)
        root = tree.getroot()
        for ReportHost in root.iter("ReportHost"):
            os = []
            hostname = ""
            hostIP = ""
            for HostProperties in ReportHost.iter("HostProperties"):
                for tag in HostProperties:
                    if tag.get("name") == "host-ip":
                        hostIP = tag.text

                    if tag.get("name") == "host-fqdn":
                        hostname = tag.text.lower()
                        hostname = hostname.replace("www.", "")

                    if tag.get("name") == "operating-system":
                        os = tag.text.split("\n")

            if hostIP:  # apparently nessus doesn't always have an IP to work with...

                if hostname:
                    display(
                        "Gathering Nessus info for {} ( {} )".format(hostIP, hostname)
                    )
                else:
                    display("Gathering Nessus info for {}".format(hostIP))

                created, ip = self.IPAddress.find_or_create(ip_address=hostIP)

                if hostname:
                    created, domain = self.Domain.find_or_create(domain=hostname)

                    if ip not in domain.ip_addresses:
                        ip.save()
                        domain.ip_addresses.append(ip)
                        domain.save()

                if os:
                    for o in os:
                        if not ip.OS:
                            ip.OS = o
                        else:
                            if o not in ip.OS.split(" OR "):
                                ip.OS += " OR " + o

                self.getVulns(ip, ReportHost)
                self.IPAddress.commit()

        return
