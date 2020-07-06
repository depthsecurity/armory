from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
from armory2.armory_main.models import (
    BaseDomain,
    Domain,
    IPAddress,
    Port,
    Vulnerability,
    CVE,
    CIDR,
    VulnOutput,
)
from armory2.armory_main.included.utilities.color_display import display, display_new, display_error
from armory2.armory_main.included.utilities.nessus import NessusRequest
from armory2.armory_main.included.utilities.sort_ranges import merge_ranges
import json
import os
import requests
import time
import xml.etree.cElementTree as ET
import pdb


class Module(ModuleTemplate):

    name = "Nessus"

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
        self.options.add_argument(
            "--disable_mitre",
            help="Disable mitre CVE data gathering.",
            action="store_true",

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
                    for ip in IPAddress.get_set(scope_type="active", tool=self.name)
                ]
                cidrs = [cidr.name for cidr in CIDR.get_set(tool=self.name, scope_type="active")]
                domains = [
                    domain.name
                    for domain in Domain.get_set(scope_type="active", tool=self.name)
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
                    
                )

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
            plugin_output = []

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

            db_port, created = Port.objects.get_or_create(
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

            cwe_ids = [c.text for c in tag.findall("cwe")]
            references = [c.text for c in tag.findall("see_also")]

            if not Vulnerability.objects.all().filter(name=findingName):
                db_vuln, created = Vulnerability.objects.get_or_create(
                    name=findingName,
                    severity=severity,
                    description=description,
                    remediation=solution,
                )
                
                db_vuln.ports.add(db_port)
                db_vuln.exploitable = exploitable
                if exploitable:
                    display_new("exploit available for " + findingName)

                if vuln_refs:
                    db_vuln.exploit_reference = vuln_refs

            else:
                db_vuln = Vulnerability.objects.get(name=findingName)
                db_vuln.ports.add(db_port)
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
            db_vuln.meta['CWEs'] = cwe_ids
            db_vuln.meta['Refs'] = references
            
            if tag.find("plugin_output") is not None:
                
                plugin_output = tag.find("plugin_output").text

                db_output, created = VulnOutput.objects.get_or_create(port = db_port, vulnerability=db_vuln)

                if created:
                    # print("Plugin output added to database")
                    db_output.data = plugin_output
                    db_output.save()
                      
                # if not db_vuln.meta.get('plugin_output', False):
                #     db_vuln.meta['plugin_output'] = {}
                # if not db_vuln.meta['plugin_output'].get(ip.ip_address, False):
                #     db_vuln.meta['plugin_output'][ip.ip_address] = {}

                # if not db_vuln.meta['plugin_output'][ip.ip_address].get(port, False):
                #     db_vuln.meta['plugin_output'][ip.ip_address][port] = []

                # if plugin_output not in db_vuln.meta['plugin_output'][ip.ip_address][port]:
                
                #     db_vuln.meta['plugin_output'][ip.ip_address][port].append(plugin_output)
                

            if not self.args.disable_mitre:
                for cve in cves:
                    if not CVE.objects.all().filter(name=cve):
                        try:
                            
                            url = 'https://nvd.nist.gov/vuln/detail/{}/'
                            res = requests.get(url.format(cve)).text

                            cveDescription = res.split('<p data-testid="vuln-description">')[1].split('</p>')[0]
                            if 'vuln-cvssv3-base-score' in res:
                                cvss = float(res.split('<span data-testid="vuln-cvssv3-base-score">')[1].split('</span>')[0].strip()) 
                            else:
                                cvss = float(res.split('<span data-testid="vuln-cvssv2-base-score">')[1].split('</span>')[0].strip()) 

                        
                            cveDescription = res["summary"]
                            cvss = float(res["cvss"])

                        except Exception:
                            cveDescription = ""
                            cvss = 0.0

                        if not CVE.objects.all().filter(name=cve):
                            db_cve, created = CVE.objects.get_or_create(
                                name=cve,
                                description=cveDescription,
                                temporal_score=cvss,
                            )
                            db_cve.vulnerability_set.add(db_vuln)
                        else:
                            db_cve = CVE.objects.get(name=cve)
                            if (
                                db_cve.description is None
                                and cveDescription is not None  # noqa: W503
                            ):
                                db_cve.description = cveDescription
                            if db_cve.temporal_score is None and cvss is not None:
                                db_cve.temporal_score = cvss
                            db_cve.vulnerability_set.add(db_vuln)

    def process_data(self, nFile, args):
        display("Reading " + nFile)
        tree = ET.parse(nFile)
        root = tree.getroot()
        self.args = args
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

                ip, created = IPAddress.objects.get_or_create(ip_address=hostIP, defaults={'active_scope':True, 'passive_scope':True})

                if hostname and '.' in hostname: # Filter out the random hostnames that aren't fqdns
                    domain, created = Domain.objects.get_or_create(name=hostname)

                    if ip not in domain.ip_addresses.all():
                        ip.add_tool_run(tool=self.name)
                        domain.ip_addresses.add(ip)
                        domain.add_tool_run(tool=self.name)


                if os:
                    for o in os:
                        if not ip.os:
                            ip.os = o
                        else:
                            if o not in ip.os.split(" OR "):
                                ip.os += " OR " + o

                self.getVulns(ip, ReportHost)
                

        return
