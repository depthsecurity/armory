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

from armory2.armory_main.models.network import get_cidr_info
from armory2.armory_main.included.utilities.color_display import display, display_new, display_error
from armory2.armory_main.included.utilities.nessus import NessusRequest
from armory2.armory_main.included.utilities.sort_ranges import merge_ranges
from armory2.armory_main.included.utilities.network_tools import validate_ip

import json
import os
import requests
import time
import xml.etree.cElementTree as ET
import pdb
from netaddr import IPNetwork, IPAddress as IPAddr
from datetime import datetime


def gd(orig):
    now = datetime.now()
    diff = now - orig
    print(f"{diff.seconds}.{diff.microseconds}")


class Module(ModuleTemplate):

    name = "Nessus"
    orig = datetime.now()

    # Mappings to cache db ids for ports and vulns - makes it quicker later

    ports = []
    vulns = {}
    vulnobjects = {}
    ip_data = {}
    cve_map = []
    cve_data = {}

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
        # display("Processing IP: {}".format(ip))
        ip_data = {}
        vuln_data = []
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
            port_id = f"{port}|{proto}"

            if not ip_data.get(port_id):
                ip_data[port_id] = {'service_name':""}

            # db_port, created = Port.objects.get_or_create(
            #     port_number=port, status="open", proto=proto, ip_address_id=ip
            # )
            if ip_data[port_id]['service_name'] == "http":
                if portName == "https":
                    ip_data[port_id]['service_name'] = portName
            elif ip_data[port_id]['service_name'] == "https":
                pass
            else:
                ip_data[port_id]['service_name'] = portName
            

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
                if not ip_data[port_id].get('info'):
                    ip_data[port_id]['info'] = {findingName: nessCheck}
                else:
                    ip_data[port_id]['info'][findingName] = nessCheck

                

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
                    
            if self.vulns.get(findingName):
                db_vuln = self.vulns[findingName]


            
            else:
                db_vuln, created = Vulnerability.objects.get_or_create(
                        name=findingName,
                        defaults={'severity':severity,
                        'description':description,
                        'remediation':solution,
                        'exploitable' : exploitable,
                        }
                    )
                self.vulns[findingName] = db_vuln
                # if exploitable:
                #     display_new("exploit available for " + findingName)

            if [f"{ip}|{port}|{proto}", db_vuln.id] not in vuln_data:

                vuln_data.append([f"{ip}|{port}|{proto}", db_vuln.id])
            #db_vuln.ports.add(db_port)
            
            

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

                self.vulnobjects[f"{ip}|{port}|{proto}|{db_vuln.id}"] = plugin_output

                # db_output, created = VulnOutput.objects.get_or_create(port = db_port, vulnerability=db_vuln)

                # if created:
                #     # print("Plugin output added to database")
                #     db_output.data = plugin_output
                #     db_output.save()
                      
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
                    if not self.cve_data.get(cve):

                    # if not CVE.objects.all().filter(name=cve):
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

                        # if not CVE.objects.all().filter(name=cve):
                        self.cve_data[cve] = [cveDescription, cvss]

                    self.cve_map.append(f"{cve}|{db_vuln.id}")
                            # db_cve.vulnerability_set.add(db_vuln)
                        # else:
                        #     db_cve = CVE.objects.get(name=cve)
                        #     if (
                        #         db_cve.description is None
                        #         and cveDescription is not None  # noqa: W503
                        #     ):
                        #         db_cve.description = cveDescription
                        #     if db_cve.temporal_score is None and cvss is not None:
                        #         db_cve.temporal_score = cvss
                        #     db_cve.vulnerability_set.add(db_vuln)

        self.ip_data[ip] = ip_data
        self.ports += vuln_data

    def process_data(self, nFile, args):
        
        display("Reading " + nFile)
        tree = ET.parse(nFile)
        root = tree.getroot()
        current_ips = set([i.ip_address for i in IPAddress.objects.all()])
        current_domains = set([d.name for d in Domain.objects.all()])

        new_ips = []
        new_ip_list = []
        new_domains = {}
        just_domains = []

        self.args = args
        print("Preprocessing IPs/Domains")
        for ReportHost in root.iter("ReportHost"):
            hostname = ""
            hostIP = ""
            os = ""

            for HostProperties in ReportHost.iter("HostProperties"):
                for tag in HostProperties:
                    if tag.get("name") == "host-ip":
                        hostIP = tag.text

                    if tag.get("name") == "host-fqdn":
                        hostname = tag.text.lower()
                        hostname = hostname.replace("www.", "")

                    if tag.get("name") == "operating-system":
                        os = " OR ".join(tag.text.split("\n"))
            # pdb.set_trace()


            if hostIP and hostIP not in current_ips:
                res = validate_ip(hostIP)
                if res == "ipv4":
                    v = 4
                else:
                
                    v = 6
                new_ips.append(IPAddress(ip_address=hostIP, active_scope=True, passive_scope=True, version=v, os=os))
                new_ip_list.append(hostIP)
              
            if hostIP and hostname and '.' in hostname: # Filter out the random hostnames that aren't fqdns
                if not new_domains.get(hostIP):
                    new_domains[hostIP] = []

                hostname = ''.join([i for i in hostname.lower() if i in 'abcdefghijklmnopqrstuvwxyz.-0123456789'])
                
                if hostname not in current_domains:
                    new_domains[hostIP].append(hostname)
                    if hostname not in just_domains:
                        just_domains.append(hostname)
           
                
        cidrs = {c.name: c.id for c in CIDR.objects.all()}

        for instance in new_ips:
            found = False
            for c, v in cidrs.items():
                if instance.ip_address in IPNetwork(c):
                    
                    instance.cidr__id = v
                    found = True
                    break
            
            cidr_data, org_name = get_cidr_info(instance.ip_address)
            cidr, created = CIDR.objects.get_or_create(name=cidr_data, defaults={'org_name':org_name})
            instance.cidr = cidr
            cidrs[cidr.name] = cidr.id

        
        display("Bulk creating IPs...")
        IPAddress.objects.bulk_create(new_ips)
        domain_objs = []

        base_domains = { bd.name: bd.id for bd in BaseDomain.objects.all()}

        for d in just_domains:
            
            base_domain = '.'.join(d.split('.')[-2:])

            if not base_domains.get(base_domain):
                bd = BaseDomain(name=base_domain, active_scope = False, passive_scope = True)
                bd.save()

                bd_id = bd.id
                base_domains[bd.name] = bd.id

            else:
                bd_id = base_domains[base_domain]

            domain_objs.append(Domain(name=d, basedomain_id=bd_id))
        display("Bulk creating domains...")
        Domain.objects.bulk_create(domain_objs)

        current_ips = {i.ip_address:i.id for i in IPAddress.objects.all()}
        current_domains = {d.name:d.id for d in Domain.objects.all()}

        ThroughModel = Domain.ip_addresses.through

        many_objs = []

        for i, v in new_domains.items():

            ip_id = current_ips[i]

            for d in v:
                if d in just_domains or i in new_ip_list:
                    d_id = current_domains[d]

                    many_objs.append(ThroughModel(domain_id=d_id, ipaddress_id=ip_id))

        display("Bulk gluing them together")
        ThroughModel.objects.bulk_create(many_objs)

        
        for ReportHost in root.iter("ReportHost"):
            
            for HostProperties in ReportHost.iter("HostProperties"):
                for tag in HostProperties:
                    if tag.get("name") == "host-ip":
                        hostIP = tag.text

            
            if hostIP:  # apparently nessus doesn't always have an IP to work with...

                ip_id = current_ips[hostIP]

                
                self.getVulns(ip_id, ReportHost)
                

        
        ports = []

        current_ports = [f"{p.ip_address_id}|{p.port_number}|{p.proto}" for p in Port.objects.all()]

        

        for i, v in self.ip_data.items():
            for k, data in v.items():
                if f"{i}|{k}" not in current_ports:
                    ports.append(Port(ip_address_id=i, port_number=k.split('|')[0], proto=k.split('|')[1], service_name=data['service_name']))
        display(f"Bulk loading {len(ports)} Ports")            
        Port.objects.bulk_create(ports)

        all_ports = {f"{p.ip_address_id}|{p.port_number}|{p.proto}":p.id for p in Port.objects.all()}
        
        display("Gluing in Vulnerabilities")

        ThroughModel = Vulnerability.ports.through

        vuln_port_current = [f"{v.vulnerability_id}|{v.port_id}" for v in ThroughModel.objects.all()]
        port_vuln_data = []

        for p, v in self.ports:
            if f"{v}|{all_ports[p]}" not in vuln_port_current:
                
                port_vuln_data.append(ThroughModel(port_id=all_ports[p], vulnerability_id=v))
        

        ThroughModel.objects.bulk_create(port_vuln_data)

        

        vuln_outputs = []

        vulnobject_data = set([f"{v.port.ip_address_id}|{v.port.port_number}|{v.port.proto}|{v.vulnerability_id}" for v in VulnOutput.objects.all()])


        for k, v in self.vulnobjects.items():
            if k not in vulnobject_data:
                port_id = all_ports['|'.join(k.split('|')[:3])]
                vuln_id = k.split('|')[-1]

                vuln_outputs.append(VulnOutput(port_id=port_id, vulnerability_id=vuln_id, data=v))

        display(f"Adding in {len(vuln_outputs)} output data")
        VulnOutput.objects.bulk_create(vuln_outputs)

        display("Attaching CVEs")

        cve_current = [c.name for c in CVE.objects.all()]
        new_cves = []

        for k, v in self.cve_data.items():
            if k not in cve_current:
                new_cves.append(CVE(name=k, description=v[0], temporal_score=v[1]))

        CVE.objects.bulk_create(new_cves)

        display("And finally gluing them to the vulns")

        cve_current = {c.name :c.id for c in CVE.objects.all()}
        ThroughModel = Vulnerability.cves.through

        cve_through = set([f"{c.cve_id}|{c.vulnerability_id}" for c in ThroughModel.objects.all()])

        cve_glue = []
        for m in list(set(self.cve_map)):

            cve_id = cve_current[m.split('|')[0]]
            vuln_id = m.split('|')[1]
            if f"{cve_id}|{vuln_id}" not in cve_through:

                cve_glue.append(ThroughModel(cve_id=cve_id, vulnerability_id=vuln_id))

        ThroughModel.objects.bulk_create(cve_glue)


        # Now to add all of this data into the database


        return
