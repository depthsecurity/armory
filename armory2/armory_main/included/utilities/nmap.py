from armory2.armory_main.models import (     
    BaseDomain,
    Domain,
    IPAddress,
    Port,
    CIDR,
    Vulnerability,
    CVE, )

import datetime
import json
import os
import re
import tempfile
import requests
import sys
import pdb
import xml.etree.ElementTree as ET


def import_nmap(
    filename, args
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

        ip, created = IPAddress.objects.get_or_create(ip_address=hostIP)

        for hostname in host.findall("hostnames/hostname"):
            hostname = hostname.get("name")
            hostname = hostname.lower().replace("www.", "")

            # reHostname = re.search(
            #     r"\d{1,3}\-\d{1,3}\-\d{1,3}\-\d{1,3}", hostname
            # )  # attempt to not get PTR record
            # if not reHostname:

            domain, created = Domain.objects.get_or_create(name=hostname)
            if ip not in domain.ip_addresses.all():
                domain.ip_addresses.add(ip)
                domain.save()

        for port in host.findall("ports/port"):

            if port.find("state").get("state"):
                portState = port.find("state").get("state")
                hostPort = port.get("portid")
                portProto = port.get("protocol")
                # pdb.set_trace()
                args.filter_ports = []

                if not args.filter_ports or int(hostPort) not in [
                    int(p) for p in args.filter_ports.split(",")
                ]:
                    db_port, created = Port.objects.get_or_create(
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

                    if not db_port.meta.get('nmap_scripts'):
                        db_port.meta['nmap_scripts'] = {}
                    for script in port.findall(
                        "script"
                    ):  # just getting commonName from cert
                        db_port.meta['nmap_scripts'][script.get("id")] = script.get('output')
                        # print(script.get("id"))
                        if script.get("id") == "ssl-cert":
                            db_port.cert = script.get("output")
                            cert_domains = get_domains_from_cert(
                                script.get("output")
                            )

                            for hostname in cert_domains:
                                hostname = hostname.lower().replace("www.", "")
                                created, domain = Domain.objects.get_or_create(
                                    name=hostname
                                )
                                if created:
                                    print("New domain found: %s" % hostname)

                        elif script.get("id") == "vulners":
                            print(
                                "Gathering vuln info for {} : {}/{}\n".format(
                                    hostIP, portProto, hostPort
                                )
                            )
                            parseVulners(script.get("output"), db_port)

                        elif script.get("id") == "banner":
                            info["banner"] = script.get("output")

                        elif script.get("id") == "http-headers":

                            httpHeaders = script.get("output")
                            httpHeaders = httpHeaders.strip().split("\n")
                            keepHeaders = parseHeaders(httpHeaders)
                            info["http-headers"] = keepHeaders

                        elif script.get("id") == "http-auth":
                            info["http-auth"] = script.get("output")

                        elif script.get("id") == "http-title":
                            info["http-title"] = script.get("output")

                    db_port.info = info
                    db_port.save()

        

def parseVulners(scriptOutput, db_port):
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

        if not CVE.objects.all().filter(name=cve):
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

                if not Vulnerability.objects.filter(name=findingName):
                    # print "Creating", findingName
                    db_vuln, created = Vulnerability.objects.get_or_create(
                        name=findingName,
                        severity=severity,
                        description=cveDescription,
                    )
                    db_vuln.port.add(db_port)
                    db_vuln.exploitable = exploitable
                    if vuln_refs:
                        db_vuln.exploit_reference = {"edb-id": vuln_refs}
                        db_vuln.save()

                else:
                    # print "modifying",findingName
                    db_vuln = Vulnerability.objects.get(name=findingName)
                    db_vuln.ports.add(db_port)
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

                if not CVE.objects.filter(name=cve):
                    db_cve, created = CVE.objects.get_or_create(
                        name=cve, description=cveDescription, temporal_score=cvss
                    )
                    db_cve.vulnerability_set.add(db_vuln)
                    db_cve.save()

                else:
                    db_cve = CVE.objects.get(name=cve)
                    db_cve.vulnerability_set.add(db_vuln)
                    db_cve.save()

                
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
            db_cve = CVE.objects.get(name=cve)
            for db_vulns in db_cve.vulnerabilities:
                if db_port not in db_vulns.ports:
                    db_vulns.ports.add(db_port)
    return

def get_domains_from_cert(cert):
    # Shamelessly lifted regex from stack overflow
    regex = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"

    domains = list(set([d for d in re.findall(regex, cert) if "*" not in d]))

    return domains

def parseHeaders(httpHeaders):
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