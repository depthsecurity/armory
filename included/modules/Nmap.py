from included.ModuleTemplate import ModuleTemplate
from database.repositories import BaseDomainRepository, DomainRepository, IPRepository, PortRepository, ScopeCIDRRepository, VulnRepository, CVERepository
from included.utilities import which, get_whois
import os
import subprocess
import pdb
import xml.etree.ElementTree as ET
import re
from tld import get_tld
import tempfile
import requests
import json

class Module(ModuleTemplate):

    name = "Nmap"

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
        self.options.add_argument('--hosts', help="Things to scan separated by a space. DO NOT USE QUOTES OR COMMAS", nargs='+')
        self.options.add_argument('--hosts_file', help="File containing hosts", action="store_true")
        self.options.add_argument('--hosts_database', help="Use unscanned hosts from the database", action="store_true")
        self.options.add_argument('--import_file', help="Import nmap XML file")
        self.options.add_argument('-A', help="OS and service info", action="store_true")
        self.options.add_argument('-o', '--output_path', help="Relative directory to store Nmap XML output name", default="nmap")
        self.options.add_argument('-nf', '--nFile', help="Nmap XML output name")
        self.options.add_argument('-T', '--timing', help="Set timing template (higher is faster)", default="4", type=str)
        self.options.add_argument('--scripts', help="Nmap scripts",default='ssl-cert,http-headers,http-methods,http-auth,http-title,http-robots.txt,banner')
        self.options.add_argument('-p', help="Comma separate ports to scan", default="21,22,23,25,80,110,443,467,587,8000,8080,8081,8082,8443,8008,1099,5005,9080,8880,8887,7001,7002,16200")
        self.options.add_argument('-Pn', help="Disable ping", action="store_true", default=False)
        self.options.add_argument('-sS', help='Syn scan (default)', action="store_true", default=True)
        self.options.add_argument('-sT', help='TCP scan', action="store_true", default=False)
        self.options.add_argument('-sU', help='UDP scan', action="store_true", default=False)
        self.options.add_argument('-OS', help='Enable OS detection', action="store_true", default=False)
        self.options.add_argument("--open", help="Only show open ports", action="store_true", default=False)
        self.options.add_argument("--force", help="Overwrite files without asking", action="store_true")
        self.options.add_argument('--interactive', help="Prompt to store domains not in Base Domains already", default=False, action="store_true")
        self.options.add_argument('--internal', help="Store domains not in Base Domains already", action="store_true")

    def run(self, args):
        if args.binary:
            if os.path.exists(args.binary):
                command = args.binary+" "
            else:
                exit("Specified binary doesn't exist. Quitting now")
        else:
            if not which.run('nmap'):
                exit("Nmap is not globally accessible. Quitting now")
            else:
                command = "nmap "


        if args.output_path[0] == "/":
            self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
        else:
            self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        file_name = ""

        if args.hosts:
            if type(args.hosts) == list:
                hosts = args.hosts
            else:
                hosts = [args.hosts]
            _, file_name = tempfile.mkstemp()
            open(file_name, 'w').write('\n'.join(hosts))
            
        elif args.hosts_database:
            hosts = [h.ip_address for h in self.IPAddress.all(tool=self.name)]
            hosts += [h.cidr for h in self.ScopeCIDR.all(tool=self.name)]
            _, file_name = tempfile.mkstemp()
            open(file_name, 'w').write('\n'.join(hosts))
        elif args.hosts_file:
            file_name = args.hosts_file

        if file_name:
            self.execute_nmap(args, file_name, command)

        elif args.import_file:
            self.import_nmap(args.import_file, args)

    def execute_nmap(self, args, host_file, command):

        if args.nFile:
            nFile = os.path.join(self.path,args.nFile)

        else:
            nFile = os.path.join(self.path, "nmap-scan.xml")
            # if type(hosts) == list:
            #     nFile = os.path.join(self.path,"nmaped_"+",".join(hosts).replace("/","_"))

            # else:
            #     nFile = os.path.join(self.path,"nmaped_"+hosts.replace("/","_").replace(" ",","))
        
        if os.path.isfile(nFile) and not args.force:
            print (nFile,"exists.")
            answered = False
            
            while answered == False:
                rerun = raw_input("Would you like to [r]un nmap again and overwrite the file, [p]arse the file, or change the file [n]ame? ")
                if rerun.lower() == 'r':
                    answered = True
                
                elif rerun.lower() == 'p':
                    answered = True
                    return nFile

                elif rerun.lower() == 'n':
                    new = False
                    while new == False:
                        newFile = raw_input("enter a new file name: ")
                        if not os.path.exists(path+newFile):
                            nFile = path+newFile
                            answered = True
                            new = True
                        else:
                            print "That file exists as well"
                else:
                    "Please enter \'r\' to run nmap, \'p\' to parse the file"

        if args.sS and args.sT:
            technique = "-sT "

        else:
            technique = "-sS "

        if args.sU:
            technique += "-sU "

        if args.A:
            technique += "-A "
        command += technique

        command += "-T"+str(args.timing)+" "

        if args.Pn:
            command += "-Pn "
        
        if args.open:
            command += "--open "

        if args.OS:
            command += "-O "

        command += "--script "+args.scripts+" "

        command += "-p "+args.p+" "

        command += " -iL %s " % host_file

        command += "-oX "+nFile

        if (args.sS and not args.sT) or args.OS:
            if os.geteuid() != 0:
                #exit("You need to have root privileges to run a Syn scan and OS detection.\nPlease try again, this time using 'sudo'. Exiting.")
                command = "sudo " + command
        scan = subprocess.Popen(command, shell=True).wait()
        self.import_nmap(nFile, args)
        return nFile
        
    def parseHeaders(self, httpHeaders):
        bsHeaders = ['Pragma','Expires','Date','Transfer-Encoding','Connection','X-Content-Type-Options', 'Cache-Control', 'X-Frame-Options', 'Content-Type', 'Content-Length', '(Request type']
        keepHeaders = {}
        for i in range(0, len(httpHeaders)):
            if httpHeaders[i].strip() != '' and httpHeaders[i].split(":")[0].strip() not in " ".join(bsHeaders):
                hName = httpHeaders[i].split(":")[0].strip()
                hValue = "".join(httpHeaders[i].split(":")[1:]).strip()
                keepHeaders[hName] = hValue
                
        if keepHeaders == {}:
            keepHeaders = ""
            
        return keepHeaders


    def import_nmap(self, filename, args): #domains={}, ips={}, rejects=[] == temp while no db
        nFile = filename
        
        try:
            tree = ET.parse(nFile)
            root = tree.getroot()
            hosts = root.findall("host")

        except:
            print nFile, "doesn't exist somehow...skipping"
            return domains,ips,rejects #needs to be changed for db
        
        tmpNames = []
        tmpIPs = {}     #tmpIps = {'127.0.0.1':['domain.com']} -- not really used; decided to just let nslookup take care of IP info
        skip = []
        

        for host in hosts:
            hostIP = host.find("address").get("addr")
            
            created, ip = self.IPAddress.find_or_create(ip_address=hostIP)


            for hostname in host.findall("hostnames/hostname"):
                hostname = hostname.get("name")
                hostname = hostname.lower().replace("www.","")

                reHostname = re.search(r"\d{1,3}\-\d{1,3}\-\d{1,3}\-\d{1,3}",hostname)  #attempt to not get PTR record
                if not reHostname and not args.internal:
                    
                    created, domain = self.Domain.find_or_create(domain=hostname)
                    if ip not in domain.ip_addresses:
                        domain.ip_addresses.append(ip)
                        domain.save()
                        
                elif not reHostname and args.internal:
                    created, domain = self.Domain.find_or_create(domain=hostname)
                    if ip not in domain.ip_addresses:
                        domain.ip_addresses.append(ip)
                        domain.save()
                #else:
                #    print("IP hostname found? %s" % hostname)

            for port in  host.findall("ports/port"):
                
                if port.find("state").get("state"):
                    portState = port.find("state").get("state")     
                    hostPort = port.get("portid")                   
                    portProto = port.get("protocol")                
                    
                    created, db_port = self.Port.find_or_create(port_number = hostPort, status=portState, proto=portProto, ipaddress=ip)

                    if port.find("service") != None:                
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

                    for script in port.findall("script"):   #just getting commonName from cert 
                        if script.get("id") == "ssl-cert":
                            db_port.cert = script.get('output')
                            cert_domains = self.get_domains_from_cert(script.get('output'))

                            for hostname in cert_domains:
                                hostname = hostname.lower().replace("www.","")
                                created, domain = self.Domain.find_or_create(domain=hostname)
                                if created:
                                    print("New domain found: %s" % hostname)
                            
                        elif script.get("id") == "vulners":
                            print "Gathering vuln info for {} : {}/{}\n".format(hostIP,portProto,hostPort)
                            self.parseVulners(script.get("output"), db_port)

                        elif script.get("id") == "banner":
                            info["banner"] = script.get("output")
                        
                        elif script.get("id") == "http-headers" :
                            
                            httpHeaders = script.get("output")
                            httpHeaders = httpHeaders.strip().split("\n")
                            keepHeaders = self.parseHeaders(httpHeaders)
                            info["http-headers"] = keepHeaders
                        
                        elif script.get("id") == "http-auth":
                            info['http-auth'] = script.get("output")
                            
                        elif script.get("id") == "http-title":
                            info['http-title'] = script.get("output")

                    db_port.info = info
                    db_port.save()


            self.IPAddress.commit()

    def parseVulners(self, scriptOutput, db_port):
        urls = re.findall('(https://vulners.com/cve/CVE-\d*-\d*)', scriptOutput)
        for url in urls:
            vuln_refs = []
            exploitable = False
            cve = url.split("/cve/")[1]
            vulners = requests.get("https://vulners.com/cve/%s" %cve).text
            exploitdb = re.findall('https://www.exploit-db.com/exploits/\d{,7}',vulners)
            for edb in exploitdb:
                exploitable = True

                if edb.split("/exploits/")[1] not in vuln_refs:
                    vuln_refs.append(edb.split("/exploits/")[1])

            if not self.CVE.find(name=cve):
                #print "Gathering CVE info for", cve
                try:
                    res = json.loads(requests.get('http://cve.circl.lu/api/cve/%s' % cve).text)
                    cveDescription = res['summary']
                    cvss = float(res['cvss'])
                    findingName = res['oval'][0]['title']
                    if int(cvss) <= 3:
                        severity = 1

                    elif (int(cvss)/2) == 5:
                        severity = 4

                    else:
                        severity = int(cvss)/2

                    if not self.Vulnerability.find(name=findingName):
                        #print "Creating", findingName
                        created, db_vuln = self.Vulnerability.find_or_create(name=findingName, severity=severity, description=cveDescription)
                        db_vuln.ports.append(db_port)
                        db_vuln.exploitable = exploitable
                        if vuln_refs:
                            db_vuln.exploit_reference = {'edb-id':vuln_refs}
                            db_vuln.save()

                    else:
                        #print "modifying",findingName
                        db_vuln = self.Vulnerability.find(name=findingName)
                        db_vuln.ports.append(db_port)
                        db_vuln.exploitable = exploitable

                        if vuln_refs:
                            db_vuln.exploitable = exploitable
                            if db_vuln.exploit_reference is not None:
                                if 'edb-id' in db_vuln.exploit_reference:
                                    for ref in vuln_refs:
                                        if ref not in db_vuln.exploit_reference['edb-id']:
                                            db_vuln.exploit_reference['edb-id'].append(ref)

                                else:
                                    db_vuln.exploit_reference['edb-id'] = vuln_refs
                            else:
                                db_vuln.exploit_reference= {'edb-id':vuln_refs}
                        
                        db_vuln.save()
                   
                    if not self.CVE.find(name=cve):
                        created, db_cve = self.CVE.find_or_create(name=cve, description=cveDescription,temporal_score=cvss)
                        db_cve.vulnerabilities.append(db_vuln)
                        db_cve.save()

                    else:
                        db_cve = self.CVE.find(name=cve)
                        db_cve.vulnerabilities.append(db_vuln)
                        db_cve.save()

                    self.Vulnerability.commit()
                    self.CVE.commit()
                except:
                    print "something went wrong with the vuln/cve info gathering"
                    if vulners:
                        print "Vulners report was found but no exploit-db was discovered"
                        #"Affected vulners items"
                        #print vulners
                    print "Affected CVE"
                    print cve
                    pass


            else:
                db_cve = self.CVE.find(name=cve)
                for db_vulns in db_cve.vulnerabilities:
                    if db_port not in db_vulns.ports:
                        db_vulns.ports.append(db_port)
        return



    def get_domains_from_cert(self, cert):
        # Shamelessly lifted regex from stack overflow
        regex = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'

        domains = list(set([d for d in re.findall(regex, cert) if '*' not in d]))

        return domains