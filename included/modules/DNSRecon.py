from included.ModuleTemplate import ToolTemplate
from database.repositories import (
    BaseDomainRepository,
    DomainRepository,
    ScopeCIDRRepository,
)
from included.utilities.color_display import display, display_error
import os
import subprocess
import json
import pdb


class Module(ToolTemplate):

    name = "DNSRecon"
    binary_name = "dnsrecon"
    """
    This module runs DNSRecon on a domain or set of domains. This will extract found DNS entries.
    It can also run over IP ranges, looking for additional domains in the PTR records.
    """

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.ScopeCIDR = ScopeCIDRRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()
        self.options.add_argument("-d", "--domain", help="Target domain for dnsRecon")
        self.options.add_argument("-f", "--file", help="Import domains from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import domains from database",
            action="store_true",
        )
        self.options.add_argument("-r", "--range", help="Range to scan for PTR records")
        self.options.add_argument(
            "-R",
            "--import_range",
            help="Import CIDRs from in-scope ranges in database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan", help="Rescan domains already scanned", action="store_true"
        )
        # self.options.add_argument('--import_output_xml', help="Import XML file")
        # self.options.add_argument('--import_output_json', help="Import json file")

    def get_targets(self, args):

        targets = []
        if args.domain:
            created, domain = self.BaseDomain.find_or_create(
                domain=args.domain, passive_scope=True
            )
            targets.append(domain.domain)

        elif args.file:
            domains = open(args.file).read().split("\n")
            for d in domains:
                if d:
                    created, domain = self.BaseDomain.find_or_create(
                        domain=d, passive_scope=True
                    )
                    targets.append(domain.domain)

        elif args.import_database:
            if args.rescan:
                domains = self.BaseDomain.all(scope_type="passive")
            else:
                domains = self.BaseDomain.all(scope_type="passive", tool=self.name)
            for domain in domains:
                targets.append(domain.domain)

        elif args.range:
            targets.append(args.range)

        elif args.import_range:
            cidrs = self.ScopeCIDR.all(tool=self.name)

            for cidr in cidrs:
                targets.append(cidr.cidr)

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

        res = []
        for t in targets:
            res.append(
                {
                    "target": t,
                    "output": os.path.join(self.path, t.replace("/", "_") + ".json"),
                }
            )

        return res

    def build_cmd(self, args):
        command = self.binary

        if args.domain or args.file or args.import_database:

            command += " -d {target} -j {output} "

        else:
            command += " -s -r {target} -j {output} "

        if args.tool_args:
            command += args.tool_args

        return command

    def process_output(self, cmds):

        for c in cmds:
            target = c["target"]
            output_path = c["output"]

            try:
                res = json.loads(open(output_path).read())
            except IOError:
                display_error("DnsRecon failed for {}".format(target))

            if " -d " in res[0]["arguments"]:
                created, dbrec = self.Domain.find_or_create(domain=target)
                dbrec.dns = res
                dbrec.save()

            for record in res:
                domain = None

                if record.get("type") == "A" or record.get("type") == "PTR":
                    domain = record.get("name").lower().replace("www.", "")

                elif record.get("type") == "MX":
                    domain = record.get("exchange").lower().replace("www.", "")

                elif record.get("type") == "SRV" or record.get("type" == "NS"):
                    domain = record.get("target").lower().replace("www.", "")

                elif record.get("type") == "SOA":
                    domain = record.get("mname").lower().replace("www.", "")

                if domain:
                    created, domain_obj = self.Domain.find_or_create(domain=domain)

        self.Domain.commit()
