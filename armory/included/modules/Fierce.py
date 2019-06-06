from armory.included.ModuleTemplate import ToolTemplate
from armory.database.repositories import BaseDomainRepository, DomainRepository
from armory.included.utilities.color_display import display_error
import os
import re


class Module(ToolTemplate):
    '''
    This module uses Fierce, a Perl based domain brute forcing tool. It can be installed from 

    https://github.com/davidpepper/fierce-domain-scanner

    '''
    name = "Fierce"
    binary_name = "fierce"

    def __init__(self, db):
        self.db = db
        self.BaseDomain = BaseDomainRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()
        self.options.add_argument("-d", "--domain", help="Target domain for Fierce")
        self.options.add_argument("-f", "--file", help="Import domains from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import domains from database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Force rescan of already scanned domains",
            action="store_true",
        )

    def get_targets(self, args):

        targets = []

        if args.domain:
            targets.append(args.domain)

        if args.file:
            domains = open(args.file).read().split("\n")
            for d in domains:
                if d:
                    targets.append(d)

        if args.import_database:
            if args.rescan:
                domains = self.BaseDomain.all(scope_type="passive")
            else:
                domains = self.BaseDomain.all(tool=self.name, scope_type="passive")
            for domain in domains:
                targets.append(domain.domain)

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
            res.append({"target": t, "output": os.path.join(self.path, t + ".txt")})

        return res

    def build_cmd(self, args):

        command = self.binary
        command += " -dns {target} -file {output} "

        if args.tool_args:
            command += args.tool_args

        return command

    def process_output(self, cmds):

        for c in cmds:
            target = c["target"]
            output_path = c["output"]

            try:
                fierceOutput = open(output_path).read()
            except IOError:
                display_error(
                    "The output file for {} was not found. If fierce timed out, but is still running, you can run this tool again with the --no_binary flag to just grab the file.".format(
                        target
                    )
                )
                continue

            domains = []

            if "Now performing" in fierceOutput:
                hosts = re.findall(
                    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\t.*$",
                    fierceOutput,
                    re.MULTILINE,
                )
                if hosts:
                    for host in hosts:
                        # print host
                        domain = (
                            host.split("\t")[1].lower().replace("www.", "").rstrip(".")
                        )
                        if domain not in domains:
                            domains.append(domain)

            elif "Whoah, it worked" in fierceOutput:
                print("Zone transfer found!")
                hosts = re.findall(
                    r".*\tA\t\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                    fierceOutput,
                    re.MULTILINE,
                )
                if hosts:
                    for host in hosts:
                        domain = (
                            host.split("\t")[0].lower().replace("www.", "").rstrip(".")
                        )
                        if domain not in domains:
                            domains.append(domain)

            else:
                display_error(
                    "No results found in {}.  If fierce timed out, but is still running, you can run this tool again with the --no_binary flag to just grab the file.".format(
                        output_path
                    )
                )

            if domains:
                for _domain in domains:

                    created, domain = self.Domain.find_or_create(domain=_domain)
