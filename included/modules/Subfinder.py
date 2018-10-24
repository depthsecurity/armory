#!/usr/bin/env python
from database.repositories import DomainRepository, BaseDomainRepository, IPRepository
from included.ModuleTemplate import ToolTemplate
from included.utilities import get_domain_ip
import io
import os


class Module(ToolTemplate):
    name = "Subfinder"
    binary_name = "subfinder"

    def __init__(self, db):
        self.db = db
        self.BaseDomains = BaseDomainRepository(db, self.name)
        self.Domains = DomainRepository(db, self.name)
        self.IPs = IPRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()
        self.options.add_argument(
            "-a", "--bruteforce-all", help="Brute-force subdomains."
        )
        self.options.add_argument(
            "-d", "--domain", help="Domain to run subfinder against."
        )
        self.options.add_argument(
            "-dL",
            "--domain-list",
            help="Read in a list of domains within the given file.",
        )
        self.options.add_argument(
            "-i",
            "--db_domains",
            help="Import the domains from the database.",
            action="store_true",
        )
        self.options.add_argument(
            "-r",
            "--resolvers",
            help="A list of resolvers(comma-separated) or a file containing a list of resolvers.",
        )
        self.options.add_argument(
            "--rescan", help="Overwrite files without asking", action="store_true"
        )
        self.options.add_argument(
            "-w", "--wordlist", help="The wordlist for when bruteforcing is selected."
        )

    def get_targets(self, args):
        targets = []
        outpath = ""
        if args.output_path:
            if not os.path.exists(args.output_path):
                os.makedirs(args.output_path)
            outpath = args.output_path
        if args.domain or args.db_domains:
            self.db_domain_file = self.__get_tempfile(args.domain, args)
            out_file = "database_domains.subfinder"
            if args.domain:
                created, domain = self.BaseDomains.find_or_create(domain=args.domain)
                out_file = os.path.join(outpath, "{}.subfinder".format(args.domain))
            if not self.db_domain_file:
                return targets
            targets.append({"target": self.db_domain_file, "output": out_file})
        elif args.domain_list:
            domains = io.open(args.domain_list, encoding="utf-8").read().split("\n")
            for d in domains:
                if d:
                    created, domain = self.BaseDomains.find_or_create(domain=d)
            targets.append(
                {
                    "target": args.domain_list,
                    "output": os.path.join(
                        outpath, "{}.subfinder".format(args.domain_list)
                    ),
                }
            )
        return targets

    def build_cmd(self, args):
        if args.binary:
            cmd = "{} ".format(args.binary)
        else:
            cmd = "{} ".format(self.binary_name)
        cmd = "{} -o {} -dL {}".format(cmd, "{output}", "{target}")
        return cmd

    def process_output(self, targets):
        for target in targets:
            with io.open(target["output"], encoding="utf-8") as fd:
                for line in fd:
                    domain = line.strip()
                    ips = get_domain_ip.run(domain)
                    ip_obj = None
                    _, dom = self.Domains.find_or_create(domain=domain)
                    if ips:
                        for ip in ips:
                            _, ip_obj = self.IPs.find_or_create(ip_address=ip)
                            if ip_obj:
                                dom.ip_addresses.append(ip_obj)
                        dom.save()
        self.BaseDomains.commit()
        self.IPs.commit()

    def post_run(self, args):
        # Remove the temporary db file if it was created.
        if getattr(self, "db_domain_file", None):
            try:
                os.unlink(self.db_domain_file)
            except IOError as e:
                print("Failed to remove the Subfinder db temp file: '{}'.".format(e))

    def __get_tempfile(self, domain=None, args=None):
        # Create a temporary file and place all of the current database domains within the file.
        from tempfile import NamedTemporaryFile

        with NamedTemporaryFile(delete=False) as fd:
            if domain:
                fd.write("{}\n".format(domain).encode("utf-8"))
            else:
                # Go through the database and grab the domains adding them to the file.
                if args.rescan:
                    domains = self.BaseDomains.all(passive_scope=True)
                else:
                    domains = self.BaseDomains.all(tool=self.name, passive_scope=True)
                if domains:
                    for domain in domains:
                        fd.write("{}\n".format(domain).encode("utf-8"))
                else:
                    return None
        return fd.name
