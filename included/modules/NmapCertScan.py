#!/usr/bin/python

from database.repositories import PortRepository
from included.ModuleTemplate import ToolTemplate
import subprocess
from included.utilities import which
import shlex
import os
import pdb
import xmltodict
from multiprocessing import Pool as ThreadPool
import glob
from included.utilities.color_display import display, display_error


class Module(ToolTemplate):
    """
    Runs nmap on all web hosts to pull certs and add them to the database
    """

    name = "NmapCertScan"
    binary_name = "nmap"

    def __init__(self, db):
        self.db = db
        self.Port = PortRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-s",
            "--rescan",
            help="Rescan domains that have already been scanned",
            action="store_true",
        )

    def get_targets(self, args):

        targets = []
        if args.rescan:
            services = self.Port.all(service_name="https")
        else:
            services = self.Port.all(tool=self.name, service_name="https")

        for s in services:
            if s.ip_address.in_scope:
                port = s.port_number
                targets.append(
                    {
                        "port": port,
                        "target": s.ip_address.ip_address,
                        "service_id": s.id,
                    }
                )
                for d in s.ip_address.domains:
                    targets.append(
                        {"port": port, "target": d.domain, "service_id": s.id}
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

        for t in targets:
            file_path = os.path.join(output_path, "%s_%s-ssl.xml" % (t["target"], port))

            t["output"] = file_path
        # pdb.set_trace()
        return targets

    def build_cmd(self, args):

        cmd = self.binary + " -p {port} --script=ssl-cert -oX {output} {target} "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def process_output(self, cmds):

        for data in cmds:

            try:
                xmldata = xmltodict.parse(open(data["output"]).read())

                cert = xmldata["nmaprun"]["host"]["ports"]["port"]["script"]["@output"]

                if cert:
                    # print("Cert found: {}".format(cert))
                    svc = self.Port.all(id=data["service_id"])[0]

                    # pdb.set_trace()
                    if not svc.meta.get("sslcert", False):
                        svc.meta["sslcert"] = {}
                    svc.meta["sslcert"][data["target"]] = cert
                    print(
                        "Cert added to {} for {}".format(
                            data["service_id"], data["target"]
                        )
                    )
                    svc.save()

            except Exception as e:
                display_error("File not valid: {}\nError: {}".format(data["output"], e))

        self.Port.commit()
