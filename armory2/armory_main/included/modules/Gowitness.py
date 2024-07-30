#!/usr/bin/python

from armory2.armory_main.models import IPAddress, Domain
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities.get_urls import (
    add_tool_url,
    run,
    add_tools_urls,
    get_port_object,
)
from armory2.armory_main.included.utilities.color_display import display, display_error
from armory2.armory_main.included.utilities.validate_ip import is_ip
import os
import re
import subprocess
import tempfile
from distutils.version import LooseVersion
from time import time
import sys
import json
import pdb
import sqlite3

from armory2.armory_main.models.network import VirtualHost

if sys.version[0] == "3":
    xrange = range


class Module(ToolTemplate):
    """
    This module uses Gowitness to take a screenshot of any discovered web servers. It can be installed from:

    https://github.com/sensepost/gowitness

    """

    name = "Gowitness"
    binary_name = "gowitness"
    docker_name = "gowitness"
    docker_repo = "https://github.com/sensepost/gowitness.git"
    docker_run_binary = "gowitness"
    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from the database",
            action="store_true",
        )
        self.options.add_argument("-f", "--import_file", help="Import URLs from file")
        self.options.add_argument(
            "--group_size",
            help="How many hosts per group (default 250)",
            type=int,
            default=250,
        )
        self.options.add_argument(
            "--rescan",
            help="Rerun gowitness on systems that have already been processed.",
            action="store_true",
        )
        self.options.add_argument(
            "--scan_folder",
            help="Generate list of URLs based off of a folder containing GobusterDir output files",
        )
        self.options.add_argument(
            "--counter_max", help="Max number of screenshots per host", default="20"
        )

    def get_targets(self, args):
        timestamp = str(int(time()))
        targets = []
        if args.import_file:
            targets += [t for t in open(args.import_file).read().split("\n") if t]

        if args.import_database:
            if args.rescan:
                targets += run(scope_type="active")
            else:
                targets += run(
                    scope_type="active", tool=self.name, args=self.args.tool_args
                )

        if args.scan_folder:
            files = os.listdir(args.scan_folder)
            counter_max = str(args.counter_max)
            for f in files:
                if f.count("_") == 4:
                    counter = 0
                    http, _, _, domain, port = f.split("-dir.txt")[0].split("_")
                    for data in (
                        open(os.path.join(args.scan_folder, f)).read().split("\n")
                    ):
                        if "(Status: 200)" in data:
                            targets.append(
                                "{}://{}:{}{}".format(
                                    http, domain, port, data.split(" ")[0]
                                )
                            )
                            counter += 1
                        if counter >= counter_max:
                            break

        if args.output_path[0] == "/":
            self.path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path[1:],
                timestamp,
                args.output_path[1:].split("/")[1] + "_{}",
            )
        else:
            self.path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path,
                timestamp,
                args.output_path.split("/")[1] + "_{}",
            )

        res = []
        i = 0

        for url_chunk in self.chunks(targets, args.group_size):
            i += 1
            
            if not os.path.exists(self.path.format(i)):
                os.makedirs(self.path.format(i))

            f = tempfile.NamedTemporaryFile(dir=self.path.rsplit('/', 1)[0], delete=False, mode='w')
            file_name = f.name
            f.write("\n".join(list(set(url_chunk))))
            f.close()

            res.append({"target": file_name, "output": self.path.format(i)})

        return res

    def build_cmd(self, args):
        command = (
            self.binary
            + " file -f {target} -D sqlite://{output}/gowitness.sqlite3 -P {output}  "
        )

        if args.tool_args:
            command += args.tool_args

        return command

    def process_output(self, cmds):
        """
        Not really any output to process with this module, but you need to cwd into directory to make database generation work, so
        I'll do that here.
        """

        cwd = os.getcwd()
        # ver_pat = re.compile("gowitness:\s?(?P<ver>\d+\.\d+\.\d+)")
        # version = subprocess.getoutput("gowitness version")
        # command_change = LooseVersion("1.0.8")
        # gen_command = ["report", "generate"]
        # m = ver_pat.match(version)
        # if m:
        #     if LooseVersion(m.group("ver")) <= command_change:
        #         gen_command = ["generate"]

        for cmd in cmds:
            output = cmd["output"]
            for t in open(cmd["target"]).read().split("\n"):
                if t:
                    display(f"Adding {t} with {self.args.tool_args}")
                    add_tool_url(t, tool=self.name, args=self.args.tool_args)
            # cmd = [self.binary] + gen_command
            os.chdir(output)

            # subprocess.Popen(cmd, shell=False).wait()

            conn = sqlite3.connect(os.path.join(output, "gowitness.sqlite3"))

            cr = conn.cursor()
            sql = """
                select u.url, d.name from tls_certificate_dns_names as d
                inner join tls_certificates as c on c.id = d.tls_certificate_id
                inner join tls as t on t.id = c.tls_id
                inner join urls as u on u.id = t.url_id
            """
            domain_data = cr.execute(sql).fetchall()
            domains = sorted(
                list(
                    set([d[1] for d in domain_data if "." in d[1] and "*" not in d[1]])
                )
            )
            for name in domains:
                domain, created = Domain.objects.get_or_create(name=name.lower())

            url_domain_data = {}
            # display(f"Discovered {len(domains)} unique domain names")
            for d, n in domain_data:
                if not url_domain_data.get(d):
                    url_domain_data[d] = []
                if n not in url_domain_data[d]:
                    url_domain_data[d].append(n)

            for u in cr.execute(
                "select id, url, filename, final_url, response_code from urls"
            ).fetchall():
                port = get_port_object(u[1])
                if not port:
                    display_error("Port not found: {}".format(u[1]))
                else:
                    if not port.meta.get("Gowitness"):
                        port.meta["Gowitness"] = []

                    data = {
                        "screenshot_file": os.path.join(output, u[2]),
                        "final_url": u[3],
                        "response_code_string": str(u[4]),
                        "headers": [
                            {"key": k[0], "value": k[1]}
                            for k in cr.execute(
                                "select key, value from headers where url_id = ?",
                                (u[0],),
                            )
                        ],
                        "cert": {"dns_names": url_domain_data.get(u[1], [])},
                    }

                    for dmn in url_domain_data.get(u[1], []):
                        dn, created = VirtualHost.objects.get_or_create(
                            ip_address=port.ip_address, name=dmn, port=port
                        )

                    port.meta["Gowitness"].append(data)

                    port.save()
            # for d in data:
            #     if '{"url"' in d:

            #         j = json.loads(d)

            #         port = get_port_object(j['url'])
            #         if not port:
            #             display_error("Port not found: {}".format(j['url']))
            #         else:
            #             if not port.meta.get('Gowitness'):
            #                 port.meta['Gowitness'] = []

            #             port.meta['Gowitness'].append(j)
            #             port.save()

            #             if j.get('ssl_certificate') and 'peer_certificates' in j['ssl_certificate'] and j['ssl_certificate']['peer_certificates'] != None:
            #                 for cert in j['ssl_certificate']['peer_certificates']:
            #                     if cert and cert.get('dns_names') and cert['dns_names'] != None:
            #                         for name in cert['dns_names']:

            os.chdir(cwd)

        # add_tools_urls(scope_type="active", tool=self.name, args=self.args.tool_args)

    def chunks(self, chunkable, n):
        """Yield successive n-sized chunks from l."""
        for i in xrange(0, len(chunkable), n):
            yield chunkable[i : i + n]  # noqa: E203
