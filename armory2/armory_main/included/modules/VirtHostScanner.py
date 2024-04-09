#!/usr/bin/python

import json
import pdb
import tempfile
from armory2.armory_main.models import (
    BaseDomain,
    Domain,
    VirtualHost,
    Url,
)
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities import get_urls
from armory2.armory_main.included.utilities.color_display import (
    display_warning,
    display_new,
)
import os
import time

from armory2.armory_main.models.network import Port


def clean_domain(s):
    return "".join(
        [st for st in s.lower() if st in "abcdefghijklmnopqrstuvwxyz.-0123456789"]
    )


class Module(ToolTemplate):

    name = "VirtHostScanner"
    # binary_name = "vhost_scanner.py"
    binary_name = "ffuf"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-u", "--url", help="URL to test")
        self.options.add_argument(
            "--file", help="Import potential virtualhosts from file"
        )

        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Rescan URLs that have already been checked",
            action="store_true",
        )
        self.options.add_argument(
            "-m",
            "--mark_inactive",
            help="Mark any virtualhosts in the database that aren't discovered to be accurate as inactive.",
            action="store_true",
        )
        self.options.add_argument(
            "--dictionary",
            help="Add a dictionary of prefixes to add to every passive scope base domain",
        )
        self.options.add_argument(
            "--quick",
            help="Quick test - tries every domain in the domain per each host",
            action="store_true",
        )
        self.options.add_argument(
            "--extensive",
            help="Grabs every domain prefix and tries it against every base domain",
            action="store_true",
        )
        self.options.add_argument(
            "--revalidate",
            help="Revalidates currently discovered virtualhosts, useful to weed out false positives",
            action="store_true",
        )
        self.options.set_defaults(timeout=600)  # Kick the default timeout to 10 minutes

    def get_targets(self, args):
        targets = []

        if args.url:

            targets.append(args.url)

        if args.file:
            urls = open(args.file).read().split("\n")
            for u in urls:
                if u:
                    targets.append(u)

        if args.import_database:
            if args.rescan:
                targets += get_urls.run(scope_type="active", domain=False)
            else:
                targets += get_urls.run(
                    tool=self.name, scope_type="active", domain=False
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

        self.vhosts = []
        if args.file:
            for vhost in open(args.file).read().split("\n"):
                if vhost:
                    self.vhosts.append(clean_domain(vhost))

        if args.dictionary:
            prefixes = clean_domain(
                [p for p in open(args.dictionary).read().split("\n") if p]
            )

            for bd in BaseDomain.objects.filter(passive_scope=True):
                for pref in prefixes:

                    self.vhosts.append(f"{pref}.{bd.name}")

        if args.quick:
            for d in Domain.objects.filter(passive_scope=True):
                self.vhosts.append(clean_domain(d.name))

        elif args.extensive:
            prefixes = []
            for d in Domain.objects.filter(passive_scope=True):
                if d.name != d.basedomain.name:
                    bdl = len(d.basedomain.name) + 1
                    pref = d.name[: len(d.name) - bdl]
                    if pref and pref not in prefixes:
                        prefixes.append(clean_domain(pref))

            for bd in BaseDomain.objects.filter(passive_scope=True):
                for pref in prefixes:
                    self.vhosts.append(clean_domain(f"{pref}.{bd.name}"))
        elif args.revalidate:

            target_obj = Port.objects.filter(
                virtualhost__active=True,
                port_number__gte=1,
                service_name__in=["http", "https"],
            ).distinct()

            res = []

            for target in target_obj:
                _, tmp = tempfile.mkstemp()
                t = f"{target.service_name}://{target.ip_address.ip_address}:{target.port_number}"
                res.append(
                    {
                        "target": t,
                        # "wordlist": file_name,
                        "new_wl": tmp,
                        "obj_id": target.id,
                        "output": os.path.join(
                            output_path,
                            t.replace(":", "_")
                            .replace("/", "_")
                            .replace("?", "_")
                            .replace("&", "_")
                            + ".txt",
                        ),
                    }
                )

            return res

        res = []
        for t in targets:
            _, tmp = tempfile.mkstemp()
            res.append(
                {
                    "target": t,
                    # "wordlist": file_name,
                    "new_wl": tmp,
                    "output": os.path.join(
                        output_path,
                        t.replace(":", "_")
                        .replace("/", "_")
                        .replace("?", "_")
                        .replace("&", "_")
                        + ".txt",
                    ),
                }
            )

        return res

    def build_cmd(self, args):

        cmd = self.binary

        cmd += " -w {new_wl} -u {target} -H 'Host: FUZZ' -o {output} -mc all "

        if args.tool_args:
            cmd += args.tool_args

        return cmd

    def populate_cmds(self, cmd, timeout, targets, delay):

        res = []

        for t in targets:
            if t.get("obj_id"):
                host = t["target"].split("/")[-1]
                with open(t["new_wl"], "w") as f:
                    for v in VirtualHost.objects.filter(
                        port_id=t["obj_id"], active=True
                    ):
                        f.write(clean_domain(v.name) + "\n")

            else:
                host = t["target"].split("/")[-1]
                f = open(t["new_wl"], "w")
                f.write(f"{host}\n")

                for vhost in self.vhosts:
                    f.write(f"{vhost}\n")

                f.close()

        return super().populate_cmds(cmd, timeout, targets, delay)

    def process_output(self, cmds):

        # display_warning(
        #     "There is currently no post-processing for this module. For the juicy results, refer to the output file paths."
        # )

        for c in cmds:

            try:
                res = json.load(open(c["output"]))
                vhost_data = {}
                host = c["target"].split("/")[-1]
                for data in res["results"]:
                    if data["status"] in [301, 302]:
                        redir = data["redirectlocation"].replace(data["host"], "")
                        res_str = (
                            f"{data['status']}-{redir}-{data['words']}-{data['lines']}"
                        )
                    else:
                        res_str = f"{data['status']}-{data['words']}-{data['lines']}"
                    # pdb.set_trace()
                    if data["host"] == host:
                        vhost_data[res_str] = host
                    elif not vhost_data.get(res_str):
                        vhost_data[res_str] = data["host"]

                vhosts = [v for k, v in vhost_data.items() if v != host]
                # pdb.set_trace()
                if vhosts:
                    display_new(
                        f"The following vhosts were found for {host}: {', '.join(vhosts)}"
                    )
                else:
                    display_warning(f"No new vhosts found for {host}")
                port = get_urls.get_port_object(c["target"])

                if port:
                    if self.args.mark_inactive:
                        port.virtualhost_set.exclude(name__in=vhosts).update(
                            active=False
                        )

                    for v in vhosts:
                        vhost, created = VirtualHost.objects.get_or_create(
                            port=port, name=v, ip_address=port.ip_address
                        )
                        vhost.active = True
                        vhost.save()
            except Exception as e:
                print(f"An error occurred getting the results from {c['target']}: {e}")
            get_urls.add_tool_url(c["target"], tool=self.name, args=self.args.tool_args)
