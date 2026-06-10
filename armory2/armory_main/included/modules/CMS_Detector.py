#!/usr/bin/python
from armory2.armory_main.models import Domain, Port, Tag
from armory2.armory_main.included.ModuleTemplate import ToolTemplateNoOutput
from armory2.armory_main.included.utilities.color_display import (
    display_new,
    display_warning,
    display_error,
)
from armory2.armory_main.included.utilities.validate_ip import is_ip
import json
import os


class Module(ToolTemplateNoOutput):
    """
    Detects the CMS running on web targets using CMS-Detector.

    https://github.com/joshuavanderpoll/CMS-Detector

    Only targets with domain names are scanned (IP-only hosts are skipped).
    Detected CMS names are saved to domain.meta and added as tags.
    """

    name = "CMS_Detector"
    binary_name = "CMS-Detector"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("--host", help="Single host or URL to scan")
        self.options.add_argument(
            "--file", help="File containing hosts or URLs to scan (one per line)"
        )
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import http/https domain targets from the database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Rescan domains that have already been scanned",
            action="store_true",
        )
        self.options.add_argument(
            "--insecure",
            help="Skip TLS verification",
            action="store_true",
        )

    def get_targets(self, args):
        targets = []

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

        seen = set()

        def _add(scheme, hostname, port_num):
            if is_ip(hostname):
                return
            if port_num in (80, 443):
                url = f"{scheme}://{hostname}"
            else:
                url = f"{scheme}://{hostname}:{port_num}"
            if url in seen:
                return
            seen.add(url)
            safe = (
                url.replace("https://", "")
                .replace("http://", "")
                .replace(":", "_")
                .replace("/", "_")
            )
            targets.append({
                "target": url,
                "output": os.path.join(output_path, f"{safe}.json"),
                "domain_name": hostname,
            })

        if args.host:
            host = args.host.strip().rstrip("/")
            if host.startswith("http"):
                scheme, _, rest = host.partition("://")
                if ":" in rest:
                    hostname, _, port_str = rest.rpartition(":")
                    port_num = int(port_str)
                else:
                    hostname = rest
                    port_num = 443 if scheme == "https" else 80
            else:
                scheme = "https"
                hostname = host
                port_num = 443
            _add(scheme, hostname, port_num)

        if args.file:
            for line in open(args.file).read().splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("http"):
                    scheme, _, rest = line.partition("://")
                    rest = rest.rstrip("/")
                    if ":" in rest:
                        hostname, _, port_str = rest.rpartition(":")
                        port_num = int(port_str)
                    else:
                        hostname = rest
                        port_num = 443 if scheme == "https" else 80
                else:
                    scheme = "https"
                    hostname = line
                    port_num = 443
                _add(scheme, hostname, port_num)

        if args.import_database:
            ports = Port.objects.filter(
                service_name__in=["http", "https"],
                status="open",
                ip_address__active_scope=True,
            )
            if not args.rescan:
                ports = ports.exclude(
                    ip_address__domain__meta__has_key="cms_detector"
                )

            for port in ports:
                scheme = port.service_name  # 'http' or 'https'
                for domain in port.ip_address.domain_set.filter(active_scope=True):
                    if is_ip(domain.name):
                        continue
                    if not args.rescan and domain.meta.get("cms_detector"):
                        continue
                    _add(scheme, domain.name, port.port_number)

        return targets

    def build_cmd(self, args):
        cmd = self.binary + " -host {target} -json"
        if args.insecure:
            cmd += " -insecure"
        if args.tool_args:
            cmd += " " + args.tool_args
        return cmd

    def process_output(self, cmds):
        for cmd in cmds:
            output_file = cmd["output"]
            target = cmd["target"]
            domain_name = cmd["domain_name"]

            if not os.path.exists(output_file):
                display_warning(f"No output file for {target}: {output_file}")
                continue

            try:
                with open(output_file) as f:
                    content = f.read().strip()
                if not content:
                    display_warning(f"Empty output for {target}")
                    continue
                data = json.loads(content)
            except Exception as e:
                display_error(f"Failed to parse output for {target}: {e}")
                continue

            domain = Domain.objects.filter(name=domain_name).first()
            if not domain:
                display_warning(f"Domain not found in database: {domain_name}")
                continue

            domain.meta["cms_detector"] = data

            if data.get("detected") and data.get("matches"):
                for match in data["matches"]:
                    cms_name = match.get("name", "").lower().replace(" ", "_")
                    if not cms_name:
                        continue
                    tag, _ = Tag.objects.get_or_create(
                        name=cms_name,
                        defaults={"type": Tag.TYPE_DOMAIN},
                    )
                    domain.tags.add(tag)
                    display_new(f"[CMS_Detector] {domain_name}: detected {cms_name}")
            else:
                display_warning(f"[CMS_Detector] {domain_name}: no CMS detected")

            domain.save()
