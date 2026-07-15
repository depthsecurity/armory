#!/usr/bin/python
from armory2.armory_main.models import Domain, IPAddress, Port, Vulnerability, VulnOutput
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities.color_display import (
    display_warning,
    display_error,
    display_new,
)
import os
import json


SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


class Module(ToolTemplate):
    """
    This module uses testssl.sh, which can be installed from:

    https://github.com/drwetter/testssl.sh

    testssl.sh is a free command line tool for checking server's SSL/TLS
    configuration and identifies common vulnerabilities.
    """

    name = "TestSSL"
    binary_name = "testssl.sh"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "--host", help="Host to scan (https://host[:port] or host[:port])"
        )
        self.options.add_argument(
            "-f", "--file", help="Import hosts from file (one URL or host:port per line)"
        )
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import HTTPS hosts from database",
            action="store_true",
        )
        self.options.add_argument(
            "-s",
            "--rescan",
            help="Rescan hosts that have already been scanned",
            action="store_true",
        )

    def _normalize_target(self, host):
        """Return (url, safe_filename_base) for a host/url string."""
        host = host.strip().rstrip("/")
        if host.startswith("http"):
            url = host
        else:
            url = "https://{}".format(host)
        safe = (
            url.replace("https://", "")
            .replace("http://", "")
            .replace(":", "_")
            .replace("/", "_")
        )
        return url, safe

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

        if args.host:
            url, safe = self._normalize_target(args.host)
            targets.append(
                {
                    "target": url,
                    "output": os.path.join(output_path, f"{safe}-testssl.json"),
                }
            )

        if args.file:
            for line in open(args.file).read().splitlines():
                line = line.strip()
                if line:
                    url, safe = self._normalize_target(line)
                    targets.append(
                        {
                            "target": url,
                            "output": os.path.join(output_path, f"{safe}-testssl.json"),
                        }
                    )

        if args.import_database:
            ports = Port.objects.filter(
                service_name="https", status="open", ip_address__active_scope=True
            )
            if not args.rescan:
                ports = ports.exclude(toolrun__tool=self.name)

            for p in ports:
                ip = p.ip_address.ip_address
                port_num = p.port_number
                url = f"https://{ip}:{port_num}"
                safe = f"{ip}_{port_num}"
                targets.append(
                    {
                        "target": url,
                        "output": os.path.join(output_path, f"{safe}-testssl.json"),
                    }
                )

                for d in p.ip_address.domain_set.filter(active_scope=True):
                    url = f"https://{d.name}:{port_num}"
                    safe = f"{d.name}_{port_num}"
                    targets.append(
                        {
                            "target": url,
                            "output": os.path.join(output_path, f"{safe}-testssl.json"),
                        }
                    )

        return targets

    def build_cmd(self, args):
        cmd = self.binary + " --jsonfile {output} --warnings batch {target}"
        if args.tool_args:
            cmd += " " + args.tool_args
        return cmd

    def process_output(self, cmds):
        for cmd in cmds:
            target = cmd["target"]
            output_file = cmd["output"]

            if not os.path.exists(output_file):
                display_warning(
                    "Output file not found for {}: {}".format(target, output_file)
                )
                continue

            try:
                with open(output_file) as f:
                    data = json.load(f)
            except Exception as e:
                display_error("Failed to parse {}: {}".format(output_file, e))
                continue

            # Extract host and port from the target URL
            url_no_scheme = target.replace("https://", "").replace("http://", "")
            if ":" in url_no_scheme:
                host, port_str = url_no_scheme.rsplit(":", 1)
                port_num = int(port_str)
            else:
                host = url_no_scheme
                port_num = 443

            port_object = self._find_port(host, port_num, data)
            if not port_object:
                display_warning(
                    "Could not find port object for {}:{}, skipping".format(
                        host, port_num
                    )
                )
                continue

            port_object.add_tool_run(tool=self.name, args=self.args.tool_args)

            if "testssl" not in port_object.meta:
                port_object.meta["testssl"] = {}

            for entry in data:
                entry_id = entry.get("id", "")
                severity_str = entry.get("severity", "INFO")
                finding = entry.get("finding", "")

                if not entry_id or entry.get("ip", "") == "/":
                    continue

                port_object.meta["testssl"][entry_id] = {
                    "severity": severity_str,
                    "finding": finding,
                }

                severity_int = SEVERITY_MAP.get(severity_str, 0)
                if severity_int > 0:
                    vuln_name = "TestSSL: {}".format(entry_id)
                    vuln, _ = Vulnerability.objects.get_or_create(
                        name=vuln_name,
                        defaults={
                            "description": finding,
                            "remediation": "",
                            "severity": severity_int,
                            "source": "testssl",
                        },
                    )
                    if not vuln.ports.filter(pk=port_object.pk).exists():
                        vuln.ports.add(port_object)
                        display_new(
                            "[{}] {}: {} on {}:{}".format(
                                severity_str, entry_id, finding, host, port_num
                            )
                        )
                    VulnOutput.objects.get_or_create(
                        port=port_object,
                        vulnerability=vuln,
                        defaults={"data": finding},
                    )

            port_object.save()

    def _find_port(self, host, port_num, data):
        """Locate the Port object for a given host and port, using JSON data as fallback."""
        qs = Port.objects.filter(
            ip_address__ip_address=host, port_number=port_num
        )
        if qs.exists():
            return qs.first()

        qs = Port.objects.filter(
            ip_address__domain__name=host, port_number=port_num
        )
        if qs.exists():
            return qs.first()

        # Fall back to resolved IP from testssl output
        for entry in data:
            ip_field = entry.get("ip", "")
            if "/" in ip_field:
                resolved_ip = ip_field.split("/")[-1].strip()
                if resolved_ip:
                    qs = Port.objects.filter(
                        ip_address__ip_address=resolved_ip, port_number=port_num
                    )
                    if qs.exists():
                        return qs.first()
                    break

        return None
