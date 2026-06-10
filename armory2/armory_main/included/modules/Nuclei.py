#!/usr/bin/python

from armory2.armory_main.models import (
    IPAddress,
    Domain,
    Port,
    Vulnerability,
    VirtualHost,
)
from armory2.armory_main.included.ModuleTemplate import ToolTemplate
from armory2.armory_main.included.utilities import get_urls
from armory2.armory_main.included.utilities.color_display import (
    display_warning,
    display,
    display_error,
    display_new,
)
import os
import json

class Module(ToolTemplate):
    """
    This module uses nuclei, which can be installed from:

    https://github.com/projectdiscovery/nuclei

    Nuclei is a fast, customizable vulnerability scanner powered by the global
    security community and built on a simple YAML-based DSL.
    """

    name = "nuclei"
    binary_name = "nuclei"
    docker_name = "nuclei"
    docker_repo = "https://github.com/projectdiscovery/nuclei.git"
    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-u", "--url", help="URL to scan")
        self.options.add_argument("-t", "--target", help="Target to scan")
        self.options.add_argument("--file", help="Import URLs/hosts from file")
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from database",
            action="store_true",
        )
        self.options.add_argument(
            "-w", "--web",
            help="Scan web ports only",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan",
            help="Rescan targets that have already been scanned",
            action="store_true",
        )
        self.options.add_argument(
            "--virtualhosts",
            help="Scan virtual hosts (requires -i): generates per-IP target files with <ip> <domain> lines for each active-scoped virtualhost",
            action="store_true",
        )
        
        self.options.set_defaults(timeout=0)  # Disable the default timeout.

    def get_targets(self, args):
        targets = []
        if args.output_path[0] == "/":
            output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path[1:],
            )
        else:
            output_path = os.path.join(
                self.base_config["ARMORY_BASE_PATH"],
                args.output_path,
            )

        if not os.path.exists(output_path):
            os.makedirs(output_path)
        if args.url:

            open(os.path.join(output_path, f"{args.url.split('/')[2]}-nuclei-target.txt"), "w").write(args.url)
            targets.append(os.path.join(output_path, f"{args.url.split('/')[2]}-nuclei-target.txt"))
            # targets.append(args.url)

        if args.file:
            
            targets.append(args.file)



        if args.import_database:
            # ports = Port.objects.filter(ip_address__active_scope=True, status="open", port_number__gt=0)
            ips = IPAddress.objects.filter(active_scope=True, port__port_number__gt=0, port__status="open")
            if not args.rescan:
                
                ips = ips.exclude(port__toolrun__tool=self.name, port__toolrun__args=args.tool_args)


            for i in ips:
                fname = os.path.join(output_path, f"{i.ip_address}-nuclei-target.txt")
                f = open(fname, "w")

                ports = i.port_set.filter(status="open", port_number__gt=0)

                if not args.rescan:
                    ports = ports.exclude(toolrun__tool=self.name, toolrun__args=args.tool_args)
                
                if args.web:
                    ports = ports.filter(service_name__icontains='http')
                for p in ports:
                    if not args.web:
                        f.write(f"{i.ip_address}:{p.port_number}\n")
                    if 'https' in p.service_name:
                        f.write(f"https://{i.ip_address}:{p.port_number}\n")
                    elif 'http' in p.service_name:
                        f.write(f"http://{i.ip_address}:{p.port_number}\n")
                    
                
                f.close()
                targets.append(fname)




        res = []
        for t in targets:
            res.append(
                {
                    "target": t,
                    "output": os.path.join(
                        output_path,
                        t.rsplit('/', 1)[-1].split('-nuclei-target.txt')[0]
                        .replace(":", "_")
                        .replace("?", "_")
                        .replace("&", "_")
                        + "-nuclei.jsonl",  # noqa: W503
                    ),
                }
            )

        if args.virtualhosts:
            if not args.import_database:
                display_warning("--virtualhosts requires -i/--import_database; skipping virtualhost targets")
            else:
                ip_vhosts = {}

                for domain in Domain.objects.filter(active_scope=True).prefetch_related('ip_addresses'):
                    for ip in domain.ip_addresses.filter(active_scope=True):
                        ip_vhosts.setdefault(ip, set()).add(domain.name)

                for vh in VirtualHost.objects.filter(
                    active=True, ip_address__active_scope=True, domain__active_scope=True
                ).select_related('ip_address', 'domain'):
                    ip_vhosts.setdefault(vh.ip_address, set()).add(vh.name)

                for ip, vhost_names in ip_vhosts.items():
                    if not args.rescan:
                        processed = set(
                            ip.toolrun.filter(
                                tool=self.name,
                                args=args.tool_args,
                                virtualhost__isnull=False,
                            ).values_list('virtualhost__name', flat=True)
                        )
                        vhost_names -= processed

                    if not vhost_names:
                        continue

                    fname = os.path.join(output_path, f"{ip.ip_address}-virtualhosts-nuclei-target.txt")
                    with open(fname, "w") as f:
                        for name in sorted(vhost_names):
                            f.write(f"{ip.ip_address} {name}\n")

                    ip_safe = ip.ip_address.replace(":", "_")
                    out_fname = os.path.join(output_path, f"{ip_safe}_virtualhosts.jsonl")
                    res.append({"target": fname, "output": out_fname})

        return res

    def build_cmd(self, args):
        cmd = self.binary
        cmd += " -list {target}"
        cmd += " -je {output}"

        if args.tool_args:
            cmd += " " + args.tool_args

        return cmd

    def _mark_vhost_toolruns(self, target_file):
        """Mark a toolrun for each ip+vhost pair listed in a virtualhost target file."""
        try:
            with open(target_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(" ", 1)
                    if len(parts) != 2:
                        continue
                    ip_addr, vhost_name = parts
                    try:
                        ip = IPAddress.objects.get(ip_address=ip_addr)
                        ip.add_tool_run(tool=self.name, args=self.args.tool_args, virtualhost=vhost_name)
                    except IPAddress.DoesNotExist:
                        display_warning(f"IP not found when marking vhost toolrun: {ip_addr}")
        except Exception as e:
            display_error(f"Error marking vhost toolruns from {target_file}: {e}")

    def process_output(self, cmds):
        for cmd in cmds:
            target = cmd["target"]
            output_file = cmd["output"]

            is_vhost_scan = output_file.endswith("_virtualhosts.jsonl")

            if not os.path.exists(output_file):
                display_warning(
                    "Output file not found for {}: {}".format(target, output_file)
                )
                if is_vhost_scan and os.path.exists(target):
                    self._mark_vhost_toolruns(target)
                continue

            try:
                with open(output_file, "r") as f:
                    for line in f:
                        dl = json.loads(line)
                        for data in dl:
                            ip_address = data['host'].split(':')[0]

                            port_number = data.get('port', 0)

                            port_objects = Port.objects.filter(ip_address__ip_address=ip_address, port_number=port_number)
                            if not port_objects.exists():
                                if 'arpa' in ip_address:
                                    ip_address = '.'.join(ip_address.split('.')[:4][::-1])
                                    print(ip_address)
                                ip = IPAddress.objects.get(ip_address=ip_address)

                                port_object = Port.objects.create(ip_address=ip, port_number=port_number)
                                display_new(
                                    "Port object created for {}:{}".format(ip_address, port_number)
                                )
                            else:
                                port_object = port_objects.first()

                            port_object.add_tool_run(tool=self.name, args=self.args.tool_args)

                            if not port_object.meta.get('nuclei'):
                                port_object.meta["nuclei"] = {}

                            name = data['info']['name']
                            key = "{}_{}".format(name, data.get('matcher-name', ''))
                            if not port_object.meta['nuclei'].get(key):
                                port_object.meta["nuclei"][key] = data
                                port_object.save()

                                display_new(
                                    "Added {} vulnerability to {}:{}".format(
                                        data['info']['name'], port_object.ip_address.ip_address, port_object.port_number
                                    )
                                )

                if is_vhost_scan and os.path.exists(target):
                    self._mark_vhost_toolruns(target)

            except Exception as e:
                display_error(
                    "Error processing output for {}: {}".format(target, str(e))
                )
                raise e
                continue

