#!/usr/bin/python

from included.ModuleTemplate import ModuleTemplate

from database.repositories import PortRepository, IPRepository, ScopeCIDRRepository
import time
import os
import sys
import pdb
from included.utilities.color_display import (
    display,
    display_error,
    display_warning,
    display_new,
)
import requests
import json
from netaddr import IPNetwork


class Module(ModuleTemplate):
    """
    The Shodan module will either iterate through Shodan search results from net:<cidr>
    for all scoped CIDRs, or a custom search query. The resulting IPs and ports will be
    added to the database, along with a dictionary object of the API results.

    """

    name = "ShodanImport"

    def __init__(self, db):
        self.db = db
        self.Port = PortRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)
        self.ScopeCidr = ScopeCIDRRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-k", "--api_key", help="API Key for accessing Shodan"
        )
        self.options.add_argument(
            "-s", "--search", help="Custom search string (will use credits)"
        )
        self.options.add_argument(
            "-i",
            "--import_db",
            help="Import scoped IPs from the database",
            action="store_true",
        )
        self.options.add_argument(
            "--rescan", help="Rescan CIDRs already processed", action="store_true"
        )
        self.options.add_argument(
            "--fast", help="Use 'net' filter. (May use credits)", action="store_true"
        )
        self.options.add_argument(
            "--cidr_only",
            help="Import only CIDRs from database (not individual IPs)",
            action="store_true",
        )

    def run(self, args):

        if not args.api_key:
            display_error("You must supply an API key to use shodan!")
            return

        if args.search:
            ranges = [args.search]

        if args.import_db:
            ranges = []
            if args.rescan:
                if args.fast:
                    ranges += ["net:{}".format(c.cidr) for c in self.ScopeCidr.all()]
                else:

                    cidrs = [c.cidr for c in self.ScopeCidr.all()]
                    for c in cidrs:
                        ranges += [str(i) for i in IPNetwork(c)]
                if not args.cidr_only:
                    ranges += [
                        "{}".format(i.ip_address)
                        for i in self.IPAddress.all(scope_type="active")
                    ]
            else:
                if args.fast:
                    ranges += [
                        "net:{}".format(c.cidr)
                        for c in self.ScopeCidr.all(tool=self.name)
                    ]
                else:
                    cidrs = [c.cidr for c in self.ScopeCidr.all(tool=self.name)]
                    for c in cidrs:
                        ranges += [str(i) for i in IPNetwork(c)]
                if not args.cidr_only:
                    ranges += [
                        "{}".format(i.ip_address)
                        for i in self.IPAddress.all(scope_type="active", tool=self.name)
                    ]

        api_host_url = "https://api.shodan.io/shodan/host/{}?key={}"
        api_search_url = (
            "https://api.shodan.io/shodan/host/search?key={}&query={}&page={}"
        )
        for r in ranges:

            time.sleep(1)
            if ":" in r:
                display("Doing Shodan search: {}".format(r))
                try:
                    results = json.loads(
                        requests.get(api_search_url.format(args.api_key, r, 1)).text
                    )
                    if results.get("error") and "request timed out" in results["error"]:
                        display_warning(
                            "Timeout occurred on Shodan's side.. trying again in 5 seconds."
                        )
                        results = json.loads(
                            requests.get(api_search_url.format(args.api_key, r, 1)).text
                        )
                except Exception as e:
                    display_error("Something went wrong: {}".format(e))
                    next

                total = len(results["matches"])
                matches = []
                i = 1
                while total > 0:
                    display("Adding {} results from page {}".format(total, i))
                    matches += results["matches"]
                    i += 1
                    try:
                        time.sleep(1)
                        results = json.loads(
                            requests.get(api_search_url.format(args.api_key, r, i)).text
                        )
                        if (
                            results.get("error")
                            and "request timed out" in results["error"]
                        ):
                            display_warning(
                                "Timeout occurred on Shodan's side.. trying again in 5 seconds."
                            )
                            results = json.loads(
                                requests.get(
                                    api_search_url.format(args.api_key, r, 1)
                                ).text
                            )

                        total = len(results["matches"])

                    except Exception as e:
                        display_error("Something went wrong: {}".format(e))
                        total = 0
                        pdb.set_trace()

                for res in matches:
                    ip_str = res["ip_str"]
                    port_str = res["port"]
                    transport = res["transport"]

                    display(
                        "Processing IP: {} Port: {}/{}".format(
                            ip_str, port_str, transport
                        )
                    )

                    created, IP = self.IPAddress.find_or_create(ip_address=ip_str)
                    IP.meta["shodan_data"] = results

                    created, port = self.Port.find_or_create(
                        ip_address=IP, port_number=port_str, proto=transport
                    )
                    if created:
                        svc = ""

                        if res.get("ssl", False):
                            svc = "https"
                        elif res.get("http", False):
                            svc = "http"

                        else:
                            svc = ""

                        port.service_name = svc

                    port.meta["shodan_data"] = res
                    port.save()
            else:

                try:
                    results = json.loads(
                        requests.get(api_host_url.format(r, args.api_key)).text
                    )
                except Exception as e:
                    display_error("Something went wrong: {}".format(e))
                    next
                # pdb.set_trace()
                if results.get("data", False):

                    display("{} results found for: {}".format(len(results["data"]), r))

                    for res in results["data"]:
                        ip_str = res["ip_str"]
                        port_str = res["port"]
                        transport = res["transport"]
                        display(
                            "Processing IP: {} Port: {}/{}".format(
                                ip_str, port_str, transport
                            )
                        )
                        created, IP = self.IPAddress.find_or_create(ip_address=ip_str)
                        IP.meta["shodan_data"] = results

                        created, port = self.Port.find_or_create(
                            ip_address=IP, port_number=port_str, proto=transport
                        )
                        if created:
                            svc = ""

                            if res.get("ssl", False):
                                svc = "https"
                            elif res.get("http", False):
                                svc = "http"

                            else:
                                svc = ""

                            port.service_name = svc

                        port.meta["shodan_data"] = res
                        port.save()

        self.IPAddress.commit()
