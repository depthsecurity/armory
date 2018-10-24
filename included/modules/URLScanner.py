#!/usr/bin/python

from included.ModuleTemplate import ModuleTemplate
import re
from included.utilities.get_urls import run as geturls
import requests
import time
import os


class Module(ModuleTemplate):
    """
    This module is meant to scan for certain criteria over a large estate. Useful
    for searching for specific scenarios, such as "returns 401 while http".
    Not really working quite reliably right now.
    """

    name = "UrlScanner"

    def __init__(self, db):
        self.db = db

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-sm", "--status_match", help="Status Codes that signify valid response"
        )
        self.options.add_argument(
            "-sn",
            "--status_no_match",
            help="Status Codes that signify invalid response",
        )
        self.options.add_argument(
            "-p",
            "--protocol",
            help="Protocol (http, https, or any) (Default: any)",
            default="any",
        )
        self.options.add_argument(
            "-rm", "--regex_match", help="Regex on response to indicate valid response"
        )
        self.options.add_argument(
            "-rn",
            "--regex_no_match",
            help="Regex on response to indicate invalid response",
        )
        self.options.add_argument(
            "-t", "--timeout", help="Connection timeout (default 5)", default="5"
        )
        self.options.add_argument(
            "-o", "--output", help="Output file (default UrlScanner-<tiemstamp>.txt"
        )
        self.options.add_argument("-u", "--url", help="URL to test")
        self.options.add_argument(
            "-i",
            "--import_db",
            help="Import URLs from the database",
            action="store_true",
        )
        self.options.add_argument(
            "-e", "--endpoint", help="The endpoint to attack (default '/')", default="/"
        )

    def run(self, args):

        if args.status_match:
            status_match = [int(s) for s in args.status_match.split(",")]
        else:
            status_match = []

        if args.status_no_match:
            status_no_match = [int(s) for s in args.status_no_match.split(",")]
        else:
            status_no_match = []

        if args.output:
            f = open(
                os.path.join(self.base_config["PROJECT"]["base_path"], args.output), "w"
            )

        else:
            f = open(
                os.path.join(
                    self.base_config["PROJECT"]["base_path"],
                    "UrlScanner-%s" % time.strftime("%Y%m%d-%H%M%S"),
                ),
                "w",
            )

        if args.url:
            urls = [args.url]
        elif args.import_db:
            urls = geturls(self.db)

        else:
            urls = []

        for url in urls:
            if url[-1] == "/":
                url = url[:-1]
            if args.endpoint[0] == "/":
                args.endpoint = args.endpoint[1:]

            url = url + "/" + args.endpoint

            proto = url.split(":")[0]
            if args.protocol == "any" or args.protocol == proto:
                print("Processing %s" % url)
                try:
                    res = requests.get(
                        url,
                        timeout=int(args.timeout),
                        verify=False,
                        allow_redirects=False,
                    )
                    matched = True
                    if status_match and res.status_code not in status_match:
                        print("Didn't match %s on status code" % url)
                        matched = False

                    if status_no_match and res.status_code in status_no_match:
                        print("Didn't match %s on missing status code" % url)
                        matched = False

                    if args.regex_match and not re.findall(res.text, args.regex_match):
                        print("Didn't match %s on regex" % url)
                        matched = False

                    if args.regex_no_match and re.findall(
                        res.text, args.regex_no_match
                    ):
                        print("Matched %s on restricted regex" % url)
                        matched = False

                    if matched:
                        f.write(url + "\n")

                except KeyboardInterrupt:
                    print("Keyboard Interrupt received, exiting")
                    break
                except Exception as e:
                    print("Error on %s: %s, skipping." % (url, e))

        f.close()
