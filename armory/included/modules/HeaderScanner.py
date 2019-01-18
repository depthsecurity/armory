#!/usr/bin/python

from armory.database.repositories import PortRepository, DomainRepository, IPRepository
from ..ModuleTemplate import ModuleTemplate
import requests
import sys
from multiprocessing import Pool as ThreadPool
from ..utilities.color_display import (
    display,
    display_error,
    display_warning,
    display_new,
)


def check_if_ip(txt):
    try:
        int(txt.replace(".", ""))
        return True
    except ValueError:
        return False


class Module(ModuleTemplate):

    name = "HeaderScanner"

    def __init__(self, db):
        self.db = db
        self.Port = PortRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.IPAddress = IPRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-t", "--timeout", help="Connection timeout (default 5)", default="5"
        )
        self.options.add_argument("-u", "--url", help="URL to get headers")
        self.options.add_argument("--file", help="Import URLs from file")
        self.options.add_argument(
            "-i",
            "--import_db",
            help="Import URLs from the database",
            action="store_true",
        )
        self.options.add_argument(
            "-th", "--threads", help="Number of threads to run", default="10"
        )
        self.options.add_argument(
            "--rescan", help="Rescan URLs already processed", action="store_true"
        )

    def run(self, args):
        data = []
        if args.url:
            service = args.url.split(":")[0]
            host = args.url.split("/")[2]

            if args.url.count(":") == 2:
                port = args.url.split(":")[2].split("/")[0]
            elif service == "http":
                port = "80"
            elif service == "https":
                port = "443"
            else:
                display_error(
                    "Could not figure out port number for url: {}".format(args.url)
                )
                sys.exit(1)

            if check_if_ip(host):
                created, ip = self.IPAddress.find_or_create(ip_address=host)
            else:

                created, domain = self.Domain.find_or_create(domain=host)
                ip = domain.ip_addresses[0]

            created, service_id = self.Port.find_or_create(
                ip_address=ip, port_number=port
            )
            service_id.service_name = service

            data.append([service_id.id, [args.url], args.timeout])

        if args.file:
            url = open(args.file).read().split("\n")
            for u in url:
                if u:
                    service = u.split(":")[0]
                    host = u.split("/")[2]

                    if u.count(":") == 2:
                        port = u.split(":")[2].split("/")[0]
                    elif service == "http":
                        port = "80"
                    elif service == "https":
                        port = "443"
                    else:
                        display_error(
                            "Could not figure out port number for url: {}".format(
                                args.url
                            )
                        )
                        sys.exit(1)

                    if check_if_ip(host):
                        created, ip = self.IPAddress.find_or_create(ip_address=host)
                    else:

                        created, domain = self.Domain.find_or_create(domain=host)
                        ip = domain.ip_addresses[0]

                    created, service_id = self.Port.find_or_create(
                        ip_address=ip, port_number=port
                    )
                    service_id.service_name = service

                    data.append([service_id.id, [u], args.timeout])

        if args.import_db:

            if args.rescan:
                svc = self.Port.all(service_name="http")
                svc += self.Port.all(service_name="https")
            else:
                svc = self.Port.all(service_name="http", tool=self.name)
                svc += self.Port.all(service_name="https", tool=self.name)

            for s in svc:
                if s.ip_address.in_scope:
                    urls = [
                        "%s://%s:%s"
                        % (s.service_name, s.ip_address.ip_address, s.port_number)
                    ]

                    for d in s.ip_address.domains:
                        urls.append(
                            "%s://%s:%s" % (s.service_name, d.domain, s.port_number)
                        )

                    data.append([s.id, urls, args.timeout])

        if data:
            pool = ThreadPool(int(args.threads))

            results = pool.map(process_urls, data)
            display_new("Adding headers to the database")
            for i, headers, cookies in results:
                created, svc = self.Port.find_or_create(id=i)

                svc.meta["headers"] = headers

                svc.meta["cookies"] = cookies
                svc.update()

            self.Port.commit()


def process_urls(data):

    i, urls, timeout = data
    blacklist = [
        "Date",
        "Connection",
        "Content-Type",
        "Content-Length",
        "Keep-Alive",
        "Content-Encoding",
        "Vary",
    ]
    new_headers = {}
    new_cookies = {}
    for u in urls:
        display("Processing %s" % u)
        try:
            res = requests.get(u, timeout=int(timeout), verify=False)

            for k in res.headers.keys():
                if k not in blacklist:
                    if not new_headers.get(u, False):
                        new_headers[u] = []

                    new_headers[u].append("%s: %s" % (k, res.headers[k]))
            new_cookies[u] = dict(res.cookies)

        except KeyboardInterrupt:
            display_warning("Got Ctrl+C, exiting")
            sys.exit(1)
        except Exception as e:
            display_error("%s no good, skipping: %s" % (u, e))
    return (i, new_headers, new_cookies)
