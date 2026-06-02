#!/usr/bin/python

from datetime import datetime, date

import whoisit
from netaddr import IPNetwork

from armory2.armory_main.models import BaseDomain, CIDR
from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
from armory2.armory_main.included.utilities.color_display import display, display_error


def _dt(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _kv(lines, label, value):
    if value not in (None, "", []):
        lines.append("{}: {}".format(label, value))


def _format_entities(entities):
    lines = []
    for role, members in (entities or {}).items():
        label = role.replace("_", " ").title()
        for member in members:
            _kv(lines, "{} Name".format(label), member.get("name"))
            _kv(lines, "{} Handle".format(label), member.get("handle"))
            _kv(lines, "{} Email".format(label), member.get("email"))
            _kv(lines, "{} Phone".format(label), member.get("tel"))
            address = member.get("address") or {}
            _kv(lines, "{} Street".format(label), address.get("street_address"))
            _kv(lines, "{} City".format(label), address.get("locality"))
            _kv(lines, "{} Region".format(label), address.get("region"))
            _kv(lines, "{} Postal Code".format(label), address.get("postal_code"))
            _kv(lines, "{} Country".format(label), address.get("country"))
    return lines


def format_domain(res):
    lines = []
    _kv(lines, "Domain Name", res.get("name"))
    _kv(lines, "Registry Domain ID", res.get("handle"))
    _kv(lines, "Updated Date", _dt(res.get("last_changed_date")))
    _kv(lines, "Creation Date", _dt(res.get("registration_date")))
    _kv(lines, "Registry Expiry Date", _dt(res.get("expiration_date")))
    _kv(lines, "Registrar WHOIS Server", res.get("whois_server"))
    _kv(lines, "Registrar URL", res.get("url"))
    lines.append("DNSSEC: {}".format("signedDelegation" if res.get("dnssec") else "unsigned"))
    for status in res.get("status") or []:
        _kv(lines, "Domain Status", status)
    for ns in res.get("nameservers") or []:
        _kv(lines, "Name Server", ns)
    lines.extend(_format_entities(res.get("entities")))
    return "\n".join(lines)


def format_ip(res):
    lines = []
    _kv(lines, "NetRange", res.get("handle"))
    network = res.get("network")
    _kv(lines, "CIDR", str(network) if network else None)
    _kv(lines, "NetName", res.get("name"))
    _kv(lines, "Parent", res.get("parent_handle"))
    _kv(lines, "NetType", res.get("assignment_type"))
    _kv(lines, "Country", res.get("country"))
    _kv(lines, "RegDate", _dt(res.get("registration_date")))
    _kv(lines, "Updated", _dt(res.get("last_changed_date")))
    _kv(lines, "Ref", res.get("url"))
    _kv(lines, "Whois Server", res.get("whois_server"))
    for desc in res.get("description") or []:
        _kv(lines, "Description", desc)
    lines.extend(_format_entities(res.get("entities")))
    return "\n".join(lines)


def _org_name(res):
    if res.get("description"):
        return res["description"][0]
    try:
        return res["entities"]["registrant"][0]["name"]
    except (KeyError, IndexError):
        return "Not resolved"


class Module(ModuleTemplate):
    name = "Whois"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-d", "--domain", help="Domain to query")
        self.options.add_argument("-c", "--cidr", help="CIDR to query")

        self.options.add_argument(
            "-s",
            "--rescan",
            help="Rescan domains that have already been scanned",
            action="store_true",
        )
        self.options.add_argument(
            "-a",
            "--all_data",
            help="Scan all data in database, regardless of scope",
            action="store_true",
        )
        self.options.add_argument(
            "-i",
            "--import_database",
            help="Run WHOIS on all domains and CIDRs in database",
            action="store_true",
        )

    def run(self, args):
        whoisit.bootstrap()

        domains, cidrs = self.get_targets(args)

        for domain in domains:
            self.process_domain(domain)

        for query_ip, cidr in cidrs:
            self.process_cidr(query_ip, cidr)

    def get_targets(self, args):
        domains = []
        cidrs = []

        if args.domain:
            domains.append(args.domain)

        elif args.cidr:
            cidrs.append((args.cidr.split("/")[0], None))

        elif args.import_database:
            scope_type = "" if args.all_data else "passive"
            if args.rescan:
                db_domains = BaseDomain.get_set(scope_type=scope_type)
                db_cidrs = CIDR.get_set(scope_type=scope_type)
            else:
                db_domains = BaseDomain.get_set(scope_type=scope_type, tool=self.name)
                db_cidrs = CIDR.get_set(tool=self.name)

            for domain in db_domains:
                domains.append(domain.name)
            for cidr in db_cidrs:
                cidrs.append((cidr.name.split("/")[0], cidr))

        return domains, cidrs

    def process_domain(self, name):
        try:
            res = whoisit.domain(name)
        except Exception as e:
            display_error("Error resolving RDAP for {}: {}".format(name, e))
            return

        domain, _ = BaseDomain.objects.get_or_create(name=name)
        domain.meta["whois"] = format_domain(res)
        domain.save()
        display(domain.meta["whois"])
        domain.add_tool_run(self.name)

    def process_cidr(self, query_ip, cidr):
        try:
            res = whoisit.ip(query_ip)
        except Exception as e:
            display_error("Error resolving RDAP for {}: {}".format(query_ip, e))
            return

        if cidr is None:
            network = str(res["network"])
            cidr, _ = CIDR.objects.get_or_create(
                name=network,
                defaults={
                    "org_name": _org_name(res),
                    "size": IPNetwork(network).size,
                },
            )

        cidr.meta["whois"] = format_ip(res)
        cidr.save()
        display(cidr.meta["whois"])
        cidr.add_tool_run(self.name)
