#!/usr/bin/python

from database.repositories import IPRepository, DomainRepository
from .get_domain_ip import run as get_ip
import pdb


def run(hosts, db, proto="tcp", svc="ssl", lookup_domains=False):

    IPAddress = IPRepository(db)
    Domain = DomainRepository(db)

    ips = {}

    for h in hosts:
        if h.count(":") == 2:
            host, port, svc = h.split(":")
        else:

            host, port = h.split(":")

        try:
            int(host.replace(".", ""))
            if not ips.get(host, False):
                ips[host] = {"domains": [], "ports": []}

            if (port, svc) not in ips[host]["ports"]:
                ips[host]["ports"].append((port, svc))

        except:
            domains = Domain.all(domain=host)
            if domains:
                domain = domains[0]
                for ip in domain.ip_addresses:
                    if not ips.get(ip.ip_address, False):
                        ips[ip.ip_address] = {"domains": [], "ports": []}

                    if host not in ips[ip.ip_address]["domains"]:
                        ips[ip.ip_address]["domains"].append(host)

                    if (port, svc) not in ips[ip.ip_address]["ports"]:
                        ips[ip.ip_address]["ports"].append((port, svc))
            else:
                # domain is not in the database.
                domain_ips = get_ip(host)
                for ip in domain_ips:
                    ips[ip] = {"domains": [host], "ports": []}

    results = []
    if lookup_domains:
        for ip in sorted(ips.keys()):

            # print("Checking %s" % ip)
            try:
                ip_obj = IPAddress.all(ip_address=ip)[0]
                domains = [d.domain for d in ip_obj.domains]
                if domains:
                    results.append(
                        "%s / %s: %s"
                        % (
                            ip,
                            ", ".join(sorted(domains)),
                            ", ".join(
                                [
                                    "%s/%s/%s" % (proto, p, svc)
                                    for p, svc in sorted(ips[ip]["ports"])
                                ]
                            ),
                        )
                    )
                else:
                    results.append(
                        "%s / No Hostname Registered: %s"
                        % (
                            ip,
                            ", ".join(
                                [
                                    "%s/%s/%s" % (proto, p, svc)
                                    for p, svc in sorted(ips[ip]["ports"])
                                ]
                            ),
                        )
                    )
            except:
                if ips[ip]["domains"]:
                    results.append(
                        "%s / %s: %s"
                        % (
                            ip,
                            ", ".join(sorted(ips[ip]["domains"])),
                            ", ".join(
                                [
                                    "%s/%s/%s" % (proto, p, svc)
                                    for p, svc in sorted(ips[ip]["ports"])
                                ]
                            ),
                        )
                    )
                else:
                    results.append(
                        "%s / No Hostname Registered: %s"
                        % (
                            ip,
                            ", ".join(
                                [
                                    "%s/%s/%s" % (proto, p, svc)
                                    for p, svc in sorted(ips[ip]["ports"])
                                ]
                            ),
                        )
                    )

    else:
        for ip in sorted(ips.keys()):
            if ips[ip]["domains"]:
                results.append(
                    "%s / %s: %s"
                    % (
                        ip,
                        ", ".join(sorted(ips[ip]["domains"])),
                        ", ".join(
                            [
                                "%s/%s/%s" % (proto, p, svc)
                                for p, svc in sorted(ips[ip]["ports"])
                            ]
                        ),
                    )
                )
            else:
                results.append(
                    "%s / No Hostname Registered: %s"
                    % (
                        ip,
                        ", ".join(
                            [
                                "%s/%s/%s" % (proto, p, svc)
                                for p, svc in sorted(ips[ip]["ports"])
                            ]
                        ),
                    )
                )
    return results
