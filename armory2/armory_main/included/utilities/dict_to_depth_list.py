#!/usr/bin/python

from armory2.armory_main.models import IPAddress, Domain
from .network_tools import get_ips as get_ip
import pdb

def run(hosts, proto="tcp", svc="ssl", lookup_domains=False):


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

        except Exception:
            domains = Domain.objects.filter(name=host)
            if domains:
                domain = domains[0]
                for ip in domain.ip_addresses.all():
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
                ip_obj = IPAddress.objects.filter(ip_address=ip)[0]
                domains = [d.name for d in ip_obj.domain_set.all()]
                if domains:
                    results.append(
                        "%s / %s: %s"
                        % (
                            ip,
                            ", ".join(sorted(domains)),
                            ", ".join(
                                [
                                    "%s/%s/%s" % (proto, p, _svc)
                                    for p, _svc in sorted(ips[ip]["ports"])
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
                                    "%s/%s/%s" % (proto, p, _svc)
                                    for p, _svc in sorted(ips[ip]["ports"])
                                ]
                            ),
                        )
                    )
            except Exception:
                if ips[ip]["domains"]:
                    results.append(
                        "%s / %s: %s"
                        % (
                            ip,
                            ", ".join(sorted(ips[ip]["domains"])),
                            ", ".join(
                                [
                                    "%s/%s/%s" % (proto, p, _svc)
                                    for p, _svc in sorted(ips[ip]["ports"])
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
                                    "%s/%s/%s" % (proto, p, _svc)
                                    for p, _svc in sorted(ips[ip]["ports"])
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
                                "%s/%s/%s" % (proto, p, _svc)
                                for p, _svc in sorted(ips[ip]["ports"])
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
                                "%s/%s/%s" % (proto, p, _svc)
                                for p, _svc in sorted(ips[ip]["ports"])
                            ]
                        ),
                    )
                )
    return results
