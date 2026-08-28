"""
The sample dataset every Armory test class starts from.

``build_sample_data()`` runs once per test class (from
``ArmoryTest.setUpTestData``) and everything it creates is rolled back when the
class finishes, so tests can mutate it freely.

Everything here is deliberately offline. Creating an ``IPAddress`` that falls
outside any known CIDR fires an RDAP lookup, and creating a ``Domain`` fires a
DNS resolution, so the fixture creates its CIDR first (with ``org_name`` set,
which short-circuits ``pre_save_cidr``) and tags every domain with
``meta['offlinedns']``, which ``post_save_domain`` checks before it resolves.
Virtual hosts reuse those domain names so ``VirtualHost.save()`` finds an
existing row instead of creating one that would resolve.

Addresses come from the documentation ranges in RFC 5737 / RFC 2606, so a test
that leaks a real request goes somewhere harmless.
"""

from types import SimpleNamespace

from armory2.armory_main.models import (
    CIDR,
    Cred,
    CVE,
    Domain,
    IPAddress,
    Port,
    Tag,
    User,
    Url,
    VirtualHost,
    VulnOutput,
    Vulnerability,
)

CIDR_NAME = "192.0.2.0/24"
HOST_A = "192.0.2.10"
HOST_B = "192.0.2.11"
BASE_DOMAIN = "example.com"
DOMAIN_A = "www.example.com"
DOMAIN_B = "mail.example.com"


def _domain(name, **kwargs):
    """Create a Domain without letting the post_save hook hit DNS."""
    domain = Domain(name=name, whois="", meta={"offlinedns": True}, **kwargs)
    domain.save()
    return Domain.objects.get(name=name)


def build_sample_data():
    """
    Populate the test database and return a namespace of the objects created.

    Attributes: ``cidr``, ``host``, ``host_b``, ``basedomain``, ``domain``,
    ``domain_b``, ``http``, ``https``, ``ssh``, ``vhost``, ``vuln``,
    ``vuln_output``, ``url``, ``cve``, ``user``, ``cred``, ``tag``.
    """
    cidr = CIDR.objects.create(
        name=CIDR_NAME,
        org_name="Armory Test Fixture",
        size=256,
        active_scope=True,
        passive_scope=True,
    )

    host = IPAddress.objects.create(ip_address=HOST_A, os="Linux", whois="")
    host_b = IPAddress.objects.create(ip_address=HOST_B, os="", whois="")

    domain = _domain(DOMAIN_A, active_scope=True, passive_scope=True)
    domain_b = _domain(DOMAIN_B, active_scope=True, passive_scope=True)
    basedomain = domain.basedomain
    domain.ip_addresses.add(host)
    domain_b.ip_addresses.add(host_b)

    http = Port.objects.create(
        ip_address=host, port_number=80, proto="tcp", service_name="http",
        status="open", active_scope=True, passive_scope=True,
    )
    https = Port.objects.create(
        ip_address=host, port_number=443, proto="tcp", service_name="https",
        status="open", active_scope=True, passive_scope=True,
    )
    ssh = Port.objects.create(
        ip_address=host_b, port_number=22, proto="tcp", service_name="ssh",
        status="open", active_scope=True, passive_scope=True,
    )

    # The domain already exists, so VirtualHost.save() links to it rather than
    # creating one that would trigger a DNS lookup.
    vhost, _ = VirtualHost.objects.get_or_create(
        ip_address=host, port=http, name=DOMAIN_A
    )

    cve = CVE.objects.create(
        name="CVE-1999-0001", description="Fixture CVE", temporal_score=5.0
    )
    vuln = Vulnerability.objects.create(
        name="Armory Test Finding",
        description="A finding that exists only inside the test database.",
        remediation="Nothing to remediate; this is a fixture.",
        severity=2,
        exploitable=False,
        source="armory-test",
    )
    vuln.ports.add(http, https)
    vuln.cves.add(cve)

    vuln_output = VulnOutput.objects.create(
        port=http, vulnerability=vuln, data="fixture evidence"
    )
    url = Url.objects.create(
        name="http://%s/login" % DOMAIN_A,
        method="get",
        port=http,
        vuln_output=vuln_output,
    )

    user = User.objects.create(
        email="tester@%s" % BASE_DOMAIN,
        first_name="Test",
        last_name="Fixture",
        user_name="tfixture",
        domain=basedomain,
        job_title="Fixture",
        location="Nowhere",
    )
    cred = Cred.objects.create(user=user, password="Fixture123!", source="armory-test")

    tag = Tag.objects.create(name="armory-test", type=Tag.TYPE_ANY)
    host.tags.add(tag)

    return SimpleNamespace(
        cidr=cidr,
        host=host,
        host_b=host_b,
        basedomain=basedomain,
        domain=domain,
        domain_b=domain_b,
        http=http,
        https=https,
        ssh=ssh,
        vhost=vhost,
        vuln=vuln,
        vuln_output=vuln_output,
        url=url,
        cve=cve,
        user=user,
        cred=cred,
        tag=tag,
    )
