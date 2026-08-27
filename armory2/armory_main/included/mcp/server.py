#!/usr/bin/env python3
"""
Armory MCP Server

Exposes Armory security data as MCP tools so Claude can query, create, update,
and delete records in the database during a pentest engagement.

This is a client of the Armory web API (the `armory_api` webapp), so an
`armory-web` instance must be running for the tools to return data.

Run it directly with the `armory-mcp` console script, or let `armory-web --mcp`
start it alongside the web server.

Targets the mcp 2.x `MCPServer` API (v1's `FastMCP`); `pyproject.toml` pins
`mcp>=2.0` accordingly.

Configuration:
    --url <URL>       Base URL of the Armory web server (without /armory_api).
                      Default: http://localhost:8099
    --transport       stdio (default), streamable-http, or sse.
    --host / --port   Bind address for the http/sse transports.
                      Default: 127.0.0.1:8100
    ARMORY_API_URL    Environment variable fallback, used if --url is not given.
                      May include the /armory_api suffix.
"""

import argparse
import json
import os
import httpx
from mcp.server.mcpserver import MCPServer

from armory2 import __version__

DEFAULT_API_URL = "http://localhost:8099"
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 8100


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="armory-mcp",
        description="Armory MCP Server",
    )
    parser.add_argument(
        "--url",
        default=None,
        help=f"Base URL of the Armory web server (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "streamable-http", "sse"],
        help="MCP transport to serve on (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_MCP_HOST,
        help=f"Bind address for http/sse transports (default: {DEFAULT_MCP_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_MCP_PORT,
        help=f"Port for http/sse transports (default: {DEFAULT_MCP_PORT})",
    )
    return parser


def _normalize_api_url(url: str) -> str:
    base = url.rstrip("/")
    if not base.endswith("/armory_api"):
        base += "/armory_api"
    return base


def _resolve_base_url() -> str:
    args, _ = _build_parser().parse_known_args()

    if args.url:
        return _normalize_api_url(args.url)

    env = os.environ.get("ARMORY_API_URL")
    if env:
        return _normalize_api_url(env)

    return _normalize_api_url(DEFAULT_API_URL)


BASE_URL = _resolve_base_url()

mcp = MCPServer(
    "Armory",
    version=__version__,
    instructions=(
        "You have access to the Armory security platform database for the current "
        "penetration test engagement. Use these tools to explore discovered hosts, "
        "ports, vulnerabilities, domains, and CIDRs. You can also create, update, "
        "and delete records — DELETE cascades through Django foreign keys, so "
        "deleting a host removes its ports and vulnerability links. Severity scale: "
        "0=informational, 1=low, 2=medium, 3=high, 4=critical."
    ),
)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _http(method: str, path: str, params: dict = None, body: dict = None) -> dict | list:
    try:
        r = httpx.request(
            method,
            f"{BASE_URL}{path}",
            params={k: v for k, v in (params or {}).items() if v is not None and v != ""},
            json=body,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}", "detail": e.response.text[:300]}
    except httpx.RequestError as e:
        return {"error": f"Cannot reach Armory API at {BASE_URL}", "detail": str(e)}


def _get(path: str, **params) -> dict | list:
    return _http("GET", path, params=params)


def _post(path: str, body: dict) -> dict:
    return _http("POST", path, body=body)


def _patch(path: str, body: dict) -> dict:
    return _http("PATCH", path, body=body)


def _delete(path: str) -> dict:
    return _http("DELETE", path)


def _fmt(data) -> str:
    return json.dumps(data, indent=2)


def _build_body(**kwargs) -> dict:
    """Strip keys whose value is None. Empty strings ARE kept so callers can
    explicitly clear text fields like notes."""
    return {k: v for k, v in kwargs.items() if v is not None}


# ── Stats & search ────────────────────────────────────────────────────────────

@mcp.tool()
def get_stats() -> str:
    """
    Return aggregate counts for the entire Armory database: total hosts broken
    down by scope, completion, and recon status; port counts (including recon
    status); vulnerability counts by severity; domain counts (including recon
    status); and CIDR counts. Call this first to understand the size and scope
    of the engagement before drilling in.
    """
    return _fmt(_get("/stats"))


@mcp.tool()
def search(query: str) -> str:
    """
    Cross-entity keyword search across hosts (IP and domain), domains,
    vulnerability names, and service names. Returns up to 20 matches per
    category. Use this for quick lookups when you know a string but not the
    database ID.

    Args:
        query: Search string matched against all entity types simultaneously.
    """
    return _fmt(_get("/search", q=query))


# ── Hosts (IPAddress) ─────────────────────────────────────────────────────────

@mcp.tool()
def list_hosts(
    search: str = "",
    scope: str = "all",
    completed: str = "",
    recon_complete: str = "",
    display_zero: str = "",
    page: int = 1,
    per_page: int = 50,
) -> str:
    """
    List IP addresses in Armory with optional filters. Returns a paginated
    summary of each host including port count, domain count, OS, notes, and
    completion status. Use get_host() on a specific ID to see full port detail.

    Every filter is opt-in — by default this returns every host in the
    database, so the host list always agrees with list_ports().

    Args:
        search:         Substring filter applied to IP address and associated domain names.
        scope:          'active', 'passive', or 'all'. Default: 'all'.
        completed:      Filter by review status — 'true', 'false', or '' (default) for all.
        recon_complete: Filter by recon status — 'true', 'false', or '' (default) for all.
        display_zero:   'false' hides hosts whose only ports are the Nessus
                        general/tcp + general/udp pseudo-ports (port 0), along
                        with hosts that have no ports at all. Default '' keeps them.
        page:           Page number for pagination. Default: 1.
        per_page:       Results per page (1–500). Default: 50.
    """
    return _fmt(_get(
        "/hosts",
        search=search,
        scope=scope,
        completed=completed or None,
        recon_complete=recon_complete or None,
        display_zero=display_zero or None,
        page=page,
        per_page=per_page,
    ))


@mcp.tool()
def get_host(ip_id: int) -> str:
    """
    Retrieve full detail for a single IP address: all ports with service names,
    vulnerability counts, highest severity per port, tool availability flags
    (nmap/gowitness/ffuf/nikto/xss), associated domains, virtual hosts, scope,
    notes, ai_notes (LLM-discovered findings), completion status, and
    recon_complete flag.

    Use list_hosts() or search() first to find the ip_id.

    Args:
        ip_id: Integer ID of the IPAddress record.
    """
    return _fmt(_get(f"/hosts/{ip_id}"))


@mcp.tool()
def create_host(
    ip_address: str,
    os: str = None,
    notes: str = None,
    ai_notes: str = None,
    whois: str = None,
    completed: bool = None,
    recon_complete: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Create a new IP address record. The CIDR for the host is auto-resolved from
    a whois lookup on first save, which requires internet access and may take
    a few seconds.

    Args:
        ip_address:     Required. IPv4 or IPv6 address (e.g. '10.0.0.5').
        os:             Operating system string (default empty).
        notes:          Analyst notes (default empty).
        ai_notes:       Notes for LLM-discovered findings about this host (default empty).
        whois:          Whois text blob (default empty).
        completed:      True to mark the host as fully reviewed.
        recon_complete: True to mark recon as finished for this host.
        active_scope:   True if the host is in active scope.
        passive_scope:  True if the host is in passive scope.
    """
    body = _build_body(
        ip_address=ip_address, os=os, notes=notes, ai_notes=ai_notes, whois=whois,
        completed=completed, recon_complete=recon_complete,
        active_scope=active_scope, passive_scope=passive_scope,
    )
    return _fmt(_post("/hosts", body))


@mcp.tool()
def update_host(
    ip_id: int,
    notes: str = None,
    ai_notes: str = None,
    completed: bool = None,
    recon_complete: bool = None,
    os: str = None,
    whois: str = None,
    ip_address: str = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Update any subset of fields on an existing IP address. At least one field
    must be provided. Pass an empty string to clear text fields.

    Args:
        ip_id:          Required. Integer ID of the IPAddress record.
        notes:          Replace host notes.
        ai_notes:       Replace notes for LLM-discovered findings about this host.
        completed:      True to mark reviewed, False to unmark.
        recon_complete: True to mark recon finished, False to unmark.
        os:             Replace OS string.
        whois:          Replace whois blob.
        ip_address:     Rename the IP (unique — fails on conflict).
        active_scope:   Update active-scope flag.
        passive_scope:  Update passive-scope flag.
    """
    body = _build_body(
        notes=notes, ai_notes=ai_notes, completed=completed,
        recon_complete=recon_complete, os=os, whois=whois,
        ip_address=ip_address, active_scope=active_scope, passive_scope=passive_scope,
    )
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/hosts/{ip_id}", body))


@mcp.tool()
def delete_host(ip_id: int) -> str:
    """
    Delete an IP address. Cascades to all ports, virtualhosts, and
    vulnerability-port links on this host. The vulnerability records themselves
    are not deleted (they may still affect other hosts).

    Args:
        ip_id: Integer ID of the IPAddress record.
    """
    return _fmt(_delete(f"/hosts/{ip_id}"))


# ── Ports ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_ports(
    search: str = "",
    ip: str = "",
    service: str = "",
    recon_complete: str = "",
    page: int = 1,
    per_page: int = 50,
) -> str:
    """
    List ports across all hosts with optional filters. Each result includes the
    parent IP and service info. Use get_port() for full vuln/nmap/gowitness
    detail.

    Args:
        search:         Substring matched against service name or IP address.
        ip:             Restrict to ports on this IP (substring match).
        service:        Restrict to ports with this service name (substring match).
        recon_complete: Filter by recon status — 'true', 'false', or '' for all.
        page:           Page number. Default: 1.
        per_page:       Results per page (1–500). Default: 50.
    """
    return _fmt(_get(
        "/ports",
        search=search or None,
        ip=ip or None,
        service=service or None,
        recon_complete=recon_complete or None,
        page=page,
        per_page=per_page,
    ))


@mcp.tool()
def get_port(port_id: int) -> str:
    """
    Retrieve full detail for a single port: parent IP, service name, status,
    all Nessus vulnerabilities with per-port plugin output, nmap script results,
    and Gowitness data (final URL, response code, response headers). Also
    includes ai_notes (LLM-discovered findings), recon_complete flag, and
    boolean flags indicating which other tools ran against this port.

    Use get_host() first to find port IDs for a given IP.

    Args:
        port_id: Integer ID of the Port record.
    """
    return _fmt(_get(f"/ports/{port_id}"))


@mcp.tool()
def create_port(
    port_number: int,
    proto: str,
    ip_id: int,
    status: str = None,
    service_name: str = None,
    cert: str = None,
    ai_notes: str = None,
    recon_complete: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Create a new port on an existing host.

    Args:
        port_number:    Required. 1–65535.
        proto:          Required. 'tcp' or 'udp'.
        ip_id:          Required. ID of the parent IPAddress.
        status:         Port status (default 'open').
        service_name:   Service name (e.g. 'http', 'ssh'). Auto-normalized.
        cert:           TLS cert text blob.
        ai_notes:       Notes for LLM-discovered findings about this port (default empty).
        recon_complete: True to mark recon as finished for this port.
        active_scope:   Active-scope flag.
        passive_scope:  Passive-scope flag.
    """
    body = _build_body(
        port_number=port_number, proto=proto, ip_id=ip_id,
        status=status, service_name=service_name, cert=cert, ai_notes=ai_notes,
        recon_complete=recon_complete,
        active_scope=active_scope, passive_scope=passive_scope,
    )
    return _fmt(_post("/ports", body))


@mcp.tool()
def update_port(
    port_id: int,
    port_number: int = None,
    proto: str = None,
    ip_id: int = None,
    status: str = None,
    service_name: str = None,
    cert: str = None,
    ai_notes: str = None,
    recon_complete: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Update any subset of fields on an existing port. At least one field must
    be provided.

    Args:
        port_id:        Required. Integer ID of the Port record.
        port_number:    New port number (1–65535).
        proto:          New proto ('tcp' or 'udp').
        ip_id:          Move the port to a different IPAddress.
        status:         New port status.
        service_name:   New service name.
        cert:           New TLS cert blob.
        ai_notes:       Replace notes for LLM-discovered findings about this port.
        recon_complete: True to mark recon finished, False to unmark.
        active_scope:   Active-scope flag.
        passive_scope:  Passive-scope flag.
    """
    body = _build_body(
        port_number=port_number, proto=proto, ip_id=ip_id,
        status=status, service_name=service_name, cert=cert, ai_notes=ai_notes,
        recon_complete=recon_complete,
        active_scope=active_scope, passive_scope=passive_scope,
    )
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/ports/{port_id}", body))


@mcp.tool()
def delete_port(port_id: int) -> str:
    """
    Delete a port. Cascades to any virtualhosts and tool-runs bound to it.
    Vulnerability records are unlinked but not deleted.

    Args:
        port_id: Integer ID of the Port record.
    """
    return _fmt(_delete(f"/ports/{port_id}"))


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@mcp.tool()
def list_vulns(
    severity_min: int = None,
    severity_max: int = None,
    search: str = "",
    ip: str = "",
    exploitable: str = "",
    page: int = 1,
    per_page: int = 50,
) -> str:
    """
    List Nessus vulnerabilities with optional filters. Results are sorted by
    severity descending. Severity scale: 0=informational, 1=low, 2=medium,
    3=high, 4=critical.

    Args:
        severity_min: Minimum severity inclusive (0–4). Omit for no lower bound.
        severity_max: Maximum severity inclusive (0–4). Omit for no upper bound.
        search:       Substring filter on vulnerability name.
        ip:           Restrict to vulns affecting this IP address (substring match).
        exploitable:  'true' for exploitable only, 'false' for non-exploitable only.
        page:         Page number. Default: 1.
        per_page:     Results per page (1–500). Default: 50.
    """
    return _fmt(_get(
        "/vulns",
        severity_min=severity_min,
        severity_max=severity_max,
        search=search or None,
        ip=ip or None,
        exploitable=exploitable or None,
        page=page,
        per_page=per_page,
    ))


@mcp.tool()
def get_vuln(vuln_id: int) -> str:
    """
    Retrieve full detail for a single vulnerability: description, remediation
    guidance, CVEs, exploitability flag, and every affected port with the
    per-port Nessus plugin output.

    Use list_vulns() first to find the vuln_id.

    Args:
        vuln_id: Integer ID of the Vulnerability record.
    """
    return _fmt(_get(f"/vulns/{vuln_id}"))


@mcp.tool()
def create_vuln(
    name: str,
    severity: int,
    description: str = None,
    remediation: str = None,
    source: str = None,
    exploitable: bool = None,
    port_ids: list = None,
) -> str:
    """
    Create a new vulnerability. Name is unique — duplicates return 409.

    Args:
        name:         Required. Unique vulnerability name.
        severity:     Required. 0=informational … 4=critical.
        description:  Long-form description.
        remediation:  Remediation guidance text.
        source:       Tool source label (default 'nessus').
        exploitable:  Mark exploitable.
        port_ids:     List of Port IDs to associate with this vuln.
    """
    body = _build_body(
        name=name, severity=severity, description=description,
        remediation=remediation, source=source, exploitable=exploitable,
        port_ids=port_ids,
    )
    return _fmt(_post("/vulns", body))


@mcp.tool()
def update_vuln(
    vuln_id: int,
    name: str = None,
    severity: int = None,
    description: str = None,
    remediation: str = None,
    source: str = None,
    exploitable: bool = None,
    port_ids: list = None,
) -> str:
    """
    Update fields on an existing vulnerability. At least one field required.
    Passing port_ids REPLACES the entire affected-port set.

    Args:
        vuln_id:     Required. Integer ID of the Vulnerability record.
        name:        Rename (must remain unique).
        severity:    New severity 0–4.
        description: Replace description text.
        remediation: Replace remediation text.
        source:      Replace source label.
        exploitable: Toggle exploitable flag.
        port_ids:    Replace the list of affected Port IDs.
    """
    body = _build_body(
        name=name, severity=severity, description=description,
        remediation=remediation, source=source, exploitable=exploitable,
        port_ids=port_ids,
    )
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/vulns/{vuln_id}", body))


@mcp.tool()
def delete_vuln(vuln_id: int) -> str:
    """
    Delete a vulnerability and all its port associations and VulnOutput rows.

    Args:
        vuln_id: Integer ID of the Vulnerability record.
    """
    return _fmt(_delete(f"/vulns/{vuln_id}"))


# ── Vuln output (per-port proof / plugin output) ───────────────────────────────

@mcp.tool()
def list_vuln_outputs(
    vuln_id: int = 0,
    port_id: int = 0,
    ip: str = "",
    search: str = "",
    full: str = "",
    page: int = 1,
    per_page: int = 50,
) -> str:
    """
    List VulnOutput rows — the per-port evidence attached to a vulnerability
    (Nessus plugin output, and the proof written back during hunting and
    validation). One row exists per (vulnerability, port) pair.

    Returns a 300-character preview of each row by default; pass full='true'
    to get the complete text, or use get_vuln_output() on a single row.

    Args:
        vuln_id:  Restrict to one vulnerability. 0 (default) for all.
        port_id:  Restrict to one port. 0 (default) for all.
        ip:       Restrict to rows whose port belongs to this IP (substring match).
        search:   Substring matched against the output text and the vuln name.
        full:     'true' returns the complete data for every row instead of a preview.
        page:     Page number. Default: 1.
        per_page: Results per page (1-500). Default: 50.
    """
    return _fmt(_get(
        "/vuln_outputs",
        vuln_id=vuln_id or None,
        port_id=port_id or None,
        ip=ip or None,
        search=search or None,
        full=full or None,
        page=page,
        per_page=per_page,
    ))


@mcp.tool()
def get_vuln_output(output_id: int) -> str:
    """
    Retrieve one VulnOutput row in full: the complete evidence text plus the
    parent vulnerability, port, and IP it belongs to.

    Use list_vuln_outputs() to find the output_id.

    Args:
        output_id: Integer ID of the VulnOutput record.
    """
    return _fmt(_get(f"/vuln_outputs/{output_id}"))


@mcp.tool()
def set_vuln_output(
    vuln_id: int,
    port_id: int,
    data: str,
    append: bool = False,
) -> str:
    """
    Write the per-host evidence for a vulnerability on a specific port. This
    is an upsert on the (vuln_id, port_id) pair — it creates the row if none
    exists and overwrites it otherwise. The port is also added to the
    vulnerability's affected-port set, so it shows up in get_vuln().

    Convention: the client-facing overview belongs in the vulnerability's
    description; this row holds the proof for one host — request/response,
    command transcript, or validation block.

    Args:
        vuln_id: Required. Integer ID of the Vulnerability record.
        port_id: Required. Integer ID of the Port the evidence came from.
        data:    Required. The evidence text.
        append:  True appends to the existing row (separated by a newline)
                 instead of replacing it — use this to add a dated VALIDATION
                 block without discarding the original output.
    """
    return _fmt(_post("/vuln_outputs", _build_body(
        vuln_id=vuln_id, port_id=port_id, data=data, append=append or None,
    )))


@mcp.tool()
def delete_vuln_output(output_id: int) -> str:
    """
    Delete a single VulnOutput row. The vulnerability, the port, and their
    association all remain — only the evidence text for that pair is removed.

    Args:
        output_id: Integer ID of the VulnOutput record.
    """
    return _fmt(_delete(f"/vuln_outputs/{output_id}"))


# ── Domains ───────────────────────────────────────────────────────────────────

@mcp.tool()
def list_domains(
    search: str = "",
    scope: str = "all",
    recon_complete: str = "",
    page: int = 1,
    per_page: int = 50,
) -> str:
    """
    List domains discovered during the engagement. Each result includes the
    base domain, scope, and all associated IP addresses.

    Args:
        search:         Substring filter on domain name.
        scope:          'active', 'passive', or 'all'. Default: 'all'.
        recon_complete: Filter by recon status — 'true', 'false', or '' for all.
        page:           Page number. Default: 1.
        per_page:       Results per page (1–500). Default: 50.
    """
    return _fmt(_get(
        "/domains",
        search=search or None,
        scope=scope,
        recon_complete=recon_complete or None,
        page=page,
        per_page=per_page,
    ))


@mcp.tool()
def get_domain(domain_id: int) -> str:
    """
    Retrieve full detail for a single domain: name, base domain, scope flags,
    dynamic-IP flag, whois blob, ai_notes (LLM-discovered findings),
    recon_complete flag, and all associated IP addresses.

    Args:
        domain_id: Integer ID of the Domain record.
    """
    return _fmt(_get(f"/domains/{domain_id}"))


@mcp.tool()
def create_domain(
    name: str,
    whois: str = None,
    ai_notes: str = None,
    recon_complete: bool = None,
    dynamic_ip: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
    ip_ids: list = None,
) -> str:
    """
    Create a new domain. The base domain is derived automatically from the
    name; on creation a post-save hook performs DNS resolution to attach IPs
    (this can be slow). If you pass ip_ids, those IDs replace the auto-derived
    set after the initial save.

    Note: if the active_scope/passive_scope of an existing base domain conflicts
    with the values you pass, the base-domain values win on create.

    Args:
        name:           Required. FQDN, e.g. 'mail.example.com'.
        whois:          Whois blob.
        ai_notes:       Notes for LLM-discovered findings about this domain (default empty).
        recon_complete: True to mark recon as finished for this domain.
        dynamic_ip:     Mark as dynamic-IP host.
        active_scope:   Active-scope flag.
        passive_scope:  Passive-scope flag.
        ip_ids:         Optional list of IPAddress IDs to attach.
    """
    body = _build_body(
        name=name, whois=whois, ai_notes=ai_notes, recon_complete=recon_complete,
        dynamic_ip=dynamic_ip,
        active_scope=active_scope, passive_scope=passive_scope, ip_ids=ip_ids,
    )
    return _fmt(_post("/domains", body))


@mcp.tool()
def update_domain(
    domain_id: int,
    name: str = None,
    whois: str = None,
    ai_notes: str = None,
    recon_complete: bool = None,
    dynamic_ip: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
    ip_ids: list = None,
) -> str:
    """
    Update fields on an existing domain. At least one field required.
    Passing ip_ids REPLACES the entire associated-IP set.

    Note: updates bypass Domain.save() (an upstream Armory quirk where the
    override is a no-op for existing rows) and write directly via .update(),
    so post-save signals do not fire.

    Args:
        domain_id:      Required. Integer ID of the Domain record.
        name:           Rename (must remain unique).
        whois:          Replace whois blob.
        ai_notes:       Replace notes for LLM-discovered findings about this domain.
        recon_complete: True to mark recon finished, False to unmark.
        dynamic_ip:     Update dynamic-IP flag.
        active_scope:   Update active-scope flag.
        passive_scope:  Update passive-scope flag.
        ip_ids:         Replace the list of associated IPAddress IDs.
    """
    body = _build_body(
        name=name, whois=whois, ai_notes=ai_notes, recon_complete=recon_complete,
        dynamic_ip=dynamic_ip,
        active_scope=active_scope, passive_scope=passive_scope, ip_ids=ip_ids,
    )
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/domains/{domain_id}", body))


@mcp.tool()
def delete_domain(domain_id: int) -> str:
    """
    Delete a domain. The associated IPAddress records are not affected (only
    the link from this domain to them is removed).

    Args:
        domain_id: Integer ID of the Domain record.
    """
    return _fmt(_delete(f"/domains/{domain_id}"))


# ── CIDRs ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_cidrs(
    search: str = "",
    scope: str = "all",
    page: int = 1,
    per_page: int = 50,
) -> str:
    """
    List CIDR ranges in Armory. Each result includes the org name, scope,
    network size, and whether the range is a cloud provider range.

    Args:
        search:   Substring filter on CIDR notation or org name.
        scope:    'active', 'passive', or 'all'. Default: 'all'.
        page:     Page number. Default: 1.
        per_page: Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/cidrs", search=search or None, scope=scope, page=page, per_page=per_page))


@mcp.tool()
def get_cidr(cidr_id: int) -> str:
    """
    Retrieve full detail for a single CIDR: name, org, size, scope flags,
    cloud flag, and the number of child IP addresses.

    Args:
        cidr_id: Integer ID of the CIDR record.
    """
    return _fmt(_get(f"/cidrs/{cidr_id}"))


@mcp.tool()
def create_cidr(
    name: str,
    org_name: str = None,
    size: int = None,
    cloud: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Create a new CIDR. If org_name is omitted, a whois lookup is performed
    on first save to populate org_name and size (requires internet).

    Args:
        name:          Required. CIDR notation, e.g. '10.0.0.0/24'.
        org_name:      Organization name (skip to auto-resolve via whois).
        size:          Network size (auto-set if name was omitted).
        cloud:         Mark as cloud-provider range.
        active_scope:  Active-scope flag.
        passive_scope: Passive-scope flag.
    """
    body = _build_body(
        name=name, org_name=org_name, size=size, cloud=cloud,
        active_scope=active_scope, passive_scope=passive_scope,
    )
    return _fmt(_post("/cidrs", body))


@mcp.tool()
def update_cidr(
    cidr_id: int,
    name: str = None,
    org_name: str = None,
    size: int = None,
    cloud: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Update fields on an existing CIDR. At least one field required.

    Args:
        cidr_id:       Required. Integer ID of the CIDR record.
        name:          Rename (must remain unique).
        org_name:      Replace org name.
        size:          Update network size.
        cloud:         Update cloud-provider flag.
        active_scope:  Update active-scope flag.
        passive_scope: Update passive-scope flag.
    """
    body = _build_body(
        name=name, org_name=org_name, size=size, cloud=cloud,
        active_scope=active_scope, passive_scope=passive_scope,
    )
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/cidrs/{cidr_id}", body))


@mcp.tool()
def delete_cidr(cidr_id: int) -> str:
    """
    Delete a CIDR. CASCADES to every IPAddress in this CIDR — and through them,
    every Port, VirtualHost, and vuln link. Use with extreme caution.

    Args:
        cidr_id: Integer ID of the CIDR record.
    """
    return _fmt(_delete(f"/cidrs/{cidr_id}"))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    args = _build_parser().parse_args()

    # stdio takes no bind options; the http transports take them as run kwargs.
    kwargs = {} if args.transport == "stdio" else {
        "host": args.host,
        "port": args.port,
    }

    mcp.run(transport=args.transport, **kwargs)


if __name__ == "__main__":
    main()
