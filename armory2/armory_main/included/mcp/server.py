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
    --api-key <KEY>   API key sent to the Armory API in the X-Armory-Key header.
                      Defaults to the Django SECRET_KEY from ~/.armory/settings.py,
                      which is what armory-web checks against, so a local server
                      needs no extra configuration.
    ARMORY_API_URL    Environment variable fallback, used if --url is not given.
                      May include the /armory_api suffix.
    ARMORY_API_KEY    Environment variable fallback, used if --api-key is not
                      given. Handy when the Armory web server is on another host
                      and its settings file is not readable here.
"""

import argparse
import contextlib
import json
import os
import sys
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
    parser.add_argument(
        "--api-key",
        default=None,
        help="Armory API key (default: the SECRET_KEY from ~/.armory/settings.py)",
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


def _django_secret_key() -> str:
    """Read SECRET_KEY out of the Armory Django settings.

    Loading the settings module executes the user's ~/.armory/settings.py, which
    is free to print; on the stdio transport anything on stdout would corrupt the
    JSON-RPC stream, so stdout is redirected to stderr for the duration.
    """
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "armory2.armory2.settings")
    try:
        with contextlib.redirect_stdout(sys.stderr):
            from django.conf import settings as django_settings

            return str(django_settings.SECRET_KEY or "")
    except Exception as e:  # missing config, unreadable settings, no django
        print(
            f"armory-mcp: could not read SECRET_KEY from the Armory settings: {e}",
            file=sys.stderr,
        )
        return ""


def _resolve_api_key() -> str:
    args, _ = _build_parser().parse_known_args()

    if args.api_key:
        return args.api_key

    env = os.environ.get("ARMORY_API_KEY")
    if env:
        return env

    return _django_secret_key()


BASE_URL = _resolve_base_url()
API_KEY = _resolve_api_key()

if not API_KEY:
    print(
        "armory-mcp: no API key resolved -- every request will be rejected. "
        "Set SECRET_KEY in ~/.armory/settings.py, or pass --api-key / "
        "$ARMORY_API_KEY.",
        file=sys.stderr,
    )

mcp = MCPServer(
    "Armory",
    version=__version__,
    instructions=(
        "You have access to the Armory security platform database for the current "
        "penetration test engagement. Use these tools to explore discovered hosts, "
        "ports, virtual hosts, vulnerabilities, domains, CIDRs, discovered URLs, users, "
        "credentials, CVEs, and tags. You can also create, update, "
        "and delete records — DELETE cascades through Django foreign keys, so "
        "deleting a host removes its ports and vulnerability links. Severity scale: "
        "0=informational, 1=low, 2=medium, 3=high, 4=critical. "
        "run_command() proxies a shell command to the host running armory-web, so "
        "engagement tooling can be driven from wherever Armory lives; long scans "
        "should use background=True and then get_command() to collect output."
    ),
)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

_HTTP_CLIENT = httpx.Client(
    headers={"X-Armory-Key": API_KEY},
    timeout=httpx.Timeout(30.0),
    limits=httpx.Limits(max_connections=20, max_keepalive_connections=20),
)

def _http(method: str, path: str, params: dict = None, body: dict = None,
          timeout: int = 30) -> dict | list:
    try:
        r = _HTTP_CLIENT.request(
            method,
            f"{BASE_URL}{path}",
            params={k: v for k, v in (params or {}).items() if v is not None and v != ""},
            json=body,
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code in (401, 403):
            return {
                "error": f"HTTP {e.response.status_code} — Armory API key rejected",
                "detail": (
                    "armory-mcp and armory-web must resolve the same SECRET_KEY. "
                    "Set it in ~/.armory/settings.py, or pass --api-key / "
                    "$ARMORY_API_KEY to armory-mcp."
                ),
            }
        return {"error": f"HTTP {e.response.status_code}", "detail": e.response.text[:300]}
    except httpx.RequestError as e:
        return {"error": f"Cannot reach Armory API at {BASE_URL}", "detail": str(e)}


def _get(path: str, **params) -> dict | list:
    return _http("GET", path, params=params)


def _post(path: str, body: dict, timeout: int = 30) -> dict:
    return _http("POST", path, body=body, timeout=timeout)


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
def list_recon_targets(
    scope: str = "active",
    completed: str = "false",
    recon_complete: str = "false",
    after_id: int = 0,
    limit: int = 100,
) -> str:
    """Return a compact, cursor-paginated batch of hosts and ports for recon.

    Unlike get_host(), this deliberately omits vulnerability output, certificates,
    Whois data, and other large fields. Use next_after_id from the response as the
    next call's after_id. Defaults select active hosts whose recon and review are
    incomplete.
    """
    return _fmt(_get(
        "/recon/targets",
        scope=scope,
        completed=completed or None,
        recon_complete=recon_complete or None,
        after_id=after_id or None,
        limit=limit,
    ))


@mcp.tool()
def bulk_write_recon_results(
    hosts: list = None,
    ports: list = None,
    dry_run: bool = False,
) -> str:
    """Atomically write a batch of recon results in one Armory request.

    Each entry is an object with `id` and optional `set`, `append`, and
    `expected_modified_at` objects/values. Host append supports notes and
    ai_notes; port append supports ai_notes. A stale expected_modified_at rejects
    the entire batch instead of overwriting another analyst's changes. At most
    500 host and port updates may be submitted together.
    """
    return _fmt(_post("/recon/results/bulk", {
        "hosts": hosts or [],
        "ports": ports or [],
        "dry_run": dry_run,
    }))


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
    tags: list = None,
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
        tags:           Tag names to apply (created if new). REPLACES the
                        record's tag list; use apply_tag() to add or remove one.
    """
    body = _build_body(
        ip_address=ip_address, os=os, notes=notes, ai_notes=ai_notes, whois=whois,
        completed=completed, recon_complete=recon_complete,
        active_scope=active_scope, passive_scope=passive_scope, tag_names=tags,
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
    tags: list = None,
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
        tags:           Tag names to apply (created if new). REPLACES the
                        record's tag list; use apply_tag() to add or remove one.
    """
    body = _build_body(
        notes=notes, ai_notes=ai_notes, completed=completed,
        recon_complete=recon_complete, os=os, whois=whois,
        ip_address=ip_address, active_scope=active_scope, passive_scope=passive_scope,
        tag_names=tags,
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
    tags: list = None,
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
        tags:           Tag names to apply (created if new). REPLACES the
                        record's tag list; use apply_tag() to add or remove one.
    """
    body = _build_body(
        port_number=port_number, proto=proto, ip_id=ip_id,
        status=status, service_name=service_name, cert=cert, ai_notes=ai_notes,
        recon_complete=recon_complete,
        active_scope=active_scope, passive_scope=passive_scope, tag_names=tags,
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
    tags: list = None,
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
        tags:           Tag names to apply (created if new). REPLACES the
                        record's tag list; use apply_tag() to add or remove one.
    """
    body = _build_body(
        port_number=port_number, proto=proto, ip_id=ip_id,
        status=status, service_name=service_name, cert=cert, ai_notes=ai_notes,
        recon_complete=recon_complete,
        active_scope=active_scope, passive_scope=passive_scope, tag_names=tags,
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
    cves: list = None,
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
        cves:         CVE names to link, e.g. ['CVE-2024-3094'] — unknown CVEs are
                      created. REPLACES the vuln's existing CVE links.
    """
    body = _build_body(
        name=name, severity=severity, description=description,
        remediation=remediation, source=source, exploitable=exploitable,
        port_ids=port_ids, cve_names=cves,
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
    cves: list = None,
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
        cves:        CVE names to link, e.g. ['CVE-2024-3094'] — unknown CVEs are
                     created. REPLACES the vuln's existing CVE links.
    """
    body = _build_body(
        name=name, severity=severity, description=description,
        remediation=remediation, source=source, exploitable=exploitable,
        port_ids=port_ids, cve_names=cves,
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
    to get the complete text, or use get_vuln_output() on a single row. Each row
    also carries the URLs linked to it as evidence (see create_url/update_url).

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
    parent vulnerability, port, and IP it belongs to, and any URLs linked to it
    as evidence.

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
    tags: list = None,
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
        tags:           Tag names to apply (created if new). REPLACES the
                        record's tag list; use apply_tag() to add or remove one.
    """
    body = _build_body(
        name=name, whois=whois, ai_notes=ai_notes, recon_complete=recon_complete,
        dynamic_ip=dynamic_ip,
        active_scope=active_scope, passive_scope=passive_scope, ip_ids=ip_ids,
        tag_names=tags,
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
    tags: list = None,
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
        tags:           Tag names to apply (created if new). REPLACES the
                        record's tag list; use apply_tag() to add or remove one.
    """
    body = _build_body(
        name=name, whois=whois, ai_notes=ai_notes, recon_complete=recon_complete,
        dynamic_ip=dynamic_ip,
        active_scope=active_scope, passive_scope=passive_scope, ip_ids=ip_ids,
        tag_names=tags,
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


# ── Virtual hosts ─────────────────────────────────────────────────────────────

@mcp.tool()
def list_virtualhosts(
    search: str = "",
    name: str = "",
    ip: str = "",
    ip_id: int = None,
    port_id: int = None,
    domain: str = "",
    active: str = "",
    scope: str = "all",
    page: int = 1,
    per_page: int = 50,
) -> str:
    """
    List virtual hosts — the hostnames Armory knows are served by a given IP,
    usually one row per (IP, port, hostname). Use this to find every name that
    answers on a host before testing it, since a web port often serves different
    content per Host header.

    Armory also keeps a host-wide row with no port for each name; those come back
    with port_id null.

    Args:
        search:   Substring matched against both the vhost name and the IP.
        name:     Substring filter on the vhost name only.
        ip:       Substring filter on the IP address.
        ip_id:    Only vhosts on this IPAddress id.
        port_id:  Only vhosts bound to this Port id.
        domain:   Substring filter on the linked Domain name.
        active:   'true', 'false', or '' (default) for all.
        scope:    'active', 'passive', or 'all'. Default: 'all'.
        page:     Page number. Default: 1.
        per_page: Results per page (1–500). Default: 50.
    """
    return _fmt(_get(
        "/virtualhosts",
        search=search or None,
        name=name or None,
        ip=ip or None,
        ip_id=ip_id,
        port_id=port_id,
        domain=domain or None,
        active=active or None,
        scope=scope,
        page=page,
        per_page=per_page,
    ))


@mcp.tool()
def get_virtualhost(vh_id: int) -> str:
    """
    Retrieve full detail for a single virtual host: name, the IP and port it is
    bound to (with service name and protocol), the linked Domain, active flag,
    scope flags, and the tool that discovered it.

    Args:
        vh_id: Integer ID of the VirtualHost record.
    """
    return _fmt(_get(f"/virtualhosts/{vh_id}"))


@mcp.tool()
def create_virtualhost(
    ip_id: int,
    name: str,
    port_id: int = None,
    domain_id: int = None,
    active: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Record a hostname served by an IP — e.g. after finding it in a TLS
    certificate, a redirect, or a vhost bruteforce.

    This is get_or_create on (ip_id, port_id, name), which is the same key
    Armory's own modules use, so re-recording a known vhost returns the existing
    row with "created": false instead of duplicating it. Omit port_id for the
    host-wide row that applies to every port.

    If the name is not a bare IP, Armory links it to the matching Domain and
    creates that Domain record when it does not exist yet.

    Args:
        ip_id:         Required. IPAddress id serving this hostname.
        name:          Required. The hostname (e.g. 'admin.example.com').
        port_id:       Port id this vhost was seen on. Omit for a host-wide row.
        domain_id:     Force the Domain link. Omit to let Armory resolve it from the name.
        active:        False to mark the vhost as no longer serving. Default true.
        active_scope:  Active-scope flag.
        passive_scope: Passive-scope flag.
    """
    body = _build_body(
        ip_id=ip_id, name=name, port_id=port_id, domain_id=domain_id,
        active=active, active_scope=active_scope, passive_scope=passive_scope,
    )
    return _fmt(_post("/virtualhosts", body))


@mcp.tool()
def update_virtualhost(
    vh_id: int,
    name: str = None,
    ip_id: int = None,
    port_id: int = None,
    domain_id: int = None,
    active: bool = None,
    active_scope: bool = None,
    passive_scope: bool = None,
) -> str:
    """
    Update fields on an existing virtual host. At least one field required.

    Moving a vhost to a different ip_id requires setting port_id to a port on
    that IP (or clearing it), since a vhost cannot be bound to a port on another
    host.

    Args:
        vh_id:         Required. Integer ID of the VirtualHost record.
        name:          Rename the vhost.
        ip_id:         Move it to a different IPAddress.
        port_id:       Bind it to a different Port.
        domain_id:     Re-link it to a different Domain.
        active:        Mark it serving (true) or no longer serving (false).
        active_scope:  Update active-scope flag.
        passive_scope: Update passive-scope flag.
    """
    body = _build_body(
        name=name, ip_id=ip_id, port_id=port_id, domain_id=domain_id,
        active=active, active_scope=active_scope, passive_scope=passive_scope,
    )
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/virtualhosts/{vh_id}", body))


@mcp.tool()
def delete_virtualhost(vh_id: int) -> str:
    """
    Delete a virtual host record. Cascades to the ToolRun rows recorded against
    it. The IP, port, and Domain it referenced are left alone.

    Prefer update_virtualhost(active=False) when a hostname simply stopped
    resolving — that keeps the history.

    Args:
        vh_id: Integer ID of the VirtualHost record.
    """
    return _fmt(_delete(f"/virtualhosts/{vh_id}"))


# ── Base domains ──────────────────────────────────────────────────────────────

@mcp.tool()
def list_basedomains(search: str = "", scope: str = "all", tag: str = "",
                     page: int = 1, per_page: int = 50) -> str:
    """
    List root domains (e.g. 'example.com') — the parents that subdomains and
    discovered users hang off. Each result carries its child-domain count, user
    count, scope, and tags.

    Args:
        search:   Substring filter on the root domain name.
        scope:    'active', 'passive', or 'all'. Default: 'all'.
        tag:      Only root domains carrying this exact tag name.
        page:     Page number. Default: 1.
        per_page: Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/basedomains", search=search or None, scope=scope,
                     tag=tag or None, page=page, per_page=per_page))


@mcp.tool()
def get_basedomain(basedomain_id: int) -> str:
    """
    Retrieve a root domain in full: DNS records Armory has collected, every
    child domain, user count, scope flags, and tags.

    Args:
        basedomain_id: Integer ID of the BaseDomain record.
    """
    return _fmt(_get(f"/basedomains/{basedomain_id}"))


@mcp.tool()
def update_basedomain(basedomain_id: int, active_scope: bool = None,
                      passive_scope: bool = None, tags: list = None) -> str:
    """
    Update a root domain's scope flags or tags.

    Root domains are created implicitly — by adding a subdomain or a user — and
    renaming one would orphan every child domain, so name is not editable and
    there is no delete.

    Args:
        basedomain_id: Required. Integer ID of the BaseDomain record.
        active_scope:  Active-scope flag.
        passive_scope: Passive-scope flag.
        tags:          REPLACES the tag list with these names (created if new).
                       Use apply_tag() to add or remove a single tag.
    """
    body = _build_body(active_scope=active_scope, passive_scope=passive_scope,
                       tag_names=tags)
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/basedomains/{basedomain_id}", body))


# ── URLs ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_urls(search: str = "", method: str = "", port_id: int = None,
              ip: str = "", vuln_output_id: str = "", vuln_id: int = None,
              scope: str = "all", page: int = 1, per_page: int = 50) -> str:
    """
    List URLs discovered on the engagement, each tied to the port that serves
    it. Use this to see what content enumeration has already turned up on a web
    port before spidering it again.

    A URL may also be linked to the vuln output row it is evidence for; when it
    is, the result carries vuln_output_id, vuln_id, and vuln_name.

    Args:
        search:         Substring filter on the URL.
        method:         Exact HTTP method filter, e.g. 'get' or 'post'.
        port_id:        Only URLs on this Port id.
        ip:             Substring filter on the serving IP address.
        vuln_output_id: Only URLs linked to this VulnOutput id. Pass 'none' for
                        URLs not linked to any finding.
        vuln_id:        Only URLs linked to an output row of this Vulnerability id.
        scope:          'active', 'passive', or 'all'. Default: 'all'.
        page:           Page number. Default: 1.
        per_page:       Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/urls", search=search or None, method=method or None,
                     port_id=port_id, ip=ip or None,
                     vuln_output_id=vuln_output_id or None, vuln_id=vuln_id,
                     scope=scope, page=page, per_page=per_page))


@mcp.tool()
def create_url(port_id: int, name: str, method: str = "get",
               vuln_output_id: int = None,
               active_scope: bool = None, passive_scope: bool = None) -> str:
    """
    Record a discovered URL against the port that serves it — an admin panel, an
    API route, an upload endpoint worth coming back to.

    This is get_or_create on (port_id, name, method), so re-recording a known
    URL returns the existing row with "created": false.

    Args:
        port_id:        Required. Port id serving this URL.
        name:           Required. The URL itself.
        method:         HTTP method. Default: 'get'.
        vuln_output_id: Optionally link this URL to the vuln output row it is
                        evidence for. Many URLs may point at one output row, and
                        that row must be on the same port as the URL.
        active_scope:   Active-scope flag.
        passive_scope:  Passive-scope flag.
    """
    body = _build_body(port_id=port_id, name=name, method=method,
                       vuln_output_id=vuln_output_id,
                       active_scope=active_scope, passive_scope=passive_scope)
    return _fmt(_post("/urls", body))


@mcp.tool()
def update_url(url_id: int, name: str = None, method: str = None, port_id: int = None,
               vuln_output_id: int = None, unlink_vuln_output: bool = False,
               active_scope: bool = None, passive_scope: bool = None) -> str:
    """
    Update fields on a recorded URL. At least one field required.

    Args:
        url_id:             Required. Integer ID of the Url record.
        name:               Replace the URL.
        method:             Replace the HTTP method.
        port_id:            Move it to a different Port. This clears any vuln
                            output link that belonged to the old port.
        vuln_output_id:     Link this URL to the vuln output row it is evidence
                            for. The output row must be on the URL's port.
        unlink_vuln_output: True drops the vuln output link entirely.
        active_scope:       Active-scope flag.
        passive_scope:      Passive-scope flag.
    """
    body = _build_body(name=name, method=method, port_id=port_id,
                       vuln_output_id=vuln_output_id,
                       active_scope=active_scope, passive_scope=passive_scope)
    if unlink_vuln_output:
        body["vuln_output_id"] = None
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/urls/{url_id}", body))


@mcp.tool()
def delete_url(url_id: int) -> str:
    """
    Delete a recorded URL. Nothing else references it — a vuln output row it was
    linked to is left alone.

    Args:
        url_id: Integer ID of the Url record.
    """
    return _fmt(_delete(f"/urls/{url_id}"))


# ── Users ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_users(search: str = "", basedomain_id: int = None, domain: str = "",
               tag: str = "", scope: str = "all", page: int = 1, per_page: int = 50) -> str:
    """
    List discovered user accounts — the OSINT harvest (TheHarvester, LinkedInt,
    PyMeta) plus anything added during testing. Each result shows the email,
    username, name, root domain, tags, and how many credentials are on file.

    Args:
        search:        Substring matched against email, username, first and last name.
        basedomain_id: Only users under this BaseDomain id.
        domain:        Substring filter on the root domain name.
        tag:           Only users carrying this exact tag name.
        scope:         'active', 'passive', or 'all'. Default: 'all'.
        page:          Page number. Default: 1.
        per_page:      Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/users", search=search or None, basedomain_id=basedomain_id,
                     domain=domain or None, tag=tag or None, scope=scope,
                     page=page, per_page=per_page))


@mcp.tool()
def get_user(user_id: int) -> str:
    """
    Retrieve one user in full, including every credential recorded for them
    (plaintext passwords and hashes), job title, location, scope, and tags.

    Args:
        user_id: Integer ID of the User record.
    """
    return _fmt(_get(f"/users/{user_id}"))


@mcp.tool()
def create_user(
    email: str,
    first_name: str = None,
    last_name: str = None,
    user_name: str = None,
    job_title: str = None,
    location: str = None,
    basedomain_id: int = None,
    domain: str = None,
    tags: list = None,
) -> str:
    """
    Record a discovered user account. Email is the unique key, so calling this
    for a known address updates that record and returns "created": false.

    The root domain is resolved automatically from the email address unless you
    pass basedomain_id or domain, and is created if Armory has not seen it.

    Args:
        email:         Required. Email address — the unique key for the record.
        first_name:    Given name.
        last_name:     Family name.
        user_name:     Login name, if it differs from the email local part.
        job_title:     Job title (useful for spray target selection).
        location:      Office or geography.
        basedomain_id: Force the root domain by id.
        domain:        Force the root domain by name (created if new).
        tags:          Tag names to apply (created if new). REPLACES the list.
    """
    body = _build_body(
        email=email, first_name=first_name, last_name=last_name,
        user_name=user_name, job_title=job_title, location=location,
        basedomain_id=basedomain_id, domain=domain, tag_names=tags,
    )
    return _fmt(_post("/users", body))


@mcp.tool()
def update_user(
    user_id: int,
    email: str = None,
    first_name: str = None,
    last_name: str = None,
    user_name: str = None,
    job_title: str = None,
    location: str = None,
    basedomain_id: int = None,
    domain: str = None,
    tags: list = None,
) -> str:
    """
    Update a user record. At least one field required.

    Args:
        user_id:       Required. Integer ID of the User record.
        email:         Replace the email (must stay unique).
        first_name:    Replace the given name.
        last_name:     Replace the family name.
        user_name:     Replace the login name.
        job_title:     Replace the job title.
        location:      Replace the location.
        basedomain_id: Move the user to another root domain by id.
        domain:        Move the user to another root domain by name.
        tags:          REPLACES the tag list. Use apply_tag() to add or remove one.
    """
    body = _build_body(
        email=email, first_name=first_name, last_name=last_name,
        user_name=user_name, job_title=job_title, location=location,
        basedomain_id=basedomain_id, domain=domain, tag_names=tags,
    )
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/users/{user_id}", body))


@mcp.tool()
def delete_user(user_id: int) -> str:
    """
    Delete a user. CASCADES to every credential recorded for them.

    Args:
        user_id: Integer ID of the User record.
    """
    return _fmt(_delete(f"/users/{user_id}"))


# ── Credentials ───────────────────────────────────────────────────────────────

@mcp.tool()
def list_creds(search: str = "", user_id: int = None, source: str = "",
               has_password: str = "", has_hash: str = "", tag: str = "",
               page: int = 1, per_page: int = 50) -> str:
    """
    List credentials recovered on the engagement — sprayed passwords, dumped
    NTDS hashes, config-file secrets. Each row carries the owning user's email.

    Args:
        search:       Substring matched against email, username, password, and source.
        user_id:      Only credentials for this User id.
        source:       Substring filter on where the credential came from.
        has_password: 'true' for plaintext only, 'false' for hash-only rows.
        has_hash:     'true' for rows carrying a hash, 'false' for those without.
        tag:          Only credentials carrying this exact tag name.
        page:         Page number. Default: 1.
        per_page:     Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/creds", search=search or None, user_id=user_id,
                     source=source or None, has_password=has_password or None,
                     has_hash=has_hash or None, tag=tag or None,
                     page=page, per_page=per_page))


@mcp.tool()
def create_cred(
    user_id: int = None,
    email: str = None,
    password: str = None,
    passhash: str = None,
    source: str = None,
    tags: list = None,
) -> str:
    """
    Record a recovered credential. Provide the owner as either user_id or email
    — an unknown email creates the user (and its root domain) first. At least
    one of password or passhash is required.

    Re-recording the same secret for the same user returns the existing row with
    "created": false, so replaying a dump does not duplicate rows.

    Args:
        user_id:  User id owning the credential. Use this or email.
        email:    Owner's email — the user is created if Armory does not know it.
        password: Plaintext password.
        passhash: Password hash (NTLM, bcrypt, whatever the source produced).
        source:   Where it came from, e.g. 'ntds', 'spray', 'web.config'.
        tags:     Tag names to apply (created if new). REPLACES the list.
    """
    body = _build_body(user_id=user_id, email=email, password=password,
                       passhash=passhash, source=source, tag_names=tags)
    return _fmt(_post("/creds", body))


@mcp.tool()
def update_cred(cred_id: int, password: str = None, passhash: str = None,
                source: str = None, user_id: int = None, tags: list = None) -> str:
    """
    Update a credential — typically to add the plaintext after cracking a hash.
    At least one field required.

    Args:
        cred_id:  Required. Integer ID of the Cred record.
        password: Set or replace the plaintext password.
        passhash: Set or replace the hash.
        source:   Replace the source label.
        user_id:  Reassign the credential to another user.
        tags:     REPLACES the tag list. Use apply_tag() to add or remove one.
    """
    body = _build_body(password=password, passhash=passhash, source=source,
                       user_id=user_id, tag_names=tags)
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/creds/{cred_id}", body))


@mcp.tool()
def delete_cred(cred_id: int) -> str:
    """
    Delete a credential. The user it belonged to is left alone.

    Args:
        cred_id: Integer ID of the Cred record.
    """
    return _fmt(_delete(f"/creds/{cred_id}"))


# ── CVEs ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_cves(search: str = "", min_score: float = None, updated: str = "",
              page: int = 1, per_page: int = 50) -> str:
    """
    List CVE records, highest temporal score first, with the number of Armory
    vulnerabilities referencing each one.

    Args:
        search:    Substring matched against the CVE id and its description.
        min_score: Only CVEs at or above this temporal score.
        updated:   'true', 'false', or '' (default) for all.
        page:      Page number. Default: 1.
        per_page:  Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/cves", search=search or None, min_score=min_score,
                     updated=updated or None, page=page, per_page=per_page))


@mcp.tool()
def get_cve(cve_id: int) -> str:
    """
    Retrieve one CVE with its description and every vulnerability linked to it.

    Args:
        cve_id: Integer ID of the CVE record (not the CVE name).
    """
    return _fmt(_get(f"/cves/{cve_id}"))


@mcp.tool()
def create_cve(name: str, description: str = None, temporal_score: float = None,
               updated: bool = None, vuln_ids: list = None) -> str:
    """
    Record a CVE. This is get_or_create on the name, so a CVE that Nessus
    already imported comes back with "created": false and your fields applied.

    To attach a CVE to a finding you can also pass cve_names to create_vuln() or
    update_vuln(), which creates unknown CVEs on the fly.

    Args:
        name:           Required. CVE identifier, e.g. 'CVE-2024-3094'.
        description:    Description text.
        temporal_score: CVSS temporal score.
        updated:        Whether the record has been enriched from a feed.
        vuln_ids:       Vulnerability ids to link — REPLACES the existing links.
    """
    body = _build_body(name=name, description=description,
                       temporal_score=temporal_score, updated=updated,
                       vuln_ids=vuln_ids)
    return _fmt(_post("/cves", body))


@mcp.tool()
def update_cve(cve_id: int, name: str = None, description: str = None,
               temporal_score: float = None, updated: bool = None,
               vuln_ids: list = None) -> str:
    """
    Update a CVE record. At least one field required.

    Args:
        cve_id:         Required. Integer ID of the CVE record.
        name:           Rename the CVE identifier.
        description:    Replace the description.
        temporal_score: Replace the CVSS temporal score.
        updated:        Set the enriched flag.
        vuln_ids:       REPLACES the linked vulnerability list.
    """
    body = _build_body(name=name, description=description,
                       temporal_score=temporal_score, updated=updated,
                       vuln_ids=vuln_ids)
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/cves/{cve_id}", body))


@mcp.tool()
def delete_cve(cve_id: int) -> str:
    """
    Delete a CVE record. Vulnerabilities referencing it survive — they just lose
    the link.

    Args:
        cve_id: Integer ID of the CVE record.
    """
    return _fmt(_delete(f"/cves/{cve_id}"))


# ── Tags ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_tags(search: str = "", type: str = "", page: int = 1, per_page: int = 50) -> str:
    """
    List tags with how many records carry each one. Tags are the cross-cutting
    labels on hosts, ports, domains, root domains, users, and credentials —
    'wordpress', 'dmz', 'domain_admin', whatever the engagement needs.

    Args:
        search:   Substring filter on the tag name.
        type:     Filter by what the tag may be applied to — 'ip', 'domain',
                  'cred', or 'any'.
        page:     Page number. Default: 1.
        per_page: Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/tags", search=search or None, type=type or None,
                     page=page, per_page=per_page))


@mcp.tool()
def get_tag(tag_id: int) -> str:
    """
    Retrieve one tag and everything it is applied to, grouped by record type.
    Use this to answer "what did we mark as X?".

    Args:
        tag_id: Integer ID of the Tag record.
    """
    return _fmt(_get(f"/tags/{tag_id}"))


@mcp.tool()
def create_tag(name: str, type: str = "any") -> str:
    """
    Create a tag. Names are unique, so an existing tag comes back with
    "created": false.

    The type controls what the tag may be attached to: 'ip' covers hosts and
    ports, 'domain' covers domains and root domains, 'cred' covers users and
    credentials, and 'any' (the default) fits everywhere. Applying a tag to the
    wrong kind of record is rejected.

    Args:
        name: Required. Tag name.
        type: 'ip', 'domain', 'cred', or 'any'. Default: 'any'.
    """
    return _fmt(_post("/tags", _build_body(name=name, type=type)))


@mcp.tool()
def update_tag(tag_id: int, name: str = None, type: str = None) -> str:
    """
    Rename a tag or change what it may be applied to. At least one field
    required. Renaming updates the tag everywhere it is already applied.

    Args:
        tag_id: Required. Integer ID of the Tag record.
        name:   New name (must stay unique).
        type:   'ip', 'domain', 'cred', or 'any'.
    """
    body = _build_body(name=name, type=type)
    if not body:
        return json.dumps({"error": "Provide at least one field to update."})
    return _fmt(_patch(f"/tags/{tag_id}", body))


@mcp.tool()
def delete_tag(tag_id: int) -> str:
    """
    Delete a tag, removing it from every record that carries it. The records
    themselves are untouched.

    Args:
        tag_id: Integer ID of the Tag record.
    """
    return _fmt(_delete(f"/tags/{tag_id}"))


@mcp.tool()
def apply_tag(
    tag_id: int,
    action: str = "add",
    ip_ids: list = None,
    port_ids: list = None,
    domain_ids: list = None,
    basedomain_ids: list = None,
    user_ids: list = None,
    cred_ids: list = None,
) -> str:
    """
    Add or remove ONE tag across many records at once, without touching the
    other tags those records carry. Prefer this over the `tags` argument on
    create/update tools, which replaces a record's whole tag list.

    Args:
        tag_id:         Required. Integer ID of the Tag record.
        action:         'add' (default) or 'remove'.
        ip_ids:         Host ids to tag or untag.
        port_ids:       Port ids to tag or untag.
        domain_ids:     Domain ids to tag or untag.
        basedomain_ids: Root domain ids to tag or untag.
        user_ids:       User ids to tag or untag.
        cred_ids:       Credential ids to tag or untag.
    """
    body = _build_body(action=action, ip_ids=ip_ids, port_ids=port_ids,
                       domain_ids=domain_ids, basedomain_ids=basedomain_ids,
                       user_ids=user_ids, cred_ids=cred_ids)
    return _fmt(_post(f"/tags/{tag_id}/apply", body))


# ── Tool runs ─────────────────────────────────────────────────────────────────

@mcp.tool()
def list_toolruns(tool: str = "", ip: str = "", port_id: int = None,
                  virtualhost_id: int = None, target_type: str = "",
                  search: str = "", page: int = 1, per_page: int = 50) -> str:
    """
    Read the history of tools Armory has run, newest first — what ran, with what
    arguments, against which host, port, or virtual host. Check this before
    launching a scan to avoid repeating work someone already did.

    Read-only: entries are written by the modules themselves.

    Args:
        tool:           Substring filter on the tool name, e.g. 'nmap'.
        ip:             Substring filter on the target IP — matches runs against
                        the host, its ports, and its virtual hosts.
        port_id:        Only runs recorded against this Port id.
        virtualhost_id: Only runs recorded against this VirtualHost id.
        target_type:    Filter by target model — 'ipaddress', 'port', 'domain',
                        or 'basedomain'.
        search:         Substring matched against tool name and arguments.
        page:           Page number. Default: 1.
        per_page:       Results per page (1–500). Default: 50.
    """
    return _fmt(_get("/toolruns", tool=tool or None, ip=ip or None,
                     port_id=port_id, virtualhost_id=virtualhost_id,
                     target_type=target_type or None, search=search or None,
                     page=page, per_page=per_page))


# ── Shell command execution ───────────────────────────────────────────────────

@mcp.tool()
def run_command(
    command: str,
    cwd: str = "",
    timeout: int = 60,
    background: bool = False,
    tail: int = 0,
) -> str:
    """
    Run a shell command on the host running armory-web and return its exit code,
    stdout, and stderr. Use this to drive engagement tooling (nmap, curl,
    smbclient, dig, …) from the machine Armory lives on, which is usually the
    machine with network access to the targets.

    The command runs through bash, so pipes, redirection, globbing, and && all
    work. Each command starts in its own process group and is killed — along with
    everything it spawned — when its timeout expires.

    Anything longer than a minute or so should be started with background=True,
    which returns immediately with a job id; poll it with get_command(). Output
    is captured while the job runs, so a background job can be watched.

    Args:
        command:    Required. The shell command line to run.
        cwd:        Working directory. Defaults to the armory-web working directory.
        timeout:    Seconds before the command is killed (1–3600). Default: 60.
        background: True returns a job id immediately instead of waiting.
        tail:       Return only the last N characters of each stream. 0 = all.
    """
    body = _build_body(
        command=command,
        cwd=cwd or None,
        timeout=timeout,
        background=background,
        tail=tail or None,
    )
    # Give the HTTP call room to outlast the command itself.
    http_timeout = 30 if background else max(30, int(timeout) + 30)
    return _fmt(_post("/exec", body, timeout=http_timeout))


@mcp.tool()
def get_command(job_id: str, wait: int = 0, tail: int = 0) -> str:
    """
    Fetch the status and captured output of a command started by run_command().
    Works while the command is still running — stdout and stderr hold everything
    produced so far — and after it has exited.

    Status is one of: running, finished, timed_out, killed, failed.

    Args:
        job_id: Required. Job id returned by run_command().
        wait:   Block up to this many seconds for the job to finish before
                returning. 0 (default) returns the current state immediately.
        tail:   Return only the last N characters of each stream. 0 = all.
    """
    http_timeout = max(30, int(wait) + 30)
    return _fmt(_http(
        "GET",
        f"/exec/{job_id}",
        params={"wait": wait or None, "tail": tail or None},
        timeout=http_timeout,
    ))


@mcp.tool()
def list_commands(status: str = "", search: str = "", limit: int = 20) -> str:
    """
    List command jobs from this armory-web process, newest first, without their
    output. Use it to find a job id you have lost track of, or to see what is
    still running. The list is in-memory only and is emptied when armory-web
    restarts.

    Args:
        status: Filter by state — 'running', 'finished', 'timed_out', 'killed',
                or 'failed'. Default '' returns every job.
        search: Substring filter on the command line.
        limit:  Maximum jobs to return (1–200). Default: 20.
    """
    return _fmt(_get("/exec", status=status or None, search=search or None, limit=limit))


@mcp.tool()
def kill_command(job_id: str) -> str:
    """
    Kill a running command and everything it spawned (the whole process group).
    The job record and whatever output it produced stay readable with
    get_command(). Killing an already-finished job is a no-op.

    Args:
        job_id: Required. Job id returned by run_command().
    """
    return _fmt(_delete(f"/exec/{job_id}"))


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
