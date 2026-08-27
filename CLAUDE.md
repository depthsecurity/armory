# Armory — Claude Code Guide

Armory is a **Python/Django-based security data correlation framework** built by Depth Security. It ingests output from 39+ security tools via pluggable modules, stores findings in a SQLite database, and exposes them through CLI reports and a Django web UI.

The companion custom extensions tree lives at `../armory_custom`; read its `CLAUDE.md` before touching shared conventions.

---

## Repository layout

```
armory2/                        # Installable Python package (flit)
  armory2/settings.py           # Django settings (loads user's ~/.armory/settings.py)
  armory_cmd.py                 # CLI entrypoint — `armory` command
  manage.py                     # Django management shim (armory-manage / armory-web / armory-init)
  shell.py                      # IPython shell entrypoint
  armory_main/
    included/
      ModuleTemplate.py         # Base classes: ModuleTemplate, ToolTemplate, ToolTemplateNoOutput
      ReportTemplate.py         # Base class for all reports
      modules/                  # 39 built-in modules (one class Module per file)
      reports/                  # 13 built-in reports (one class Report per file)
      webapps/                  # 7 built-in Django apps (host_scoping, domain_scoping, …)
      utilities/                # Shared helpers (color_display, nmap, get_urls, …)
    models/                     # Django ORM models
      network.py                # BaseDomain, Domain, IPAddress, CIDR, Port, VirtualHost, ToolRun
      vuln.py                   # Vulnerability, CVE, Url, VulnOutput
      user.py                   # User, Cred
      armory_task.py            # ArmoryTask
    migrations/                 # 36+ Django migrations
    views/                      # Django views for built-in webapps
    urls/                       # URL routing
    templates/armory_main/      # Shared templates: base.html (legacy Bootstrap), base_tw.html (Tailwind), index.html (dashboard)
    static/armory_main/         # Vendored assets: css/tailwind.css (built), js/htmx.min.js, legacy bootstrap/jquery
  default_configs/
    settings.py                 # Template written to ~/.armory/settings.py on first run
tailwind/                       # Tailwind build source (input.css, tailwind.config.js); compiles into static/
pyproject.toml                  # flit build config, entry points, dependencies
tests/                          # unittest suite
```

---

## Entry points

| Command | What it does |
|---|---|
| `armory` | Main CLI — run modules and reports |
| `armory-init` | Run Django migrations (first-time setup) |
| `armory-web` | Start web server on `http://127.0.0.1:8099` |
| `armory-manage` | Raw Django management (`armory-manage <cmd>`) |
| `armory-shell` | IPython shell with all models pre-imported |
| `armory-docker` | Build Docker images for tool modules |
| `armory-mcp` | Start the MCP server (stdio by default) |

```bash
armory -lm                  # list available modules
armory -m <Name> -M         # show module options
armory -m <Name> [options]  # run a module
armory -lr                  # list available reports
armory -r <Name> -R         # show report options
armory -r <Name> [options]  # run a report
```

---

## Configuration

- Config folder: `~/.armory/` (override with `$ARMORY_HOME`)
- Settings file: `~/.armory/settings.py` (override with `$ARMORY_CONFIG`)
- Auto-generated on first `armory` or `armory-init` run from `default_configs/settings.py`

Key settings:
```python
ARMORY_BASE_PATH = "~/armory_project"   # DB and output root
ARMORY_CUSTOM_MODULES = ["/path/to/armory_custom/modules"]
ARMORY_CUSTOM_REPORTS  = ["/path/to/armory_custom/reports"]
ARMORY_CUSTOM_WEBAPPS  = ["/path/to/armory_custom/webapps"]
```

Database defaults to SQLite at `{ARMORY_BASE_PATH}/db.sqlite3`. The task queue (django-q2) requires Redis on `127.0.0.1:6379`.

A `SECRET_KEY` in `~/.armory/settings.py` overrides the built-in Django default
and is the shared secret for the `armory_api` auth header (see **MCP server**).
The generated config creates one on first run and caches it in `~/.armory/api_key`;
configs written before that have none and fall back to the built-in default key,
which is public — set one.

`ARMORY_WEB_USERNAME` / `ARMORY_WEB_PASSWORD` in the same file gate the web UI
(see **Web UI authentication**).

---

## Modules

### Rules
- **Filename = CLI name**: `Foo.py` is invoked as `armory -m Foo`. Use valid Python identifiers (no hyphens).
- Every module file exposes exactly one class: `class Module(...)`.
- Always call `super().set_options()` first inside `set_options`.
- Use `armory2.armory_main.models` (Port, Domain, IPAddress, …) for all DB reads/writes.
- Use `armory2.armory_main.included.utilities.color_display` for console output — never `print`.
- New modules go in `armory_custom/modules/` (custom tree) or `armory_main/included/modules/` (core).

### Base classes (in `armory_main/included/ModuleTemplate.py`)

| Class | When to use |
|---|---|
| `ModuleTemplate` | Pure Python logic, no external binary |
| `ToolTemplate` | Wraps an external binary; override `get_targets`, `build_cmd`, `process_output` |
| `ToolTemplateNoOutput` | Like `ToolTemplate` but captures stdout to a file rather than printing it |

### ToolTemplate key attributes
```python
binary_name = "nmap"          # looked up via which; sets self.binary
docker_name  = "org/image"    # used if binary not found or use_docker=True
use_docker   = False
no_threading = False          # set True for tools that must run serially
```

### Verify after adding
```bash
armory -lm            # module appears in list
armory -m <Name> -h   # argparse help renders correctly
```

---

## Reports

### Rules
- Every report file exposes exactly one class: `class Report(ReportTemplate)`.
- Implement `set_options` (call `super()` first) and `run(self, args)`.
- Call `self.process_output(data, args)` inside `run` — do not write to stdout directly.
- Output formats are handled by `ReportTemplate`: plain, JSON (`-j`), custom markdown (`-c`), clipboard (`-x`), file (`-o`).

### Verify after adding
```bash
armory -lr            # report appears in list
armory -r <Name> -h   # help renders correctly
```

---

## Webapps

### Rules
- Each webapp is a **directory**; the directory name becomes its URL prefix (`/host_scoping/`, …).
- Required files: `config.json`, `urls.py`, `views.py`; optionally `templates/` and `static/`.
- `config.json` must have: `name`, `pretty_name`, `description`, `category`, `authors`.
- Use `armory2.armory_main.models` and core helpers in views.
- Built-in webapps live in `armory_main/included/webapps/`; custom ones go in `armory_custom/webapps/` and are registered via `ARMORY_CUSTOM_WEBAPPS`.
- Each webapp's `templates/` and `static/` dirs are auto-registered in `settings.py` (globbed at startup); the nav dropdown is built from every webapp's `config.json` via the `get_armory_webapps_grouped` context processor.
- **Template shadowing**: custom webapp templates are registered before built-in ones. A custom webapp whose `config.json` `name` matches a built-in will shadow it entirely — both URLs and templates.

### Styling

All webapps use **Tailwind CSS + htmx**. `armory_main/base.html` (Bootstrap) is legacy; do not extend it in new webapps.

All webapp templates should `{% extends 'armory_main/base_tw.html' %}`.

#### Template blocks

| Block | Purpose |
|---|---|
| `{% block content %}` | Main page body |
| `{% block extra_head %}` | Injected into `<head>` — per-page styles, jQuery if needed |
| `{% block extra_body %}` | Injected before `</body>` — page-specific scripts |
| `{% block page_header %}` | Empty by default. Override only to add a custom sub-header below the nav bar (rare). |

#### Nav bar and title

The nav bar is a single **Armory ▾** dropdown grouping all registered webapps by `category`. The page title and theme toggle are in the nav bar — no separate header is rendered by default.

- Pass `'title': 'My Page Name'` from the view. The nav bar displays it (stripping any `"Armory Web - "` prefix via the `| cut` filter).
- Do not include `"Armory Web - "` in `title` values for new webapps.

#### Component classes (defined in `tailwind/input.css`, always available without a rebuild)

`armory-container`, `armory-card` / `armory-card-body` / `armory-card-title` / `armory-card-text`, `armory-section-title`, `armory-input`, `btn` + `btn-{primary,secondary,ghost}`, `badge` + `badge-{primary,info,dark,secondary,success,warning,danger}`, `nav-link` / `nav-link-active`

#### Vendored assets (no CDN — works offline)

- Tailwind CSS: `{% static 'armory_main/css/tailwind.css' %}`
- htmx: `{% static 'armory_main/js/htmx.min.js' %}` — already loaded by `base_tw.html`; do not include again
- jQuery: `{% static 'armory_main/js/jquery-3.5.1.min.js' %}` — not loaded by default; add to `extra_head` if a webapp needs it for existing jQuery-based AJAX patterns. Prefer htmx for new work.

#### Full-height layouts (sidebar + scrollable content)

For pages that need a full-viewport split (sidebar + results area), `<main id="content">` has `py-8` padding by default. Override it in `extra_head`:

```html
{% block extra_head %}
<style>
  #content { padding: 0; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
</style>
{% endblock %}
```

Then structure `{% block content %}` as a flex column — a sticky filter bar, then a `flex flex-1 overflow-hidden` wrapper containing `aside` (sidebar) and a `flex-1 overflow-y-auto` results pane. See `host_summary/templates/host_summary/index.html` for a complete example.

#### Rebuilding Tailwind CSS
Required only after editing `tailwind/input.css` / `tailwind.config.js`, or after adding **new raw utility classes** in a template (component classes from `input.css` always ship). Commit the regenerated CSS.
```bash
cd tailwind
npm install          # first time only
npm run build        # one-off minified build
npm run watch        # rebuild on change during dev
```
See `tailwind/README.md` for details.

### Verify after adding
Reload the Armory web UI; the new entry should appear under the chosen `category` in the Armory nav dropdown. After editing source, reinstall so the commands pick up changes (`pipx install . --force`, or `flit install --symlink` for an editable install).

---

## Web UI authentication

`armory_main/middleware.py` holds `ArmoryWebAuthMiddleware`, which redirects any
request without an authenticated session to `/login/`. Armory has no user table:
the credentials are a single pair in `~/.armory/settings.py`, and a successful
POST to the login view sets `request.session['armory_authenticated']`.

```python
ARMORY_WEB_USERNAME = 'analyst'
ARMORY_WEB_PASSWORD = 'a-long-passphrase'   # or a make_password() hash
```

- **Leave either blank and auth is off** — every request passes through, which is
  what existing configs (and the built-in default config) do.
- `ARMORY_WEB_PASSWORD` may be plaintext or any Django password hash; a value
  starting with a hasher prefix (`pbkdf2_sha256$`, `argon2`, …) is checked with
  `check_password`, anything else with `hmac.compare_digest`.
- Both settings also read from environment variables of the same name, for
  containers.
- Exempt paths: `/armory_api/` (it has its own key header — MCP clients cannot
  log in), `/login/`, `/logout/`, and `STATIC_URL`.
- Websockets get the same gate via `ArmoryWebAuthChannelsMiddleware`, wired
  inside `AuthMiddlewareStack` in `armory2/asgi.py`; an unauthenticated
  `ws/module_runner/` connect is rejected with a 403 handshake.

Because it is middleware, every webapp — built-in or custom — is covered with no
per-view opt-in. New pages need nothing; a page that must be public has to be
added to `is_exempt()` in the middleware.

Login page: `armory_main/templates/armory_main/login.html` (extends
`base_tw.html` with `hide_nav`). The nav bar and dashboard header show a
**Log out** link whenever `request.session.armory_authenticated` is set.

Sessions are the stock Django DB-backed sessions under the cookie name
`armory_session`.

---

## MCP server

`armory2/armory_main/included/mcp/server.py` exposes the Armory database to MCP
clients (Claude Code, Claude Desktop) as ~30 CRUD tools over hosts, ports,
vulns, vuln outputs, domains, and CIDRs.

It is a **client of the `armory_api` webapp**, not a direct ORM consumer — an
`armory-web` instance must be running or every tool returns a connection error.
Adding a tool means adding the API endpoint in
`armory_main/included/webapps/armory_api/views.py` first, then a thin
`@mcp.tool()` wrapper here.

```bash
armory-mcp                                   # stdio (what .mcp.json uses)
armory-mcp --url http://127.0.0.1:8099       # point at a non-default web server
armory-mcp --api-key <key>                   # override the API key (see below)
armory-web --mcp                             # web on 8099 + MCP http on 8100
armory-web --mcp --mcp-port 9000             # pick the MCP port
```

### API authentication

Every `/armory_api/` endpoint is wrapped in `@require_api_key` (defined in the
API's `views.py`) and requires the key as an `X-Armory-Key` header or
`Authorization: Bearer <key>`; missing key → 401, wrong key → 403. The key is
`settings.SECRET_KEY`, compared with `hmac.compare_digest`. New endpoints must
carry the decorator — put it directly under `@csrf_exempt`.

`armory-mcp` resolves the key at import time from `--api-key`, then
`$ARMORY_API_KEY`, then the Django `SECRET_KEY` (loading the settings with
stdout redirected to stderr, since the user config prints and stdout is the
stdio JSON-RPC stream). Local `armory-mcp` + `armory-web` therefore need no
configuration; only a remote client that cannot read `~/.armory/settings.py`
needs the flag or env var.

Any other API client needs the header too:
```bash
curl -H "X-Armory-Key: $(python -c 'import os;os.environ.setdefault("DJANGO_SETTINGS_MODULE","armory2.armory2.settings");from django.conf import settings;print(settings.SECRET_KEY)')" \
     http://127.0.0.1:8099/armory_api/stats
```

`--mcp` runs the server as a child process rather than mounting it into the
Django ASGI app: daphne does not implement the ASGI lifespan protocol, which the
streamable-http app needs to start its session manager. `armory-web` supervises
both and tears them down together on SIGINT/SIGTERM.

The code targets the **mcp 2.x `MCPServer` API** (`pyproject.toml` pins
`mcp>=2.0`). If you port code from a v1 example, the differences are:
`from mcp.server.fastmcp import FastMCP` → `from mcp.server.mcpserver import
MCPServer`, and `mcp.settings.host/port` → `host=`/`port=` kwargs on
`mcp.run()`. `@mcp.tool()` is unchanged.

---

## Models

Core models imported as `from armory2.armory_main.models import ...`:

| Model | Description |
|---|---|
| `BaseDomain` | Root domains with DNS/ASN data |
| `Domain` | Subdomains; FK to BaseDomain and IPAddress |
| `IPAddress` | IP addresses with geolocation |
| `CIDR` | Network ranges with org name |
| `Port` | Open ports; FK to IPAddress |
| `VirtualHost` | Virtual hosts; FK to Domain/IPAddress |
| `Vulnerability` | Vulnerability records with severity/remediation |
| `CVE` | CVE entries with CVSS scores |
| `Url` | Discovered URLs with HTTP methods |
| `User` / `Cred` | Usernames and credentials |

After adding or changing model fields, create and apply a migration:
```bash
armory-manage makemigrations
armory-manage migrate
```

---

## Testing & linting

```bash
coverage run --rcfile .coveragerc setup.py test   # run tests with coverage
coverage report --rcfile .coveragerc -i -m        # show coverage report
flake8 setup.py docs armory2 tests                # lint (ignores E501)
```

Tests use Python `unittest` and live in `tests/`.

---

## Install / dev setup

```bash
pip install flit
flit install --symlink          # editable install; entry points become available
armory-init                     # create ~/.armory/settings.py and run migrations
```

---

## Branch conventions

- Main branch: `main`
- Active feature branches follow standard naming (`feature/`, `fix/`, etc.)
- Do not commit `*.bak`, `*.old.py`, or scratch/debug files (e.g. `dantest.py`)
- Remove `import pdb` / `pdb.set_trace()` before committing
