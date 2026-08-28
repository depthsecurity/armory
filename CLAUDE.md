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

`ARMORY_API_EXEC_ENABLED` (default `True`, also readable from the environment)
toggles shell execution through the API (see **Shell execution**).

---

## Modules

### Rules
- **Filename = CLI name**: `Foo.py` is invoked as `armory -m Foo`. Use valid Python identifiers (no hyphens).
- Every module file exposes exactly one class: `class Module(...)`.
- Always call `super().set_options()` first inside `set_options`.
- Use `armory2.armory_main.models` (Port, Domain, IPAddress, …) for all DB reads/writes.
- Use `armory2.armory_main.included.utilities.color_display` for console output — never `print`.
- New modules go in `armory_custom/modules/` (custom tree) or `armory_main/included/modules/` (core).
- A module may carry `class Tests(ModuleTest)` in the same file — see **Testing**.

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
- A report may carry `class Tests(ReportTest)` in the same file — see **Testing**.

### Verify after adding
```bash
armory -lr            # report appears in list
armory -r <Name> -h   # help renders correctly
```

---

## Webapps

### Rules
- Each webapp is a **directory**; the directory name becomes its URL prefix (`/host_scoping/`, …).
- Required files: `config.json`, `urls.py`, `views.py`; optionally `templates/`, `static/`, and `tests.py` holding `class Tests(WebappTest)` — see **Testing**.
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
clients (Claude Code, Claude Desktop) as ~70 CRUD tools covering every Armory
model — hosts, ports, virtual hosts, vulns, vuln outputs, domains, root
domains, CIDRs, URLs, users, credentials, CVEs, tags, and the tool-run
history — plus shell execution on the Armory host (see **Shell execution**).

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

### Virtual hosts

`/armory_api/virtualhosts` is full CRUD over `VirtualHost` — the hostnames known
to be served by an IP. MCP wrappers: `list_virtualhosts`, `get_virtualhost`,
`create_virtualhost`, `update_virtualhost`, `delete_virtualhost`.

Two model behaviors leak through the API and are worth knowing before touching
these views:

- **`(ip_address, port, name)` is the natural key.** Armory's own modules
  `get_or_create` on that triple (see the `post_save` hooks in
  `models/network.py`), so `POST` does the same: an existing row comes back with
  `"created": false` and HTTP 200 instead of a duplicate. A null `port_id` is
  the legitimate host-wide row that applies to every port.
- **The name drives the Domain link.** `VirtualHost.save()` resolves an empty
  `domain` from the vhost name and creates the `Domain` (and `BaseDomain`) when
  it does not exist. So a `PATCH` that renames a vhost without naming a
  `domain_id` clears the link on purpose and lets `save()` re-resolve it;
  passing `domain_id` in the same PATCH wins.

A port may only be attached to a vhost on the same IP — the views reject the
mismatch rather than letting an inconsistent row through. `/armory_api/stats`
and `/armory_api/search` both cover virtual hosts.

### People, findings metadata, and history

The rest of the model layer is covered by five more endpoint groups. They follow
the same conventions as everything above (`@csrf_exempt` + `@require_api_key`,
paginated list, `POST` = get_or_create where the model has a natural key).

| Endpoints | Model | Notes |
|---|---|---|
| `/urls` | `Url` | get_or_create on `(port_id, name, method)`. |
| `/users` | `User` | Email is the unique key. The root domain resolves from the email address unless `basedomain_id`/`domain` is given, and is created if new — the same path `TheHarvester` takes. |
| `/creds` | `Cred` | Owner given as `user_id` **or** `email` (an unknown email creates the user). Requires `password` or `passhash`; get_or_create on `(user, password, passhash)` so replaying a dump does not duplicate rows. `DELETE /users/<id>` cascades to creds. |
| `/cves` | `CVE` | get_or_create on name. Link from the vuln side with `cve_ids`/`cve_names` on `POST`/`PATCH /vulns` — `cve_names` creates unknown CVEs. `/vulns/<id>` now returns CVE objects, not bare names. |
| `/basedomains` | `BaseDomain` | List/get/update only. Root domains are created implicitly, and renaming one would orphan its child domains, so `name` is not writable and there is no create or delete. |
| `/toolruns` | `ToolRun` | Read-only. `?ip=` matches runs recorded against the host, its ports (both the generic relation and the `port_obj` FK), and its virtual hosts. |

MCP wrappers exist for all of these. There is deliberately no `get_url`,
`get_cred`, or `get_toolrun` tool — those models serialize identically in list
and detail, so the list tool with a filter is the same call.

### Tags

`Tag` is an M2M on `IPAddress`, `Port`, `Domain`, `BaseDomain`, `User`, and
`Cred`, and every one of those endpoints now reads and writes it.

- Every serializer includes `tags`; the list querysets `prefetch_related('tags')`
  to keep it one query.
- `tag_ids` (by id) or `tag_names` (by name, created if new) on `POST`/`PATCH`
  **replace** the record's whole tag list. Passing both is an error.
- `POST /armory_api/tags/<id>/apply` with `{action: add|remove, ip_ids, port_ids,
  domain_ids, basedomain_ids, user_ids, cred_ids}` adds or removes one tag
  without a read-modify-write. This is the MCP `apply_tag` tool, and it is what
  an agent should reach for.
- `Tag.type` gates what a tag may be attached to, mirroring the
  `limit_choices_to` on the model fields: `ip` covers hosts and ports, `domain`
  covers domains and root domains, `cred` covers users and creds, `any` fits
  everywhere. `TAG_KIND` in `views.py` holds that mapping, and a mismatch is a
  400 rather than a silently wrong row.

### Shell execution

`POST /armory_api/exec` runs a raw shell command on the host running
`armory-web` and returns its exit code, stdout, and stderr, so an MCP client can
proxy engagement tooling through Armory instead of needing its own shell there.
The MCP wrappers are `run_command`, `get_command`, `list_commands`, and
`kill_command`.

The work happens in `armory_api/exec_runner.py`. Commands go through bash with
`shell=True` and `start_new_session=True`, so pipes and redirection work and a
kill takes down the whole process tree, not just the shell. Each job keeps up to
1 MB per stream (`DEFAULT_MAX_OUTPUT`) and reports `stdout_truncated` /
`stdout_bytes` when it overflows.

| Field | Meaning |
|---|---|
| `timeout` | Seconds before the process group is killed. Default 60, ceiling 3600 (`MAX_TIMEOUT`). |
| `background` | `true` returns a job id immediately; poll `GET /armory_api/exec/<job_id>`. Output is captured while the job runs, so partial output is readable. |
| `cwd` / `env` | Working directory (must exist) and extra environment variables. |
| `tail` | Return only the last N characters of each stream. |
| `status` | `running`, `finished`, `timed_out`, `killed`, or `failed`. |

`GET /armory_api/exec/<job_id>?wait=N` blocks up to N seconds for completion;
`DELETE` on the same URL kills the job but leaves its record and captured output
readable. `GET /armory_api/exec` lists jobs (summaries, no output).

The job registry is an in-memory dict in the `armory-web` process — jobs are
gone after a restart, and completed jobs are pruned past `MAX_JOBS` (200).

Two gates in `_exec_unavailable()` in the API's `views.py`:

- `ARMORY_API_EXEC_ENABLED = False` in `~/.armory/settings.py` (or the matching
  env var) turns the endpoint off — 403.
- Execution is refused outright while `SECRET_KEY` is the built-in default,
  which is public; otherwise anyone who can reach the port has a shell. Set a
  `SECRET_KEY` first.

This is RCE by design. Keep `armory-web` bound to localhost, or disable the
endpoint on any host where the API is reachable more widely.

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
| `Tag` | Cross-cutting labels; M2M on IPAddress, Port, Domain, BaseDomain, User, Cred |
| `ToolRun` | History of which tool ran against which host/port/vhost |
| `ArmoryTask` | django-q2 task bookkeeping — the one model with no API surface |

After adding or changing model fields, create and apply a migration:
```bash
armory-manage makemigrations
armory-manage migrate
```

---

## Testing

Tests live **inside the thing they test**, so a module, report, or webapp
carries its own coverage wherever it lives — core tree or `armory_custom`.

```bash
armory -t                     # test every module, report, and webapp
armory -t Nmap ScopeReport    # test just these
armory -t -k webapp           # restrict to a kind (module/report/webapp)
armory -lt                    # list testable tools + whether they ship tests
armory -t --strict            # also run the convention checks
armory -t -v                  # list every test, not just the failures
armory -t --only get_targets  # only tests whose name contains this
armory -t --no-smoke          # only tools' own Tests, skip the built-in checks
armory-test ...               # same thing, as its own entry point
```

Everything runs against a **throwaway database** (in memory, for the default
SQLite config) with each test wrapped in a transaction that is rolled back —
the real project database is never written to. Tool output is swallowed unless
a test fails, in which case it is replayed as part of the failure.

### Where tests go

| Kind | Location | Class |
|---|---|---|
| Module | same file as `class Module` | `class Tests(ModuleTest)` |
| Report | same file as `class Report` | `class Tests(ReportTest)` |
| Webapp | `<webapp>/tests.py` | `class Tests(WebappTest)` |

Base classes come from `armory2.armory_main.included.TestTemplate`. They are
`django.test.TestCase` subclasses, so every `unittest` assertion is available.
Working examples: `modules/SampleModule.py`, `modules/SampleToolModule.py`,
`reports/SampleReport.py`, `webapps/host_scoping/tests.py`.

```python
from armory2.armory_main.included.TestTemplate import ModuleTest

class Tests(ModuleTest):
    def test_targets_come_from_the_database(self):
        targets = self.get_targets(self.parse("--import_database"))
        self.assertIn("192.0.2.10:80", [t["target"] for t in targets])
```

### What every test gets

`self.data` is the sample dataset built fresh for each test class
(`included/testing/fixtures.py`): a CIDR `192.0.2.0/24`, hosts `.10`/`.11`,
ports 80/443/22, `www.example.com` / `mail.example.com`, a virtual host, a
vulnerability with a CVE and an output row, a URL, a user, a cred, and a tag.
It is deliberately offline — creating an IP outside a known CIDR fires an RDAP
lookup and creating a `Domain` fires DNS, so the fixture pre-creates the CIDR
and marks domains `meta['offlinedns']`. Set `sample_data = False` on the test
class to start empty. `self.tmpdir` is a scratch directory, removed afterwards.

| Base class | Provides |
|---|---|
| `ModuleTest` | `self.module` (fresh, `set_options()` applied, `base_config` pointed at `tmpdir`), `parse(*argv)`, `get_targets(args)`, `build_cmd(args)`, `run_module(*argv)` (adds `--no_binary`), `assertHasOption`, `assertBinaryAvailable` (skips when the tool is not installed) |
| `ReportTest` | `self.report` (with `silent_run` on), `run_report(*argv)` → the rendered output, `run_report_json(*argv)` → parsed JSON |
| `WebappTest` | `self.client` (session already authenticated, so `ARMORY_WEB_*` need not be unset), `self.get/post(path)` relative to the webapp prefix, `assertRenders(path, status)`, `self.config`, `urlpatterns()` |

### Built-in smoke tests

Every tool is checked even with no `Tests` class of its own
(`included/testing/smoke.py`): the file imports, `set_options()` works and
called `super()`, `--help` renders, no leftover `pdb.set_trace()`; for
`ToolTemplate` modules that a binary or docker image is declared, that
`get_targets()` returns a list of dicts and that `build_cmd()` only uses
placeholders `get_targets()` supplies; for reports that they run against the
sample data and that `-j` emits valid JSON; for webapps that `config.json` is
complete and matches the directory name, that `urls.py` and `views.py` load,
that the webapp is in the nav registry, and that every parameterless route
answers without a 500.

`--strict` adds the CLAUDE.md conventions: `name` matches the filename, the
tool class has a docstring, webapp templates extend `base_tw.html`.

A tool opts out of an individual check from its own `Tests` class:

```python
class Tests(ReportTest):
    smoke_run = False          # this report needs a live API key
    smoke_run_args = ["-s", "active"]   # ...or just needs arguments
```

Flags: `smoke_get_targets`, `smoke_build_cmd`, `smoke_run`, `smoke_run_args`,
`smoke_urls`, `smoke_source_checks` (see `SMOKE_FLAGS` in `smoke.py`). Checks
that cannot apply — a report with required arguments, a webapp with no
parameterless route — skip themselves rather than failing.

### Adding a check for every tool

New built-in checks go on the matching class in `included/testing/smoke.py`.
Gate anything that is a convention rather than breakage behind
`if not self.strict: self.skipTest(...)`, and add an opt-out flag to
`SMOKE_FLAGS` if a legitimate tool could fail it.

### Linting

```bash
flake8 setup.py docs armory2 tests                # lint (ignores E501)
```

The legacy `tests/` directory predates this framework and its `setup.py test`
invocation no longer exists.

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
