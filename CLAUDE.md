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
- Each webapp's `templates/` and `static/` dirs are auto-registered in `settings.py` (globbed at startup); the dashboard nav is built from every webapp's `config.json` via the `get_armory_webapps_grouped` context processor.

### Styling

The UI is mid-migration from Bootstrap to **Tailwind CSS + htmx**. Two base templates exist:

| Template | Use |
|---|---|
| `armory_main/base_tw.html` | **Preferred.** Tailwind shell with the modern nav, dark/light theme slider (persisted to `localStorage`, no-flash init), and htmx loaded. The dashboard (`index.html`) uses this. |
| `armory_main/base.html` | Legacy Bootstrap + jQuery shell. Existing webapps still extend this; leave them until migrated. |

- New/migrated webapp templates should `{% extends 'armory_main/base_tw.html' %}` and define blocks `content`, `extra_head`, `extra_body`.
- Reuse the shared component classes instead of long utility strings (defined in `tailwind/input.css`): `armory-container`, `armory-card` (+ `-body`/`-title`/`-text`), `armory-section-title`, `badge` + `badge-{primary,info,dark,secondary,success,warning,danger}`, `btn` + `btn-{primary,secondary,ghost}`, `armory-input`, `nav-link`/`nav-link-active`. These render without a rebuild.
- Assets are **vendored** (no runtime CDN, works offline): `static/armory_main/css/tailwind.css` and `static/armory_main/js/htmx.min.js`.

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
Reload the Armory web UI; the new entry should appear under the chosen `category` on the dashboard. After editing source, reinstall so the commands pick up changes (`pipx install . --force`, or `flit install --symlink` for an editable install).

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
