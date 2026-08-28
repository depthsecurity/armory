"""
Finding the things Armory can test.

Modules, reports, and webapps all live in two places -- the built-in trees
under ``armory_main/included/`` and any number of custom trees named by
``ARMORY_CUSTOM_MODULES`` / ``ARMORY_CUSTOM_REPORTS`` / ``ARMORY_CUSTOM_WEBAPPS``
in ``~/.armory/settings.py``. Custom trees win on a name collision, matching
how ``armory -m`` resolves modules and how ``settings.py`` registers webapp
templates.

A tool's tests live inside the tool: modules and reports declare
``class Tests`` in the same file as ``Module`` / ``Report``, and a webapp
declares one in ``tests.py`` next to its ``config.json``.
"""

import glob
import importlib
import importlib.util
import json
import os
import pkgutil
import sys
from collections import namedtuple

from django.conf import settings

#: kind      -- 'module', 'report', or 'webapp'
#: name      -- the name the CLI knows it by
#: path      -- directory holding it (the tree for modules/reports, the webapp
#:              directory itself for webapps)
#: source_file -- the file the tool's code lives in
#: source    -- 'core' or 'custom'
Target = namedtuple("Target", "kind name path source_file source")

MODULE_DIR = "armory_main/included/modules"
REPORT_DIR = "armory_main/included/reports"
WEBAPP_DIR = "armory_main/included/webapps"

#: Names that are scaffolding rather than tools.
SKIP_NAMES = {"templates", "__init__", "__pycache__"}

# Cache so a module imported for discovery is not imported again per test class.
_loaded = {}


def _armory_root():
    import armory2

    return os.path.dirname(os.path.abspath(armory2.__file__))


def _config(key):
    return settings.ARMORY_CONFIG.get(key) or []


def _is_tool_name(name):
    if name in SKIP_NAMES or "." in name or not name.isidentifier():
        return False
    # ModuleTemplate.py / ReportTemplate.py and their custom-tree copies are
    # base classes, not tools.
    return not name.endswith("Template")


def _scan_python_tree(kind, tree, source):
    found = []
    if not os.path.isdir(tree):
        return found
    for _, name, ispkg in pkgutil.iter_modules([tree]):
        if ispkg or not _is_tool_name(name):
            continue
        found.append(
            Target(
                kind=kind,
                name=name,
                path=tree,
                source_file=os.path.join(tree, name + ".py"),
                source=source,
            )
        )
    return found


def _merge(core, custom):
    """Custom trees shadow built-ins of the same name."""
    merged = {t.name: t for t in core}
    merged.update({t.name: t for t in custom})
    return sorted(merged.values(), key=lambda t: t.name.lower())


def discover_modules():
    core = _scan_python_tree("module", os.path.join(_armory_root(), MODULE_DIR), "core")
    custom = []
    for tree in _config("ARMORY_CUSTOM_MODULES"):
        custom += _scan_python_tree("module", os.path.expanduser(tree), "custom")
    return _merge(core, custom)


def discover_reports():
    core = _scan_python_tree("report", os.path.join(_armory_root(), REPORT_DIR), "core")
    custom = []
    for tree in _config("ARMORY_CUSTOM_REPORTS"):
        custom += _scan_python_tree("report", os.path.expanduser(tree), "custom")
    return _merge(core, custom)


def _scan_webapp_tree(tree, source):
    found = []
    for path in sorted(glob.glob(os.path.join(tree, "*/"))):
        name = os.path.basename(path.rstrip("/"))
        if name in SKIP_NAMES or not os.path.exists(os.path.join(path, "config.json")):
            continue
        found.append(
            Target(
                kind="webapp",
                name=name,
                path=path.rstrip("/"),
                source_file=os.path.join(path.rstrip("/"), "views.py"),
                source=source,
            )
        )
    return found


def discover_webapps():
    core = _scan_webapp_tree(os.path.join(_armory_root(), WEBAPP_DIR), "core")
    custom = []
    for tree in _config("ARMORY_CUSTOM_WEBAPPS"):
        custom += _scan_webapp_tree(os.path.expanduser(tree), "custom")
    return _merge(core, custom)


KINDS = {
    "module": discover_modules,
    "report": discover_reports,
    "webapp": discover_webapps,
}


def discover(kinds=None, names=None):
    """
    Return the targets to test.

    ``kinds`` restricts to any of 'module'/'report'/'webapp'; ``names`` is a
    list of tool names (case-insensitive) to keep. A name that matches nothing
    is returned as an ``unknown`` entry so the caller can complain about it.
    """
    kinds = list(kinds or KINDS)
    targets = []
    for kind in kinds:
        targets += KINDS[kind]()

    if not names:
        return targets, []

    wanted = {n.lower() for n in names}
    kept = [t for t in targets if t.name.lower() in wanted]
    unknown = sorted(wanted - {t.name.lower() for t in kept})
    return kept, unknown


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def _load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec so a module that imports itself (or is imported by
    # something it imports) does not get executed twice.
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


def load(target):
    """
    Import the code for a target and return the python module object.

    For a webapp this is its ``tests.py`` (or None when it has none) -- a
    webapp's views are reached through the URL router, not imported directly.
    Raises whatever the tool's own import raises.
    """
    key = (target.kind, target.name, target.source_file)
    if key in _loaded:
        return _loaded[key]

    if target.kind == "webapp":
        tests_path = os.path.join(target.path, "tests.py")
        module = (
            _load_file("armory_webapp_tests_%s" % target.name, tests_path)
            if os.path.exists(tests_path)
            else None
        )
    elif target.source == "core":
        pkg = MODULE_DIR if target.kind == "module" else REPORT_DIR
        dotted = "armory2." + pkg.replace("/", ".") + "." + target.name
        module = importlib.import_module(dotted)
    else:
        module = _load_file(target.name, target.source_file)

    _loaded[key] = module
    return module


def load_webapp_urls(target):
    """Load a webapp's ``urls.py`` the same way ``armory2/urls.py`` does."""
    return _load_file("armory_webapp_urls_%s" % target.name,
                      os.path.join(target.path, "urls.py"))


def load_webapp_views(target):
    return _load_file("armory_webapp_views_%s" % target.name,
                      os.path.join(target.path, "views.py"))


def webapp_config(target):
    with open(os.path.join(target.path, "config.json"), "r") as handle:
        return json.load(handle)


def tests_class(target):
    """
    Return the target's ``Tests`` class, or None. Any import error is raised to
    the caller so it can be reported as a failure rather than a missing tool.
    """
    module = load(target)
    if module is None:
        return None
    cls = getattr(module, "Tests", None)
    return cls if isinstance(cls, type) else None


def describe(target):
    return "%s/%s" % (target.kind + "s", target.name)
