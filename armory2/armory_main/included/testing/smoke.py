"""
The checks every Armory tool gets for free.

These run against every module, report, and webapp whether or not it ships a
``Tests`` class of its own, and they are deliberately about *wiring* rather
than behaviour: does the file import, does ``set_options()`` work, does
``--help`` render, does a report survive a run against a populated database,
does every webapp page come back without a 500.

Two tiers:

* default -- things that mean the tool is broken.
* ``--strict`` -- conventions from CLAUDE.md (name matches filename, class has
  a docstring, templates extend ``base_tw.html``). These flag style drift, not
  breakage, so they stay out of the default run.

A tool opts out of an individual check by setting the matching flag on its own
``Tests`` class::

    class Tests(ModuleTest):
        smoke_get_targets = False   # get_targets needs a live API key

Recognised flags are listed in ``SMOKE_FLAGS``.
"""

import json
import os
import re
import string

from armory2.armory_main.included.ModuleTemplate import (
    ModuleTemplate,
    ToolTemplate,
)
from armory2.armory_main.included.ReportTemplate import ReportTemplate
from armory2.armory_main.included.TestTemplate import (
    ArmoryTest,
    ModuleTest,
    ReportTest,
    WebappTest,
)
from armory2.armory_main.included.testing import discovery

#: Flags a tool's ``Tests`` class may set to steer the built-in checks.
SMOKE_FLAGS = {
    # modules
    "smoke_get_targets": True,      # call get_targets() with default args
    "smoke_build_cmd": True,        # call build_cmd() with default args
    # reports
    "smoke_run": True,              # run the report against the fixture data
    "smoke_run_args": [],           # argv used for that run
    # webapps
    "smoke_urls": True,             # GET every parameterless URL
    # shared
    "smoke_source_checks": True,    # leftover debugger statements
}

DEBUGGER_RE = re.compile(r"(?<![\w.])(pdb\s*\.\s*set_trace\s*\(|breakpoint\s*\()")

#: A page that 500s is broken. Anything else is a legitimate answer -- 404 for
#: a route that needs data, 401/403 for the API, 405 for a POST-only view.
BAD_STATUS = 500


def _source_of(path):
    with open(path, "r", errors="replace") as handle:
        return handle.read()


def _required_flags(parser):
    """
    Flags/positionals argparse will refuse to run without. A tool that has any
    cannot be smoke-run with an empty command line, which is a design choice
    rather than a defect.
    """
    required = []
    for action in getattr(parser, "_actions", []):
        if action.option_strings:
            if action.required:
                required.append(action.option_strings[-1])
        elif action.nargs not in ("?", "*") and action.dest != "help":
            required.append(action.dest)
    return required


def _debugger_lines(source):
    hits = []
    for number, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if DEBUGGER_RE.search(stripped):
            hits.append("%d: %s" % (number, stripped))
    return hits


class _SourceChecks(object):
    """Checks that read the tool's source rather than running it."""

    def test_no_leftover_debugger(self):
        if not self.smoke_source_checks:
            self.skipTest("disabled by the tool's Tests class")
        path = self.armory_target.source_file
        if not os.path.exists(path):
            self.skipTest("no source file at %s" % path)
        hits = _debugger_lines(_source_of(path))
        self.assertEqual(
            hits, [], "%s has active debugger statements:\n  %s"
            % (self.armory_target.name, "\n  ".join(hits)),
        )


# ---------------------------------------------------------------------------
# modules
# ---------------------------------------------------------------------------


class ModuleSmokeTest(_SourceChecks, ModuleTest):
    """Built-in checks for a module."""

    def setUp(self):
        # Bypass ModuleTest.setUp: building the module is itself one of the
        # things under test, so a failure there should be one failing test
        # rather than an error on every test in the class.
        ArmoryTest.setUp(self)
        self.module = None
        self.setup_error = None
        try:
            self.module = self.new_module()
        except Exception as exc:  # noqa: BLE001 - reported as a test failure
            self.setup_error = exc

    def _require_module(self):
        if self.module is None:
            self.fail("set_options() raised %r" % (self.setup_error,))
        return self.module

    def _is_tool(self):
        return isinstance(self.module, ToolTemplate)

    def test_declares_module_class(self):
        cls = getattr(self.armory_module, "Module", None)
        self.assertIsNotNone(
            cls, "%s.py defines no `class Module`" % self.armory_target.name
        )
        self.assertTrue(
            issubclass(cls, ModuleTemplate),
            "%s.Module does not subclass ModuleTemplate" % self.armory_target.name,
        )

    def test_set_options_succeeds(self):
        module = self._require_module()
        self.assertTrue(
            hasattr(module, "options"),
            "set_options() did not set self.options -- did it call super()?",
        )

    def test_help_renders(self):
        module = self._require_module()
        self.assertTrue(module.options.format_help().strip())

    def test_parses_empty_args(self):
        module = self._require_module()
        required = _required_flags(module.options)
        if required:
            self.skipTest("requires %s" % ", ".join(required))
        args, _ = module.options.parse_known_args([])
        self.assertIsNotNone(args)

    def test_name_is_set(self):
        module = self._require_module()
        self.assertTrue(
            (getattr(module, "name", "") or "").strip(),
            "%s.Module has no name attribute" % self.armory_target.name,
        )

    def test_run_is_overridden_or_tool(self):
        module = self._require_module()
        if self._is_tool():
            self.skipTest("ToolTemplate provides run()")
        self.assertIsNot(
            type(module).run, ModuleTemplate.run,
            "%s never overrides run(), so it does nothing"
            % self.armory_target.name,
        )

    # -- ToolTemplate specifics -----------------------------------------

    def test_tool_declares_a_binary(self):
        module = self._require_module()
        if not self._is_tool():
            self.skipTest("not a ToolTemplate")
        self.assertTrue(
            module.binary_name or module.docker_name,
            "%s wraps a tool but declares neither binary_name nor docker_name"
            % self.armory_target.name,
        )

    def test_get_targets_returns_a_list(self):
        module = self._require_module()
        if not self._is_tool():
            self.skipTest("not a ToolTemplate")
        if not self.smoke_get_targets:
            self.skipTest("disabled by the tool's Tests class")
        required = _required_flags(module.options)
        if required:
            self.skipTest("requires %s" % ", ".join(required))
        targets = self.get_targets()
        self.assertIsInstance(
            targets, (list, tuple),
            "get_targets() returned %r, expected a list of dicts" % type(targets),
        )
        for target in targets:
            self.assertIsInstance(target, dict)

    def test_build_cmd_placeholders_are_satisfiable(self):
        module = self._require_module()
        if not self._is_tool():
            self.skipTest("not a ToolTemplate")
        if not self.smoke_build_cmd:
            self.skipTest("disabled by the tool's Tests class")
        required = _required_flags(module.options)
        if required:
            self.skipTest("requires %s" % ", ".join(required))

        args = self.parse()
        args.output_path = os.path.join(self.tmpdir, "output")
        module.args = args
        module.binary = module.binary_name or "tool"
        cmd = module.build_cmd(args)
        self.assertIsInstance(cmd, str, "build_cmd() must return a string")

        if not self.smoke_get_targets:
            return
        targets = self.get_targets(args)
        if not targets:
            self.skipTest("no targets in the fixture database to check against")

        placeholders = {
            field for _, field, _, _ in string.Formatter().parse(cmd) if field
        }
        missing = placeholders - set(targets[0])
        self.assertEqual(
            missing, set(),
            "build_cmd() uses %s, which get_targets() does not provide (it "
            "returns %s)" % (sorted(missing), sorted(targets[0])),
        )

    # -- strict / convention --------------------------------------------

    def test_name_matches_filename(self):
        if not self.strict:
            self.skipTest("convention check; run with --strict")
        module = self._require_module()
        self.assertEqual(
            module.name, self.armory_target.name,
            "name is %r but the file is %s.py -- `armory -m %s` and the "
            "default output path use the filename"
            % (module.name, self.armory_target.name, self.armory_target.name),
        )

    def test_has_docstring(self):
        if not self.strict:
            self.skipTest("convention check; run with --strict")
        doc = (getattr(self.armory_module, "Module", None).__doc__ or "").strip()
        self.assertTrue(
            doc, "%s.Module has no docstring, so `armory -m %s -M` explains "
            "nothing" % (self.armory_target.name, self.armory_target.name),
        )


# ---------------------------------------------------------------------------
# reports
# ---------------------------------------------------------------------------


class ReportSmokeTest(_SourceChecks, ReportTest):
    """Built-in checks for a report."""

    def setUp(self):
        ArmoryTest.setUp(self)
        self.report = None
        self.setup_error = None
        try:
            self.report = self.new_report()
        except Exception as exc:  # noqa: BLE001 - reported as a test failure
            self.setup_error = exc

    def _require_report(self):
        if self.report is None:
            self.fail("set_options() raised %r" % (self.setup_error,))
        return self.report

    def test_declares_report_class(self):
        cls = getattr(self.armory_module, "Report", None)
        self.assertIsNotNone(
            cls, "%s.py defines no `class Report`" % self.armory_target.name
        )
        self.assertTrue(
            issubclass(cls, ReportTemplate),
            "%s.Report does not subclass ReportTemplate" % self.armory_target.name,
        )

    def test_set_options_succeeds(self):
        report = self._require_report()
        self.assertTrue(
            hasattr(report, "options"),
            "set_options() did not set self.options -- did it call super()?",
        )

    def test_help_renders(self):
        report = self._require_report()
        self.assertTrue(report.options.format_help().strip())

    def test_parses_empty_args(self):
        report = self._require_report()
        required = _required_flags(report.options)
        if required:
            self.skipTest("requires %s" % ", ".join(required))
        args, _ = report.options.parse_known_args([])
        self.assertIsNotNone(args)

    def test_inherits_base_options(self):
        report = self._require_report()
        for flag in ("--json", "--output", "--clipboard"):
            self.assertHasOption(flag, report=report)

    def test_run_is_overridden(self):
        self.assertIsNot(
            self.armory_module.Report.run, ReportTemplate.run,
            "%s never overrides run(), so it produces nothing"
            % self.armory_target.name,
        )

    def _check_runnable(self):
        self._require_report()
        if not self.smoke_run:
            self.skipTest("disabled by the tool's Tests class")
        if not self.smoke_run_args:
            required = _required_flags(self.report.options)
            if required:
                self.skipTest(
                    "requires %s; set smoke_run_args on the report's Tests "
                    "class to cover this" % ", ".join(required)
                )

    def test_runs_against_sample_data(self):
        self._check_runnable()
        self.run_report(*self.smoke_run_args)

    def test_json_output_is_valid(self):
        self._check_runnable()
        raw = self.run_report("-j", *self.smoke_run_args)
        if raw is None:
            # The report chose not to emit anything for this data, which is a
            # legitimate path -- test_runs_against_sample_data covers crashes.
            self.skipTest("the report produced no output for the sample data")
        json.loads(raw)

    # -- strict / convention --------------------------------------------

    def test_name_matches_filename(self):
        if not self.strict:
            self.skipTest("convention check; run with --strict")
        report = self._require_report()
        self.assertEqual(
            report.name, self.armory_target.name,
            "name is %r but the file is %s.py"
            % (report.name, self.armory_target.name),
        )

    def test_has_docstring(self):
        if not self.strict:
            self.skipTest("convention check; run with --strict")
        doc = (self.armory_module.Report.__doc__ or "").strip()
        self.assertTrue(
            doc, "%s.Report has no docstring, so `armory -r %s -R` explains "
            "nothing" % (self.armory_target.name, self.armory_target.name),
        )


# ---------------------------------------------------------------------------
# webapps
# ---------------------------------------------------------------------------

REQUIRED_CONFIG_KEYS = ("name", "pretty_name", "description", "category", "authors")


class WebappSmokeTest(WebappTest):
    """Built-in checks for a webapp."""

    sample_data = True

    def test_config_json_is_valid(self):
        path = os.path.join(self.target_path, "config.json")
        self.assertTrue(os.path.exists(path), "%s has no config.json" % path)
        config = discovery.webapp_config(self.armory_target)
        missing = [k for k in REQUIRED_CONFIG_KEYS if not config.get(k)]
        self.assertEqual(
            missing, [],
            "config.json is missing %s -- the nav dropdown is built from these"
            % missing,
        )

    def test_config_name_matches_directory(self):
        config = discovery.webapp_config(self.armory_target)
        self.assertEqual(
            config.get("name"), self.armory_target.name,
            "config.json name is %r but the directory is %r; the directory is "
            "the URL prefix and a mismatched name shadows the wrong webapp"
            % (config.get("name"), self.armory_target.name),
        )

    def test_urls_module_loads(self):
        urls = discovery.load_webapp_urls(self.armory_target)
        patterns = getattr(urls, "urlpatterns", None)
        self.assertIsInstance(patterns, list, "urls.py defines no urlpatterns list")
        self.assertTrue(patterns, "urls.py defines an empty urlpatterns")

    def test_views_module_loads(self):
        path = os.path.join(self.target_path, "views.py")
        self.assertTrue(os.path.exists(path), "%s has no views.py" % self.target_path)
        discovery.load_webapp_views(self.armory_target)

    def test_registered_with_the_app(self):
        from django.apps import apps

        webapps = apps.app_configs["armory_main"].webapps
        self.assertIn(
            self.armory_target.name, webapps,
            "%s is not in the webapp registry, so it will not appear in the "
            "Armory nav dropdown" % self.armory_target.name,
        )

    def test_pages_do_not_error(self):
        if not self.smoke_urls:
            self.skipTest("disabled by the tool's Tests class")

        checked = []
        for pattern in self.urlpatterns():
            route = str(getattr(pattern, "pattern", ""))
            if getattr(pattern.pattern, "converters", None):
                continue  # needs arguments; a tool's own Tests can cover those
            response = self.get(route)
            checked.append(route)
            self.assertLess(
                response.status_code, BAD_STATUS,
                "GET %s returned %s"
                % (self.url(route), response.status_code),
            )
        if not checked:
            self.skipTest("no parameterless routes")

    # -- strict / convention --------------------------------------------

    def test_templates_extend_the_tailwind_base(self):
        if not self.strict:
            self.skipTest("convention check; run with --strict")
        template_dir = os.path.join(self.target_path, "templates")
        if not os.path.isdir(template_dir):
            self.skipTest("no templates directory")

        legacy = []
        for root, _, files in os.walk(template_dir):
            for name in files:
                if not name.endswith(".html"):
                    continue
                path = os.path.join(root, name)
                head = _source_of(path).lstrip()[:200]
                if "extends" in head and "armory_main/base.html" in head:
                    legacy.append(os.path.relpath(path, self.target_path))
        self.assertEqual(
            legacy, [],
            "these templates still extend the legacy Bootstrap base; new work "
            "should extend armory_main/base_tw.html:\n  %s" % "\n  ".join(legacy),
        )


SMOKE_CLASSES = {
    "module": ModuleSmokeTest,
    "report": ReportSmokeTest,
    "webapp": WebappSmokeTest,
}
