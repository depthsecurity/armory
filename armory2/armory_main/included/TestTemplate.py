#!/usr/bin/python
"""
Base classes for Armory's in-tree test framework.

Every module, report, and webapp -- built-in or custom -- may ship its own
tests. Modules and reports declare a ``class Tests`` inside the same file that
holds ``Module`` / ``Report``; a webapp declares one in a ``tests.py`` beside
its ``config.json``. ``armory -t`` discovers them, spins up an isolated test
database, and runs them alongside a set of built-in smoke tests.

    from armory2.armory_main.included.TestTemplate import ModuleTest

    class Tests(ModuleTest):
        def test_targets_come_from_the_database(self):
            args = self.parse("--hosts_database")
            self.assertIn("192.0.2.10", [t["target"] for t in self.get_targets(args)])

These are ``django.test.TestCase`` subclasses, so every ``assert*`` method from
``unittest`` is available, each test runs inside a transaction that is rolled
back afterwards, and the database is a throwaway -- the real project database
is never touched.

Sample data (a CIDR, hosts, ports, domains, vhosts, a vuln, a user, a cred) is
created once per test class and reachable as ``self.data``; see
``armory2.armory_main.included.testing.fixtures``. Set ``sample_data = False``
on the test class to start from an empty database instead.
"""

import contextlib
import io
import json
import os
import shutil
import tempfile

from django.test import TestCase as _DjangoTestCase

from armory2.armory_main.included.utilities import which


class ArmoryTest(_DjangoTestCase):
    """
    Common base for every Armory test. Not used directly -- pick
    ``ModuleTest``, ``ReportTest``, or ``WebappTest``.
    """

    # Populated by the discovery layer before the suite is built.
    armory_target = None      # testing.discovery.Target for the tool under test
    armory_module = None      # the imported python module (None for webapps)

    #: Build the standard sample dataset before the class's tests run.
    sample_data = True

    #: Set by the runner when --strict is passed; convention checks honour it.
    strict = False

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.data = None
        if cls.sample_data:
            from armory2.armory_main.included.testing import fixtures

            cls.data = fixtures.build_sample_data()

    def setUp(self):
        super().setUp()
        # Anything a tool writes to disk lands here and is removed afterwards,
        # so a test run never scribbles into the real project directory.
        self.tmpdir = tempfile.mkdtemp(prefix="armory-test-")
        self.addCleanup(shutil.rmtree, self.tmpdir, True)

    # -- helpers ---------------------------------------------------------

    @property
    def target_name(self):
        return self.armory_target.name

    @property
    def target_path(self):
        return self.armory_target.path

    def read_source(self):
        """Return the source of the tool under test as a string."""
        path = self.armory_target.source_file
        with open(path, "r", errors="replace") as handle:
            return handle.read()

    @contextlib.contextmanager
    def captured_output(self):
        """
        Capture everything the code under test prints::

            with self.captured_output() as out:
                self.run_module()
            self.assertIn("Running!", out.getvalue())
        """
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            yield buf

    def assertBinaryAvailable(self, name=None):
        """Skip the test (rather than fail) when an external tool is absent."""
        name = name or getattr(self.armory_module.Module, "binary_name", "")
        if not name:
            self.skipTest("no binary_name declared")
        if not which.run(name):
            self.skipTest("%s is not installed on this host" % name)
        return which.run(name)


class ModuleTest(ArmoryTest):
    """
    Base class for a module's ``class Tests``.

    ``self.module`` is a fresh, fully-configured instance of the module under
    test, with its ``base_config`` pointed at a temporary directory so nothing
    escapes into the real project folder.
    """

    #: argv prepended to every ``parse()`` / ``run_module()`` call.
    default_args = []

    def setUp(self):
        super().setUp()
        self.module = self.new_module()

    def new_module(self):
        """Return a fresh module instance with ``set_options()`` applied."""
        from armory2.armory_cmd import get_config_options

        module = self.armory_module.Module()
        module.set_options()
        config = dict(get_config_options())
        config["ARMORY_BASE_PATH"] = self.tmpdir
        module.base_config = config
        return module

    def parse(self, *argv, module=None):
        """
        Parse argv into the module's namespace, applying the same tool_args /
        profile normalisation ``ToolTemplate.run()`` does, so ``get_targets``
        and ``build_cmd`` see what they would see in a real run.
        """
        module = module or self.module
        argv = list(self.default_args) + [str(a) for a in argv]
        args, _ = module.options.parse_known_args(argv)
        _normalize_tool_args(args)
        module.args = args
        return args

    def get_targets(self, args=None):
        """Call the module's ``get_targets`` with a safe output path."""
        args = args if args is not None else self.parse()
        if hasattr(args, "output_path"):
            args.output_path = os.path.join(self.tmpdir, "output")
        self.module.args = args
        return self.module.get_targets(args)

    def build_cmd(self, args=None):
        args = args if args is not None else self.parse()
        self.module.args = args
        self.module.binary = getattr(self.module, "binary", "/bin/true")
        return self.module.build_cmd(args)

    def run_module(self, *argv, no_binary=True):
        """
        Run the module end to end. ``--no_binary`` is added by default so an
        external tool is never actually executed; pass ``no_binary=False`` to
        really run the binary (guard that with ``assertBinaryAvailable``).
        """
        argv = list(argv)
        if no_binary and "--no_binary" not in argv:
            if _accepts_option(self.module, "--no_binary"):
                argv.append("--no_binary")
        args = self.parse(*argv)
        if hasattr(args, "output_path"):
            args.output_path = os.path.join(self.tmpdir, "output")
        return self.module.run(args)

    def assertHasOption(self, flag, module=None):
        module = module or self.module
        self.assertTrue(
            _accepts_option(module, flag),
            "%s does not accept %s" % (self.target_name, flag),
        )


class ReportTest(ArmoryTest):
    """
    Base class for a report's ``class Tests``.

    ``self.report`` is a fresh instance with ``set_options()`` applied and
    ``silent_run`` enabled, so ``run_report()`` returns the rendered output
    instead of printing it.
    """

    default_args = []

    def setUp(self):
        super().setUp()
        self.report = self.new_report()

    def new_report(self):
        from armory2.armory_cmd import get_config_options

        report = self.armory_module.Report()
        report.set_options()
        report.silent_run = True
        config = dict(get_config_options())
        config["ARMORY_BASE_PATH"] = self.tmpdir
        report.base_config = config
        return report

    def parse(self, *argv, report=None):
        report = report or self.report
        argv = list(self.default_args) + [str(a) for a in argv]
        args, _ = report.options.parse_known_args(argv)
        return args

    def run_report(self, *argv):
        """Run the report and return whatever it handed to ``process_output``."""
        args = self.parse(*argv)
        # Never let a report under test hijack the clipboard or write files
        # the caller did not ask for.
        args.clipboard = False
        if getattr(args, "output", None):
            args.output = os.path.join(self.tmpdir, os.path.basename(args.output))
        self.report.run(args)
        return getattr(self.report, "output", None)

    def run_report_json(self, *argv):
        """Run the report with ``-j`` and return the parsed JSON."""
        raw = self.run_report("-j", *argv)
        return json.loads(raw)

    def assertHasOption(self, flag, report=None):
        report = report or self.report
        self.assertTrue(
            _accepts_option(report, flag),
            "%s does not accept %s" % (self.target_name, flag),
        )


class WebappTest(ArmoryTest):
    """
    Base class for a webapp's ``class Tests`` (in ``<webapp>/tests.py``).

    ``self.client`` is a Django test client with an authenticated session, so
    tests keep working whether or not ARMORY_WEB_USERNAME/PASSWORD are set.
    ``self.config`` is the parsed ``config.json``; ``self.prefix`` is the
    webapp's URL prefix.
    """

    def setUp(self):
        super().setUp()
        from armory2.armory_main.middleware import SESSION_KEY

        session = self.client.session
        session[SESSION_KEY] = True
        session.save()

    @property
    def config(self):
        with open(os.path.join(self.target_path, "config.json"), "r") as handle:
            return json.load(handle)

    @property
    def prefix(self):
        return "/%s/" % self.target_name

    def url(self, path=""):
        return self.prefix + path.lstrip("/")

    def get(self, path="", **kwargs):
        return self.client.get(self.url(path), **kwargs)

    def post(self, path="", data=None, **kwargs):
        return self.client.post(self.url(path), data or {}, **kwargs)

    def assertRenders(self, path="", status=200, **kwargs):
        """GET a path under this webapp and assert the status code."""
        response = self.get(path, **kwargs)
        self.assertEqual(
            response.status_code,
            status,
            "GET %s returned %s, expected %s"
            % (self.url(path), response.status_code, status),
        )
        return response

    def urlpatterns(self):
        """The webapp's own ``urlpatterns``, loaded from its ``urls.py``."""
        from armory2.armory_main.included.testing import discovery

        return getattr(discovery.load_webapp_urls(self.armory_target), "urlpatterns", [])


# ---------------------------------------------------------------------------
# internals shared by the base classes and the built-in smoke tests
# ---------------------------------------------------------------------------


def _accepts_option(tool, flag):
    return flag in getattr(tool.options, "_option_string_actions", {})


def _normalize_tool_args(args):
    """
    Mirror the tool_args/profile munging ``ToolTemplate.run()`` performs before
    it calls ``get_targets``. Harmless on plain ModuleTemplate namespaces.
    """
    if not hasattr(args, "tool_args"):
        return args

    if args.tool_args:
        parts = []
        for token in args.tool_args:
            if " " in token:
                parts.append('"' + token.replace('"', '\\"') + '"')
            else:
                parts.append(token)
        args.tool_args = " ".join(parts)
    else:
        args.tool_args = ""

    for n in (1, 2, 3, 4):
        if getattr(args, "profile%d" % n, False):
            args.tool_args += " " + getattr(args, "profile%d_data" % n, "")
            break

    return args
