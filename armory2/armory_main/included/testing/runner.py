"""
The engine behind ``armory -t``.

Creates a throwaway database, builds one suite per tool out of that tool's own
``Tests`` class plus the built-in smoke checks, runs them, and prints a summary
grouped by tool. The real project database is never opened for writing: Django's
test machinery points every connection at a temporary database (in memory, for
the default SQLite config) and each test runs inside a transaction that is
rolled back.

Armory's tools print constantly -- every model save calls ``display_new`` -- so
the whole run happens with stdout redirected. Output captured during a failing
test is replayed as part of that failure; everything else is dropped.
"""

import argparse
import contextlib
import io
import logging
import sys
import time
import traceback
import unittest

from armory2.armory_main.included.utilities.color_display import bcolors, display

from armory2.armory_main.included.testing import discovery, smoke

KIND_ORDER = ["module", "report", "webapp"]
KIND_LABEL = {"module": "modules", "report": "reports", "webapp": "webapps"}


class TargetResult(unittest.TestResult):
    """A TestResult that remembers the outcome of every individual test."""

    def __init__(self):
        super().__init__()
        self.buffer = True
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append((test, "pass", None))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.append((test, "fail", self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.append((test, "error", self._exc_info_to_string(err, test)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append((test, "skip", reason))

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.outcomes.append((test, "pass", None))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.outcomes.append((test, "fail", "unexpectedly passed"))

    def counts(self):
        tally = {"pass": 0, "fail": 0, "error": 0, "skip": 0}
        for _, status, _ in self.outcomes:
            tally[status] += 1
        return tally


def _case_name(test):
    return test._testMethodName if hasattr(test, "_testMethodName") else str(test)


# ---------------------------------------------------------------------------
# building suites
# ---------------------------------------------------------------------------


def _load_failure_case(target, message):
    """A one-test case that reports why a tool could not be imported at all."""

    class LoadFailure(unittest.TestCase):
        def test_tool_imports(self):
            self.fail(message)

    LoadFailure.__qualname__ = LoadFailure.__name__ = "%s (import)" % target.name
    return LoadFailure


def _bind(cls, target, module, strict, flag_source):
    """
    Return a subclass of ``cls`` wired to one target: the target metadata, the
    imported tool, the strict flag, and any smoke-check opt-outs the tool's own
    Tests class declares.
    """
    attrs = {
        "armory_target": target,
        "armory_module": module,
        "strict": strict,
    }
    for flag, default in smoke.SMOKE_FLAGS.items():
        attrs[flag] = getattr(flag_source, flag, default) if flag_source else default

    bound = type(cls.__name__, (cls,), attrs)
    bound.__module__ = cls.__module__
    bound.__qualname__ = "%s.%s" % (discovery.describe(target), cls.__name__)
    return bound


def build_target_suite(target, strict=False, include_smoke=True, pattern=None):
    """Build the suite for one tool. Returns (suite, tests_class_or_None)."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    try:
        module = discovery.load(target)
        tests_cls = discovery.tests_class(target)
    except Exception:
        message = "importing %s failed:\n%s" % (
            target.source_file, traceback.format_exc(),
        )
        suite.addTests(loader.loadTestsFromTestCase(_load_failure_case(target, message)))
        return suite, None

    if include_smoke:
        smoke_cls = _bind(
            smoke.SMOKE_CLASSES[target.kind], target, module, strict, tests_cls
        )
        suite.addTests(loader.loadTestsFromTestCase(smoke_cls))

    if tests_cls is not None:
        bound = _bind(tests_cls, target, module, strict, tests_cls)
        suite.addTests(loader.loadTestsFromTestCase(bound))

    if pattern:
        keep = [t for t in _flatten(suite) if pattern in _case_name(t)]
        suite = unittest.TestSuite(keep)

    return suite, tests_cls


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def _summary_line(target, result, has_tests, verbose, out):
    tally = result.counts()
    bits = []
    if tally["pass"]:
        bits.append("%d passed" % tally["pass"])
    if tally["fail"]:
        bits.append("%d failed" % tally["fail"])
    if tally["error"]:
        bits.append("%d errored" % tally["error"])
    if tally["skip"]:
        bits.append("%d skipped" % tally["skip"])
    if not bits:
        bits.append("no tests")

    broken = tally["fail"] or tally["error"]
    color = bcolors.FAIL if broken else (bcolors.GREEN if tally["pass"] else bcolors.WARNING)
    code = "[!] " if broken else ("[+] " if tally["pass"] else "[-] ")

    marker = "*" if has_tests else " "
    name = "%s %-28s" % (marker, target.name)
    display("%s %s" % (name, ", ".join(bits)), color, code)

    if verbose:
        for test, status, detail in result.outcomes:
            if status == "pass":
                display("      %s" % _case_name(test), bcolors.GREEN, "")
            elif status == "skip":
                display("      %s  (skipped: %s)" % (_case_name(test), detail),
                        bcolors.WARNING, "")

    for test, status, detail in result.outcomes:
        if status in ("fail", "error"):
            display("      %s" % _case_name(test), bcolors.FAIL, "")
            for line in (detail or "").rstrip().splitlines():
                print("        %s" % line, file=out)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def run_tests(names=None, kinds=None, strict=False, include_smoke=True,
              verbose=False, failfast=False, pattern=None, verbosity=0):
    """
    Run the Armory test suite. Returns a process exit code (0 = everything
    passed).
    """
    from django.test.utils import setup_test_environment, teardown_test_environment
    from django.test.runner import DiscoverRunner

    targets, unknown = discovery.discover(kinds=kinds, names=names)

    for name in unknown:
        display("No module, report, or webapp named %r" % name,
                bcolors.FAIL, "[!] ")
    if not targets:
        if not unknown:
            display("Nothing to test.", bcolors.WARNING, "[-] ")
        return 1 if unknown else 0

    counts = {}
    for target in targets:
        counts[target.kind] = counts.get(target.kind, 0) + 1
    display(
        "Armory tests: %s" % ", ".join(
            "%d %s" % (counts[k], KIND_LABEL[k]) for k in KIND_ORDER if k in counts
        ),
        bcolors.PURPLE, "[*] ",
    )
    if strict:
        display("strict mode: convention checks enabled", bcolors.PURPLE, "[*] ")

    real_stdout = sys.stdout
    started = time.time()

    setup_test_environment()
    django_runner = DiscoverRunner(verbosity=verbosity, interactive=False)
    old_config = django_runner.setup_databases()

    totals = {"pass": 0, "fail": 0, "error": 0, "skip": 0}
    broken_targets = []

    try:
        for kind in KIND_ORDER:
            in_kind = [t for t in targets if t.kind == kind]
            if not in_kind:
                continue
            print(file=real_stdout)
            display(KIND_LABEL[kind], bcolors.BOLD + bcolors.BLUE, "")

            for target in in_kind:
                suite, tests_cls = build_target_suite(
                    target, strict=strict, include_smoke=include_smoke,
                    pattern=pattern,
                )
                # Tools chatter on every database write; keep it out of the
                # report unless a test actually fails. TestResult records the
                # stream it will mirror buffered output to at construction
                # time, so it has to be built inside the redirect.
                with contextlib.redirect_stdout(io.StringIO()):
                    with _quiet_django_logging():
                        result = TargetResult()
                        result.failfast = failfast
                        suite.run(result)

                with contextlib.redirect_stdout(real_stdout):
                    _summary_line(target, result, tests_cls is not None,
                                  verbose, real_stdout)

                tally = result.counts()
                for key in totals:
                    totals[key] += tally[key]
                if tally["fail"] or tally["error"]:
                    broken_targets.append(discovery.describe(target))
                if failfast and (tally["fail"] or tally["error"]):
                    raise _FailFast()
    except _FailFast:
        pass
    finally:
        django_runner.teardown_databases(old_config)
        teardown_test_environment()
        sys.stdout = real_stdout

    elapsed = time.time() - started
    print()
    line = "%d passed, %d failed, %d errored, %d skipped in %.1fs" % (
        totals["pass"], totals["fail"], totals["error"], totals["skip"], elapsed,
    )
    if totals["fail"] or totals["error"]:
        display(line, bcolors.FAIL, "[!] ")
        display("problems in: %s" % ", ".join(broken_targets), bcolors.FAIL, "[!] ")
        return 1
    display(line, bcolors.GREEN, "[+] ")
    return 0


class _FailFast(Exception):
    pass


@contextlib.contextmanager
def _quiet_django_logging():
    """
    Django logs every 4xx a view returns. A 404 is a perfectly good answer for
    a smoke check, so the noise is suppressed for the duration of the run.
    """
    names = ("django.request", "django.server", "django.security")
    saved = {}
    for name in names:
        logger = logging.getLogger(name)
        saved[name] = logger.level
        logger.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)


def list_tests(kinds=None, names=None):
    """Print every testable tool and whether it ships its own Tests class."""
    targets, unknown = discovery.discover(kinds=kinds, names=names)
    for name in unknown:
        display("No module, report, or webapp named %r" % name, bcolors.FAIL, "[!] ")

    loader = unittest.TestLoader()
    for kind in KIND_ORDER:
        in_kind = [t for t in targets if t.kind == kind]
        if not in_kind:
            continue
        print()
        display(KIND_LABEL[kind], bcolors.BOLD + bcolors.BLUE, "")
        for target in in_kind:
            try:
                tests_cls = discovery.tests_class(target)
            except Exception as exc:  # noqa: BLE001
                display("  %-28s %-8s import failed: %s"
                        % (target.name, target.source, exc), bcolors.FAIL, "")
                continue
            if tests_cls is None:
                detail, color = "smoke only", None
            else:
                detail = "%d own test%s" % (
                    len(loader.getTestCaseNames(tests_cls)),
                    "" if len(loader.getTestCaseNames(tests_cls)) == 1 else "s",
                )
                color = bcolors.GREEN
            display("  %-28s %-8s %s" % (target.name, target.source, detail), color, "")
    print()
    return 0


def main(argv=None):
    """``armory-test`` entry point."""
    # Importing armory_cmd bootstraps Django and the ~/.armory config exactly
    # the way the `armory` CLI does.
    import armory2.armory_cmd  # noqa: F401

    parser = argparse.ArgumentParser(
        prog="armory-test",
        description="Run the tests that live inside Armory modules, reports, "
                    "and webapps.",
    )
    add_arguments(parser)
    args = parser.parse_args(argv)
    return dispatch(args)


def add_arguments(parser):
    """Shared by ``armory-test`` and the ``armory -t`` flags."""
    parser.add_argument(
        "names", nargs="*",
        help="Module/report/webapp names to test. Default: everything.",
    )
    parser.add_argument(
        "-l", "--list", action="store_true",
        help="List testable tools and whether they ship their own tests",
    )
    parser.add_argument(
        "-k", "--kind", action="append", choices=list(discovery.KINDS),
        help="Restrict to a kind of tool; repeatable",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Also run convention checks (name matches filename, docstrings, "
             "Tailwind base template)",
    )
    parser.add_argument(
        "--no-smoke", dest="smoke", action="store_false",
        help="Run only tools' own Tests classes, skipping the built-in checks",
    )
    parser.add_argument(
        "--only", metavar="SUBSTRING",
        help="Run only tests whose method name contains SUBSTRING",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="List every test, not just the failures",
    )
    parser.add_argument(
        "--failfast", action="store_true", help="Stop at the first failure",
    )


def dispatch(args):
    if getattr(args, "list", False):
        return list_tests(kinds=args.kind, names=args.names)
    return run_tests(
        names=args.names,
        kinds=args.kind,
        strict=args.strict,
        include_smoke=args.smoke,
        verbose=args.verbose,
        failfast=args.failfast,
        pattern=args.only,
    )


if __name__ == "__main__":
    sys.exit(main())
