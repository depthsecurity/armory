#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK

# main.py
# Django specific settings

import os
from importlib.resources import read_text, files

# Ensuring the Armory config exists before loading the Django stuff.

if os.getenv("ARMORY_HOME"):
    CONFIG_FOLDER = os.getenv("ARMORY_HOME")
else:
    CONFIG_FOLDER = os.path.join(os.getenv("HOME"), ".armory")

if os.getenv("ARMORY_CONFIG"):
    CONFIG_FILE = os.getenv("ARMORY_CONFIG")
else:
    CONFIG_FILE = "settings.py"

if not os.path.exists(CONFIG_FOLDER):
    os.mkdir(CONFIG_FOLDER)
if not os.path.exists(os.path.join(CONFIG_FOLDER, CONFIG_FILE)):
    with open(os.path.join(CONFIG_FOLDER, CONFIG_FILE), "w") as out:
        out.write(
            files("armory2.default_configs").joinpath("settings.py").read_text()
        )    
    NEW_CONFIG_FOLDER = True
else:
    NEW_CONFIG_FOLDER = False

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "armory2.armory2.settings")

### Have to do this for it to work in 1.9.x!
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
from django.core.management import call_command

#############

# Your application specific imports
from armory2 import __version__
from armory2.armory_main.models import *
from django.conf import settings
from django.db.utils import OperationalError
import argparse
import argcomplete
import os
import pkgutil
import sys
import pdb
from configparser import ConfigParser



PATH = os.path.dirname(__file__)


DEFAULTS_DIR = os.path.join(os.path.dirname(__file__), "default_configs")

# call_command('migrate')

def check_database():
    '''
    Check and make sure the database is migrated
    '''

    try:
        Url.objects.filter(pk=1)
    except OperationalError:
        from django.core.management import execute_from_command_line
        execute_from_command_line(['manage', 'migrate'])

def generate_default_configs():
    config = get_config_options()
    # Delete any .sample files already there

    config_options = {}
    custom_path = config.get("ARMORY_CUSTOM_MODULES", None)

    if custom_path:
        for c in custom_path:

            for f in os.listdir(c):
                if os.path.isfile(f) and f[-7:] == ".sample":
                    os.remove(f)

    modules = get_modules(os.path.join(PATH, "armory_main/included/modules"))
    for m in modules:
        try:    
            config_options[m] = get_module_options(".armory_main.included.modules." + m, m)
        except Exception as e:
            print(f"Invalid module: {m} failed with error {e}. Skipping")
    if custom_path:
        for c in custom_path:

            modules = get_modules(c)
            for m in modules:
                # pdb.set_trace()
                
                try:
                    config_options[m] = get_module_options(os.path.join(c, m), m)
                except Exception as e:
                    print(f"Invalid module: {m} failed with error {e}. Skipping")

    for m, options in config_options.items():
        print(f"Creating sample config for {m}.")
        if not os.path.exists(os.path.join(CONFIG_FOLDER, "{}.ini.sample".format(m))):
            c = open(os.path.join(CONFIG_FOLDER, "{}.ini.sample".format(m)), "w")
            c.write("[ModuleSettings]\n\n")
            for o in sorted(options.keys()):
                c.write("# {}\n".format(options[o]["help"]))
                if options[o]["default"]:
                    c.write("{} = {}\n\n".format(o, options[o]["default"]))
                else:
                    c.write("# {} =\n\n".format(o))
            c.close()


def get_modules(module_path):

    modules = [name for _, name, _ in pkgutil.iter_modules([module_path])]
    if "templates" in modules:
        modules.pop(modules.index("templates"))

    return sorted(modules)


# Tool names hidden from `-lm`/`-lr` listings and tab-completion by default:
# base templates and bundled sample/example modules. These stay runnable if
# invoked explicitly (e.g. `armory -m SampleModule`); they're just not
# advertised. Extend per-install with ARMORY_HIDDEN_MODULES /
# ARMORY_HIDDEN_REPORTS (lists of names) in ~/.armory/settings.py.
HIDDEN_TOOL_NAMES = {"templates", "SampleModule", "SampleToolModule", "SampleReport"}


def _is_hidden_tool(name, extra=()):
    return name in HIDDEN_TOOL_NAMES or name in extra or name.endswith("Template")


def _visible(names, extra=()):
    return sorted(n for n in set(names) if not _is_hidden_tool(n, extra))


def load_module(module_path):
    if "/" not in module_path:
        import importlib
        # return importlib.import_module("%s" % module_path, package=None)
        return importlib.import_module("%s" % module_path, package="armory2")
    else:
        module_name = module_path.split("/")[-1]
        if sys.version_info.major == 2:
            import imp

            return imp.load_source(module_name, module_path + ".py")
        else:
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                module_name, module_path + ".py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module


def list_modules(silent=False):
    config = get_config_options()
    custom_path = config.get("ARMORY_CUSTOM_MODULES", None)
    hidden = set(config.get("ARMORY_HIDDEN_MODULES", []) or [])

    modules = {}

    for m in get_modules(os.path.join(PATH, "armory_main/included/modules")):
        modules[m] = os.path.join(PATH, "armory_main/included/modules")

    if custom_path:
        for c in custom_path:
            for m in get_modules(c):
                modules[m] = c

    modules = {m: p for m, p in modules.items() if not _is_hidden_tool(m, hidden)}

    if not silent:
        print("Available modules:")
        for m in _visible(modules.keys()):
            print("\t%s" % m)

    else:
        return modules

def list_reports(silent=False):
    config = get_config_options()
    custom_path = config.get("ARMORY_CUSTOM_REPORTS", None)
    hidden = set(config.get("ARMORY_HIDDEN_REPORTS", []) or [])

    modules = {}

    for m in get_modules(os.path.join(PATH, "armory_main/included/reports")):
        modules[m] = os.path.join(PATH, "armory_main/included/reports")

    if custom_path:
        for r in custom_path:
            for m in get_modules(r):
                modules[m] = r

    modules = {m: p for m, p in modules.items() if not _is_hidden_tool(m, hidden)}

    if not silent:
        print("Available reports:")
        for m in _visible(modules.keys()):
            print("\t%s" % m)
    else:
        return modules

def list_module_options(module, module_name):

    config = get_config_options()
    
    # Load the module
    Module = load_module(module)
    if Module.Module.__doc__:
        print("%s" % module_name)

        print(Module.Module.__doc__)
    m = Module.Module()

    # Populate the options
    m.set_options()
    m.options.parse_args(["-h"])


def get_module_options(module, module_name):
    config = get_config_options()
    
    # Load the module
    Module = load_module(module)
    
    # pdb.set_trace()

    m = Module.Module()

    # Populate the options
    m.set_options()

    options = {}

    for a in m.options._actions:
        cmd = ""
        for c in a.option_strings:
            if "--" in c:
                cmd = c.replace("-", "")

        if cmd and cmd != "help":
            options[cmd] = {"help": a.help, "default": a.default}

    return options


def list_report_options(module, module_name):

    config = get_config_options()
    
    # Load the module
    Module = load_module(module)
    if Module.Report.__doc__:
        print("%s" % module_name)

        print(Module.Report.__doc__)

    m = Module.Report()

    # Populate the options
    m.set_options()
    m.options.parse_args(["-h"])

def get_report_options(module, module_name):

    config = get_config_options()
    
    # Load the module
    Module = load_module(module)
    # if Module.Report.__doc__:
    #     print("%s" % module_name)

    #     print(Module.Report.__doc__)

    m = Module.Report()

    # Populate the options
    m.set_options()
    options = {}

    for a in m.options._actions:
        cmd = ""
        for c in a.option_strings:
            if "--" in c:
                cmd = c.replace("-", "")

        if cmd and cmd != "help":
            options[cmd] = {"help": a.help, "default": a.default}

    return options

def run_module(Module, argv, module, use_docker=False):
    # Get the basic settings and database set up

    config = get_config_options()
    

    m = Module.Module()

    # Populate the options
    m.set_options()
    if use_docker:
        m.use_docker = True
        
    # A bunch of fun stuff to check if arguments provided on command line
    # and override config file if found.
    module_config_data = get_config_options(module + ".ini")
    # pdb.set_trace()
    if "ModuleSettings" in module_config_data.sections():
        module_opt_keys = [a.option_strings for a in m.options._actions]

        for k in module_config_data["ModuleSettings"].keys():

            for o in module_opt_keys:

                if k in [a.replace("-", "") for a in o]:
                    exists = False
                    for n in o:
                        if n in argv:
                            exists = True
                    if not exists:
                        # Make sure if using tool_args, that our config goes before it in argv
                        if "--tool_args" in argv:
                            i = argv.index("--tool_args")
                            argv.insert(i, module_config_data["ModuleSettings"][k])
                            argv.insert(i, "--" + k)

                        else:
                            argv.append("--" + k)
                            argv.append(module_config_data["ModuleSettings"][k])

    args, unknown = m.options.parse_known_args(argv)

    m.base_config = config
    m.run(args)


def run_report(Report, argv, report):
    # Get the basic settings and database set up

    config = get_config_options()
    

    m = Report.Report()

    # Populate the options
    m.set_options()

    # A bunch of fun stuff to check if arguments provided on command line
    # and override config file if found.
    # module_config_data = get_config_options(module + '.ini')
    # if 'ModuleSettings' in module_config_data.sections():
    #     module_opt_keys = [a.option_strings for a in m.options._actions]
    #     for k in module_config_data['ModuleSettings'].keys():

    #         for o in module_opt_keys:

    #             if k in [a.replace('-', '') for a in o]:
    #                 exists = False
    #                 for n in o:
    #                     if n in argv:
    #                         exists = True
    #                 if not exists:

    #                     argv.append("--" + k)
    #                     argv.append(module_config_data['ModuleSettings'][k])

    args, unknown = m.options.parse_known_args(argv)
    m.base_config = config

    m.run(args)


def get_config_options(config_file=None):
    if not config_file:

        config = settings.ARMORY_CONFIG

        if not os.path.exists(config["ARMORY_BASE_PATH"]):
            os.makedirs(config["ARMORY_BASE_PATH"])
        return config

    else:
        config = ConfigParser()
        def_config = os.path.join(CONFIG_FOLDER, config_file)
        if config_file == CONFIG_FILE and not os.path.exists(def_config):
            print(
                "An error occurred while trying to create {}. Aborting!!".format(def_config)
            )
            raise ValueError("{} doesn't exist!".format(def_config))
        config.read(os.path.join(CONFIG_FOLDER, config_file))

        
        return config

def print_banner():
    banner = """
       _
      dM.
     ,MMb
     d'YM.   ___  __ ___  __    __     _____  ___  __ ____    ___
    ,P `Mb   `MM 6MM `MM 6MMb  6MMb   6MMMMMb `MM 6MM `MM(    )M'
    d'  YM.   MM69 "  MM69 `MM69 `Mb 6M'   `Mb MM69 "  `Mb    d'
___,P____Mb___MM______MM____MM____MM_MM_____MM_MM_______YM.__,P___
   d'    YM.  MM      MM    MM    MM MM     MM MM        MM  M    \\
__,MMMMMMMMb__MM______MM____MM____MM_MM_____MM_MM________`Mbd'_____\\
  d'      YM. MM      MM    MM    MM YM.   ,M9 MM         YMP
_dM_     _dMM_MM_    _MM_  _MM_  _MM_ YMMMMM9 _MM_         M
                                                          d'
                                                      (8),P
                                                       YMM
"""
    print(banner)


# ---------------------------------------------------------------------------
# Shell tab-completion support (argcomplete)
#
# Enable in your shell (zsh/bash) with:
#     eval "$(register-python-argcomplete armory)"
# See the completion docs / `contrib/armory-completion.sh` for details.
# ---------------------------------------------------------------------------

# The base command arguments, declared as data so the same set can be used to
# build the top-level parser and to be merged into a module/report parser when
# completing that tool's own options.
BASE_ARGUMENTS = [
    (["-m", "--module"], {"help": "Use module"}),
    (["-lm", "--list_modules"], {"help": "List modules", "action": "store_true"}),
    (["-M", "--list_module_options"], {"help": "List module options", "action": "store_true"}),
    (["-r", "--report"], {"help": "Use report"}),
    (["-lr", "--list_reports"], {"help": "List reports", "action": "store_true"}),
    (["-R", "--list_report_options"], {"help": "List report options", "action": "store_true"}),
    (["--generate_defaults"], {"help": "Generate default config files", "action": "store_true"}),
    (["--quiet"], {"help": "Don't display banner", "action": "store_true"}),
    (["-v", "--version"], {"help": "Display the current version", "action": "store_true"}),
    (["--docker"], {"help": "Use Docker versions of modules if available", "action": "store_true"}),
    (["-t", "--test"], {"help": "Run tests for modules/reports/webapps (all if no names given)", "action": "store_true"}),
    (["-lt", "--list_tests"], {"help": "List testable modules/reports/webapps", "action": "store_true"}),
]


# `armory -t` hands the rest of the command line to the test runner, so these
# base flags are dropped rather than passed along.
TEST_FLAGS = {"-t", "--test", "-lt", "--list_tests"}
BASE_FLAGS_IGNORED_BY_TESTS = {"--quiet", "--docker"}


def is_test_invocation(argv):
    """
    True when the command line is asking for a test run.

    `-t` only means "run tests" when no module or report was named, so a module
    that happens to define its own -t keeps working.
    """
    if {"-m", "--module", "-r", "--report"} & set(argv):
        return False
    return bool(TEST_FLAGS & set(argv))


def run_test_cli(argv):
    """Parse the test-specific command line and run it."""
    from armory2.armory_main.included.testing import runner

    parser = argparse.ArgumentParser(
        prog="armory -t",
        description="Run the tests that live inside Armory modules, reports, "
                    "and webapps.",
    )
    runner.add_arguments(parser)

    cleaned = []
    for arg in argv:
        if arg in ("-lt", "--list_tests"):
            cleaned.append("--list")
        elif arg in TEST_FLAGS or arg in BASE_FLAGS_IGNORED_BY_TESTS:
            continue
        else:
            cleaned.append(arg)

    return runner.dispatch(parser.parse_args(cleaned))


def _module_completer(prefix, **kwargs):
    """Complete module names for `armory -m <TAB>`."""
    try:
        return sorted(list_modules(silent=True).keys())
    except Exception:
        return []


def _report_completer(prefix, **kwargs):
    """Complete report names for `armory -r <TAB>`."""
    try:
        return sorted(list_reports(silent=True).keys())
    except Exception:
        return []


def build_base_parser():
    """Build the top-level argument parser, wiring up completers for -m/-r."""
    parser = argparse.ArgumentParser()
    for flags, kw in BASE_ARGUMENTS:
        action = parser.add_argument(*flags, **kw)
        if "--module" in flags:
            action.completer = _module_completer
        elif "--report" in flags:
            action.completer = _report_completer
    return parser


def _selected_target(comp_line):
    """
    Inspect the completion command line and, if a module (-m) or report (-r)
    has already been fully typed, return (name, kind) where kind is
    'module' or 'report'. Returns (None, None) while the name itself is still
    being typed so name completion keeps working.
    """
    import shlex

    try:
        tokens = shlex.split(comp_line)
    except ValueError:
        tokens = comp_line.split()

    trailing_space = comp_line[-1:].isspace()

    for kind, flags in (("module", ("-m", "--module")), ("report", ("-r", "--report"))):
        for i, tok in enumerate(tokens):
            if tok in flags and i + 1 < len(tokens):
                name = tokens[i + 1]
                # The name counts as "chosen" only once it is complete: either
                # something follows it, or the cursor has moved past it (space).
                if i + 2 < len(tokens) or trailing_space:
                    return name, kind
    return None, None


def _build_completion_parser(name, kind):
    """
    Load the selected module/report, populate its options, and merge the base
    arguments in so both the tool's own flags and the base flags complete.
    Returns the parser, or None if the tool can't be resolved.
    """
    catalog = list_modules(silent=True) if kind == "module" else list_reports(silent=True)
    match = next((n for n in catalog if n.lower() == name.lower()), None)
    if not match:
        return None

    path = catalog[match]
    core_path = os.path.join(PATH, "armory_main/included/modules" if kind == "module"
                             else "armory_main/included/reports")
    if path == core_path:
        pkg = ".armory_main.included.%s.%s" % (
            "modules" if kind == "module" else "reports", match)
        loaded = load_module(pkg)
    else:
        loaded = load_module(os.path.join(path, match))

    tool = loaded.Module() if kind == "module" else loaded.Report()
    tool.set_options()
    parser = tool.options

    existing = set(parser._option_string_actions)
    for flags, kw in BASE_ARGUMENTS:
        if any(f in existing for f in flags):
            continue
        action = parser.add_argument(*flags, **kw)
        if "--module" in flags:
            action.completer = _module_completer
        elif "--report" in flags:
            action.completer = _report_completer
    return parser


def run_completion(base_parser):
    """
    Entry hook for argcomplete. A no-op unless the shell is requesting
    completions (argcomplete signals this via the _ARGCOMPLETE env var), so it
    never slows down normal runs or touches the database.
    """
    if not os.environ.get("_ARGCOMPLETE"):
        return

    parser = base_parser
    name, kind = _selected_target(os.environ.get("COMP_LINE", ""))
    if name:
        try:
            merged = _build_completion_parser(name, kind)
            if merged is not None:
                parser = merged
        except Exception:
            # Never let a broken/optional tool break completion of the rest.
            parser = base_parser

    argcomplete.autocomplete(parser)


def main():
    parser = build_base_parser()

    # Handle shell completion first: this exits early when the shell is asking
    # for completions, so it stays fast and never touches the database.
    run_completion(parser)

    check_database()

    if NEW_CONFIG_FOLDER:
        generate_default_configs()

    # Tests replace the rest of the command line, so they are peeled off before
    # the module/report argument splitting below.
    if is_test_invocation(sys.argv[1:]):
        if "--quiet" not in sys.argv:
            print_banner()
        sys.exit(run_test_cli(sys.argv[1:]))

    cmd_args = sys.argv

    if '-m' in cmd_args and '-M' not in cmd_args:
        mod_args = cmd_args[cmd_args.index('-m')+2:]
        cmd_args = cmd_args[:cmd_args.index('-m')+2]

    elif '-r' in cmd_args and '-R' not in cmd_args:
        mod_args = cmd_args[cmd_args.index('-r')+2:]
        cmd_args = cmd_args[:cmd_args.index('-r')+2]

    base_args, _ = parser.parse_known_args(cmd_args)
    if base_args.generate_defaults:
        generate_default_configs()
    if base_args.version:
        print(__version__)
    elif base_args.list_module_options:
        if not base_args.quiet : print_banner()
        if base_args.module:
            config = get_config_options()
            custom_path = config.get("ARMORY_CUSTOM_MODULES", None)

            if custom_path:
                mod = []
                for c in custom_path:
                    modules = get_modules(c)
                    mod += [(m, c) for m in modules if m.lower() == base_args.module.lower()]

                if len(mod) > 0:
                    list_module_options(
                        os.path.join(mod[-1][1], mod[-1][0]), mod[-1][0]
                    )
                    sys.exit(0)
            modules = get_modules(os.path.join(PATH, "armory_main/included/modules"))
            mod = [m for m in modules if m.lower() == base_args.module.lower()]            
            if len(mod) > 0:
                
                list_module_options(
                    ".armory_main.included.modules." + mod[0], mod[0]
                )
                sys.exit(0)

        print("You must supply a valid module to get options for.")
        list_modules()

    elif base_args.list_modules:
        if not base_args.quiet : print_banner()
        list_modules()

    elif base_args.module:
        if not base_args.quiet : print_banner()
        config = get_config_options()
        

        custom_path = config.get("ARMORY_CUSTOM_MODULES", None)
        custom_modules = []
        if custom_path:
            for c in custom_path:
                # pdb.set_trace()
                custom_modules += [(m, c) for m in get_modules(c) if m.lower() == base_args.module.lower()]

        modules = [m for m in get_modules(os.path.join(PATH, "armory_main/included/modules")) if m.lower() == base_args.module.lower()]
        
        if custom_modules:
                
            Module = load_module(os.path.join(custom_modules[-1][1], custom_modules[-1][0]))
            
            
            run_module(Module, mod_args, custom_modules[-1][0], use_docker=base_args.docker)
        elif modules:
            Module = load_module(".armory_main.included.modules.%s" % modules[0])
            Module.use_docker = True
            run_module(Module, mod_args, modules[0], use_docker=base_args.docker)

        else:
            print("Module %s is not a valid module." % base_args.module)
            list_modules()

    elif base_args.list_report_options:
        if not base_args.quiet : print_banner()
        if base_args.report:
            config = get_config_options()
            custom_path = config.get("ARMORY_CUSTOM_REPORTS", None)
            custom_modules = []

            if custom_path:
                for c in custom_path:

                    custom_modules += [(r, c) for r in get_modules(c) if r.lower() == base_args.report.lower()]

                if custom_modules:
                    list_report_options(
                        os.path.join(custom_modules[-1][1], custom_modules[-1][0]), custom_modules[-1][0]
                    )
                    sys.exit(0)
            modules = [r for r in get_modules(os.path.join(PATH, "armory_main/included/reports")) if r.lower() == base_args.report.lower()]
            if modules:
                list_report_options(
                    ".armory_main.included.reports." + modules[0], modules[0]
                )
                sys.exit(0)

        print("You must supply a valid report to get options for.")
        list_reports()

    elif base_args.list_reports:
        if not base_args.quiet : print_banner()
        list_reports()

    elif base_args.report:
        if not base_args.quiet : print_banner()
        config = get_config_options()
        custom_path = config.get("ARMORY_CUSTOM_REPORTS", None)
        custom_reports = []
        if custom_path:
            for c in custom_path:
                custom_reports += [(r, c) for r in get_modules(c) if r.lower() == base_args.report.lower()]

        reports = [r for r in get_modules(os.path.join(PATH, "armory_main/included/reports")) if r.lower() == base_args.report.lower()]

        if custom_reports:
            Report = load_module(os.path.join(custom_reports[-1][1], custom_reports[-1][0]))
            run_report(Report, mod_args, custom_reports[-1][0])
        elif reports:
            Report = load_module(".armory_main.included.reports.%s" % reports[0])
            run_report(Report, mod_args, reports[0])
        else:
            print("Report %s is not a valid report." % base_args.report)
            list_reports()

if __name__ == "__main__":
    main()
