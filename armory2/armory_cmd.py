#!/usr/bin/env python

# main.py
# Django specific settings

import os
from pkg_resources import resource_string

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
            resource_string(
                "armory2.default_configs", "settings.py"
            ).decode("UTF-8")
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


__version__ = "Armory Version 2.0 Beta"
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
    
    modules = {}
    if custom_path:
        for c in custom_path:
            for m in get_modules(c):
                modules[m] = c
    
    for m in get_modules(os.path.join(PATH, "armory_main/included/modules")):
        modules[m] = os.path.join(PATH, "armory_main/included/modules")
    if not silent:
        print("Available modules:")
        for m in sorted(list(set(modules.keys()))):
            print("\t%s" % m)

    else:
        return modules

def list_reports(silent=False):
    config = get_config_options()
    custom_path = config.get("ARMORY_CUSTOM_REPORTS", None)

    modules = []

    if custom_path:
        for r in custom_path:
            modules += [m for m in get_modules(r)]
    modules += [m for m in get_modules(os.path.join(PATH, "armory_main/included/reports"))]
    if not silent:
        print("Available reports:")
        for r in sorted(list(set(modules))):
            print("\t%s" % r)   
    else:
        return sorted(list(set(modules)))

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
    argcomplete.autocomplete(m.options)
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
    argcomplete.autocomplete(m.options)
    m.options.parse_args(["-h"])


def run_module(Module, argv, module):
    # Get the basic settings and database set up

    config = get_config_options()
    

    m = Module.Module()

    # Populate the options
    m.set_options()

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

    argcomplete.autocomplete(m.options)
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

    argcomplete.autocomplete(m.options)
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


def main():
    check_database()

    if NEW_CONFIG_FOLDER:
        generate_default_configs()
    cmd_args = sys.argv
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--module", help="Use module")
    parser.add_argument(
        "-lm", "--list_modules", help="List modules", action="store_true"
    )
    parser.add_argument(
        "-M", "--list_module_options", help="List module options", action="store_true"
    )
    parser.add_argument("-r", "--report", help="Use report")
    parser.add_argument(
        "-lr", "--list_reports", help="List reports", action="store_true"
    )
    parser.add_argument(
        "-R", "--list_report_options", help="List report options", action="store_true"
    )
    parser.add_argument(
        "--generate_defaults", help="Generate default config files", action="store_true"
    )
    parser.add_argument(
        "--quiet", help="Don't display banner", action="store_true"
    )
    parser.add_argument(
        "-v", "--version", help="Display the current version", action="store_true"
    )

    base_args, unknown = parser.parse_known_args(cmd_args)
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
            run_module(Module, cmd_args, custom_modules[-1][0])
        elif modules:
            Module = load_module(".armory_main.included.modules.%s" % modules[0])
            run_module(Module, cmd_args, modules[0])

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
            run_report(Report, cmd_args, custom_reports[-1][0])
        elif reports:
            Report = load_module(".armory_main.included.reports.%s" % reports[0])
            run_report(Report, cmd_args, reports[0])
        else:
            print("Report %s is not a valid report." % base_args.report)
            list_reports()

if __name__ == "__main__":
    main()
