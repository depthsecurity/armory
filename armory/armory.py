#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK

from configparser import ConfigParser
from pkg_resources import resource_string
from . import database
import argparse
import argcomplete
import os
import pkgutil
import sys

# import pdb # Useful for debugging


__version__ = "Armory Version 1.0 Release"
PATH = os.path.dirname(__file__)
if os.getenv("ARMORY_HOME"):
    CONFIG_FOLDER = os.getenv("ARMORY_HOME")
else:
    CONFIG_FOLDER = os.path.join(os.getenv("HOME"), ".armory")

if os.getenv("ARMORY_CONFIG"):
    CONFIG_FILE = os.getenv("ARMORY_CONFIG")
else:
    CONFIG_FILE = "settings.ini"


DEFAULTS_DIR = os.path.join(os.path.dirname(__file__), "default_configs")


def check_and_create_configs():
    """
    This is run if there is no config currently setup. It will create a home .armory folder,
    create a sample base config, and populate sample module configs.
    """

    if not os.path.exists(CONFIG_FOLDER):
        os.mkdir(CONFIG_FOLDER)
    if not os.path.exists(os.path.join(CONFIG_FOLDER, CONFIG_FILE)):
        with open(os.path.join(CONFIG_FOLDER, CONFIG_FILE), "w") as out:
            out.write(
                resource_string(
                    "armory.default_configs", "settings.ini.default"
                ).decode("UTF-8")
            )

        generate_default_configs()


def generate_default_configs():
    config = get_config_options()
    # Delete any .sample files already there

    config_options = {}
    custom_path = config["PROJECT"].get("custom_modules", None)

    if custom_path:
        for f in os.listdir(custom_path):
            if os.path.isfile(f) and f[-7:] == ".sample":
                os.remove(f)

    modules = get_modules(os.path.join(PATH, "included/modules"))
    for m in modules:
        config_options[m] = get_module_options(".included.modules." + m, m)

    if custom_path:
        modules = get_modules(custom_path)
        for m in modules:
            config_options[m] = get_module_options(os.path.join(custom_path, m), m)

    for m, options in config_options.items():
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

        return importlib.import_module("%s" % module_path, package="armory")
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


def list_modules():
    config = get_config_options()
    custom_path = config["PROJECT"].get("custom_modules", None)

    modules = []
    if custom_path:
        modules += [m for m in get_modules(custom_path)]
    modules += [m for m in get_modules(os.path.join(PATH, "included/modules"))]

    print("Available modules:")
    for m in sorted(list(set(modules))):
        print("\t%s" % m)


def list_reports():
    config = get_config_options()
    custom_path = config["PROJECT"].get("custom_reports", None)

    modules = []

    if custom_path:
        modules += [m for m in get_modules(custom_path)]
    modules += [m for m in get_modules(os.path.join(PATH, "included/reports"))]

    print("Available reports:")
    for r in sorted(list(set(modules))):
        print("\t%s" % r)


def list_module_options(module, module_name):

    config = get_config_options()
    db = initialize_database(config)
    # Load the module
    Module = load_module(module)
    if Module.Module.__doc__:
        print("%s" % module_name)

        print(Module.Module.__doc__)
    m = Module.Module(db)

    # Populate the options
    m.set_options()
    argcomplete.autocomplete(m.options)
    m.options.parse_args(["-h"])


def get_module_options(module, module_name):
    config = get_config_options()
    db = initialize_database(config)
    # Load the module
    Module = load_module(module)

    m = Module.Module(db)

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
    db = initialize_database(config)
    # Load the module
    Module = load_module(module)
    if Module.Report.__doc__:
        print("%s" % module_name)

        print(Module.Report.__doc__)

    m = Module.Report(db)

    # Populate the options
    m.set_options()
    argcomplete.autocomplete(m.options)
    m.options.parse_args(["-h"])


def run_module(Module, argv, module):
    # Get the basic settings and database set up

    config = get_config_options()
    db = initialize_database(config)

    m = Module.Module(db)

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
    db = initialize_database(config)

    m = Report.Report(db)

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


def get_config_options(config_file=CONFIG_FILE):
    config = ConfigParser()
    def_config = os.path.join(CONFIG_FOLDER, config_file)
    if config_file == CONFIG_FILE and not os.path.exists(def_config):
        print(
            "An error occurred while trying to create {}. Aborting!!".format(def_config)
        )
        raise ValueError("{} doesn't exist!".format(def_config))
    config.read(os.path.join(CONFIG_FOLDER, config_file))

    if config_file == CONFIG_FILE:
        if not os.path.exists(config["PROJECT"]["base_path"]):
            os.makedirs(config["PROJECT"]["base_path"])
    return config


def get_connection_string(config):
    connect = ""
    if config["DATABASE"]["backend"] == "sqlite3":
        base = config["PROJECT"]["base_path"]
        dbname = config["DATABASE"]["filename"]
        connect = "sqlite:///%s" % os.path.join(base, dbname)

    elif config["DATABASE"]["backend"] in ["mysql", "mariadb"]:
        username = config["DATABASE"]["username"]
        password = config["DATABASE"]["password"]
        server = config["DATABASE"].get("host", "127.0.0.1")
        port = config["DATABASE"].get("port", "3306")
        database = config["DATABASE"]["database"]
        connect = "mysql://{}:{}@{}:{}/{}".format(
            username, password, server, port, database
        )
    return connect


def initialize_database(config):
    return database.create_database(get_connection_string(config))


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

        Originally By:
        Daniel Lawson @fang0654
        Cory Shay @ccsplit
        Brian Berg @xexzy
"""
    print(banner)


def main():

    check_and_create_configs()
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
        "-v", "--version", help="Display the current version", action="store_true"
    )

    base_args, unknown = parser.parse_known_args(cmd_args)
    if base_args.generate_defaults:
        generate_default_configs()
    if base_args.version:
        print(__version__)
    elif base_args.list_module_options:
        print_banner()
        if base_args.module:
            config = get_config_options()
            custom_path = config["PROJECT"].get("custom_modules", None)

            if custom_path:
                modules = get_modules(custom_path)

                if base_args.module in modules:
                    list_module_options(
                        os.path.join(custom_path, base_args.module), base_args.module
                    )
                    sys.exit(0)
            modules = get_modules(os.path.join(PATH, "included/modules"))
            if base_args.module in modules:
                list_module_options(
                    ".included.modules." + base_args.module, base_args.module
                )
                sys.exit(0)

        print("You must supply a valid module to get options for.")
        list_modules()

    elif base_args.list_modules:
        print_banner()
        list_modules()

    elif base_args.module:
        print_banner()
        config = get_config_options()
        custom_path = config["PROJECT"].get("custom_modules", None)
        custom_modules = []
        if custom_path:
            custom_modules = get_modules(custom_path)

        modules = get_modules(os.path.join(PATH, "included/modules"))

        if base_args.module in custom_modules:
            Module = load_module(os.path.join(custom_path, base_args.module))
            run_module(Module, cmd_args, base_args.module)
        elif base_args.module in modules:
            Module = load_module(".included.modules.%s" % base_args.module)
            run_module(Module, cmd_args, base_args.module)

        else:
            print("Module %s is not a valid module." % base_args.module)
            list_modules()

    elif base_args.list_report_options:
        print_banner()
        if base_args.report:
            config = get_config_options()
            custom_path = config["PROJECT"].get("custom_reports", None)

            if custom_path:
                modules = get_modules(custom_path)

                if base_args.report in modules:
                    list_report_options(
                        os.path.join(custom_path, base_args.report), base_args.report
                    )
                    sys.exit(0)
            modules = get_modules(os.path.join(PATH, "included/reports"))
            if base_args.report in modules:
                list_report_options(
                    ".included.reports." + base_args.report, base_args.report
                )
                sys.exit(0)

        print("You must supply a valid report to get options for.")
        list_reports()

    elif base_args.list_reports:
        print_banner()
        list_reports()

    elif base_args.report:
        print_banner()
        config = get_config_options()
        custom_path = config["PROJECT"].get("custom_reports", None)
        custom_reports = []
        if custom_path:
            custom_reports = get_modules(custom_path)

        reports = get_modules(os.path.join(PATH, "included/reports"))

        if base_args.report in custom_reports:
            Report = load_module(os.path.join(custom_path, base_args.report))
            run_report(Report, cmd_args, base_args.report)
        elif base_args.report in reports:
            Report = load_module(".included.reports.%s" % base_args.report)
            run_report(Report, cmd_args, base_args.report)
        else:
            print("Report %s is not a valid report." % base_args.report)
            list_reports()
