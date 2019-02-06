#!/usr/bin/env python

from armory import (
    print_banner,
    get_config_options,
    get_modules,
    load_module,
    initialize_database,
)
import glob
import os
import pdb
import readline
import six
import sys


class GlobalCommands(object):
    def __init__(self, name="Armory"):
        self.cmd = {}
        self.name = name
        self.cmd["help"] = {"func": self.show_help, "help": "Displays help text"}

        self.cmd["exit"] = {"func": self.exit_app, "help": "Exits Armory"}

        self.cmd["back"] = {"func": self.go_back, "help": "Move back one level"}

    def run_cmd(self, command, options=None):

        func = self.cmd[command]["func"]

        res = func(options)
        return res

    def show_help(self, options=None):

        commands = self.cmd.keys()
        print("Commands for %s" % self.name)
        print("-------------------------------------------------------------")
        for c in sorted(commands):
            print("{:>20} {:>40}".format(c, self.cmd[c]["help"]))
        print("\n\n")

    def exit_app(self, options=None):

        print("Exiting.")
        sys.exit(0)

    def go_back(self, options=None):
        return True

    def view_options(self, options=None):
        pass

    def set(self, options=None):
        pass

    def unset(self, options=None):
        pass


class MainCommands(GlobalCommands):
    def __init__(self, name="Armory"):
        super(MainCommands, self).__init__(name)

        self.cmd["list_modules"] = {
            "func": self.list_modules,
            "help": "List available modules",
        }

        self.cmd["list_reports"] = {
            "func": self.list_reports,
            "help": "List available reports",
        }

        self.cmd["use_module"] = {"func": self.use_module, "help": "Use a module"}

        self.cmd["use_report"] = {"func": self.use_report, "help": "Use a report"}

        config = get_config_options()
        custom_path = config["PROJECT"].get("custom_modules", None)

        self.modules = []
        if custom_path:
            self.modules += [m for m in get_modules(custom_path)]
        self.modules += [m for m in get_modules("included/modules")]

        self.modules = list(set(self.modules))

        custom_path = config["PROJECT"].get("custom_reports", None)

        self.reports = []

        if custom_path:
            self.reports += [m for m in get_modules(custom_path)]
        self.reports += [m for m in get_modules("included/reports")]

        self.reports = list(set(self.reports))

    def go_back(self, options=None):
        self.exit_app()

    def view_options(self, options=None):
        print("There are no special options available in the main menu.")
        print("\n")

    def list_modules(self, options=None):

        print("Available modules:")
        for m in sorted(self.modules):
            print("\t%s" % m)

    def list_reports(self, options=None):
        print("Available reports:")
        for r in sorted(self.reports):
            print("\t%s" % r)

    def use_module(self, options=None):
        if options in self.modules:
            show_menu(ModuleCommands, ModuleCompleter, options)
        else:
            print("That is an invalid module.")

    def use_report(self, options=None):
        if options in self.reports:
            show_menu(ReportCommands, ModuleCompleter, options)
        else:
            print("That is an invalid module.")


class ModuleCommands(GlobalCommands):
    def __init__(self, name=None):
        super(ModuleCommands, self).__init__(name)

        self.name = name

        self.cmd["options"] = {
            "func": self.view_options,
            "help": "Display available options",
        }

        self.cmd["set"] = {"func": self.set, "help": "Set value for an option"}

        self.cmd["unset"] = {"func": self.unset, "help": "Unset value for an option"}

        self.cmd["run"] = {"func": self.run_module, "help": "Run the module/report"}

        self.cmd["reset"] = {
            "func": self.reset_module,
            "help": "Reset the options back to default",
        }

        self.reset_module()

    def reset_module(
        self, options=None, module_data=["custom_modules", "included.modules."]
    ):
        config = get_config_options()
        db = initialize_database(config)
        custom_path = config["PROJECT"].get(module_data[0], None)

        if custom_path and self.name in get_modules(custom_path):
            module_path = os.path.join(custom_path, self.name)

        else:
            module_path = module_data[1] + self.name
        Module = load_module(module_path)
        if "custom_modules" in module_data:

            if Module.Module.__doc__:
                print("%s" % self.name)

                print(Module.Module.__doc__)
            self.m = Module.Module(db)
        else:
            if Module.Report.__doc__:
                print("%s" % self.name)
                print(Module.Report.__doc__)

            self.m = Module.Report(db)
        self.m.base_config = config
        # Populate the options
        self.m.set_options()

        self.options = {}

        for a in self.m.options._actions:
            atype = a.__class__.__name__
            if atype != "_HelpAction":
                o = a.option_strings[-1].replace("-", "")
                self.options[o] = {
                    "arg": a.option_strings[-1],
                    "help": a.help,
                    "type": atype,
                    "required": a.required,
                }

                if atype == "_StoreTrueAction":
                    if a.default:
                        self.options[o]["value"] = True
                    else:
                        self.options[o]["value"] = False

                elif a.default:
                    self.options[o]["value"] = a.default

                else:
                    self.options[o]["value"] = ""

        module_config_data = get_config_options(self.name + ".ini")

        if "ModuleSettings" in module_config_data.sections():
            for k in module_config_data["ModuleSettings"].keys():
                if k in self.options.keys():
                    self.options[k]["value"] = module_config_data["ModuleSettings"][k]

    def view_options(self, options=None):

        options = sorted(self.options.keys())
        print("Options for %s" % self.name)
        print(
            "{:<25} | {:<10} | {:<20} | {:<40}".format(
                "Field", "Required", "Value", "Description"
            )
        )
        print("-" * 95)
        for c in options:

            print(
                "{:<25} | {:<10} | {:<20} | {:<40}".format(
                    c,
                    str(self.options[c]["required"]),
                    str(self.options[c]["value"]),
                    self.options[c]["help"],
                )
            )
        print("\n\n")

    def set(self, options=None):
        if options:
            if options.count(" ") > 0:
                option = options.split(" ")[0]

                if option not in self.options.keys():
                    print("Unrecognized option: %s" % option)
                    return

                val = " ".join(options.split(" ")[1:])
                if self.options[option]["type"] == "_StoreTrueAction":
                    if val.lower() in "true":
                        self.options[option]["value"] = True
                    elif val.lower() in "false":
                        self.options[option]["value"] = False
                    else:
                        print(
                            "%s is too ambiguous - it should be either True or False"
                            % val
                        )
                else:
                    self.options[option]["value"] = val
            else:
                print(
                    "You need to supply a value to set! Use unset to remove all values."
                )
        else:
            print("You need to supply an option to set.")

    def unset(self, options=None):
        if options:
            option = options.split(" ")[0]
            if option in self.options.keys():

                if self.options[option]["type"] == "_StoreTrueAction":
                    self.options[option]["value"] = False
                else:
                    self.options[option]["value"] = ""

            else:
                print("%s is not a valid option." % option)

        else:
            print("You need to supply an option to unset.")

    def run_module(self, options=None):
        args = []
        for o in self.options.keys():
            if self.options[o]["value"]:
                args.append(self.options[o]["arg"])
                if self.options[o]["type"] != "_StoreTrueAction":
                    args.append(self.options[o]["value"])
            else:
                if self.options[o]["required"]:
                    print("Option %s is required to run." % o)
                    return
        args, unknown = self.m.options.parse_known_args(args)
        self.m.run(args)


class ReportCommands(ModuleCommands):
    def reset_module(self, options=None):

        super(ReportCommands, self).reset_module(
            module_data=["custom_reports", "included.reports."]
        )


class MainCompleter(object):
    def __init__(self, option_class):
        self.options = sorted(option_class.cmd)
        self.modules = sorted(option_class.modules)
        self.reports = sorted(option_class.reports)

    def complete(self, text, state):

        if state == 0:  # on first trigger, build possible matches

            if readline.get_line_buffer().startswith("use_module "):

                self.matches = [s for s in self.modules if s and s.startswith(text)]
            elif readline.get_line_buffer().startswith("use_report "):

                self.matches = [s for s in self.reports if s and s.startswith(text)]
            elif text:  # cache matches (entries that start with entered text)

                self.matches = [s for s in self.options if s and s.startswith(text)]
            else:  # no text entered, all matches possible
                self.matches = self.options[:]

        # return match indexed by state
        try:
            return self.matches[state]
        except IndexError:
            return None


class ModuleCompleter(object):
    def __init__(self, option_class):
        self.options = sorted(option_class.cmd)
        self.module_options = sorted(option_class.options)

    def complete(self, text, state):

        if state == 0:  # on first trigger, build possible matches

            full_cmd = readline.get_line_buffer()
            if full_cmd.startswith("set "):
                if full_cmd.count(" ") == 1:
                    self.matches = [
                        s for s in self.module_options if s and s.startswith(text)
                    ]
                else:
                    # print("\n%s\n%s" % (full_cmd, text))
                    self.matches = [s for s in glob.glob(full_cmd.split(" ")[-1] + "*")]
            elif text:  # cache matches (entries that start with entered text)

                self.matches = [s for s in self.options if s and s.startswith(text)]
            else:  # no text entered, all matches possible
                self.matches = self.options[:]

        # return match indexed by state
        try:
            return self.matches[state]
        except IndexError:
            return None


def show_menu(CommandClass, CompleterClass, name):
    command = CommandClass(name)
    completer = CompleterClass(command)
    readline.set_completer(completer.complete)
    readline.set_completer_delims(" ")
    readline.parse_and_bind("tab: complete")

    res = False
    while res is not True:
        valid_commands = command.cmd.keys()

        ret_cmd = six.input("%s> " % name).strip()
        cmd, options = (ret_cmd.split(" ")[0], " ".join(ret_cmd.split(" ")[1:]))
        if cmd == "debug":
            pdb.set_trace()

        elif cmd.lower() in valid_commands:
            res = command.run_cmd(cmd, options)

        else:
            print("Invalid command.")

        readline.set_completer(completer.complete)


if __name__ == "__main__":
    print_banner()

    name = "Armory"
    show_menu(MainCommands, MainCompleter, name)
