#!/usr/bin/python

from included.ModuleTemplate import ModuleTemplate


class Module(ModuleTemplate):

    name = "SampleModule"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-p", "--print_message", help="Message to print")

    def run(self, args):
        print("Running!")
        if args.print_message:
            print("Printing message")
            print(args.print_message)
