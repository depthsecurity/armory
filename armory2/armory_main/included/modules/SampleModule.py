#!/usr/bin/python

from armory2.armory_main.included.ModuleTemplate import ModuleTemplate
from armory2.armory_main.included.TestTemplate import ModuleTest


class Module(ModuleTemplate):
    """
    Minimal example module: prints whatever it is given.
    """

    name = "SampleModule"

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument("-p", "--print_message", help="Message to print")

    def run(self, args):
        print("Running!")
        if args.print_message:
            print("Printing message")
            print(args.print_message)


class Tests(ModuleTest):
    """
    Example of the tests a module can carry. `armory -t SampleModule` runs
    these alongside the built-in smoke checks.

    Available out of the box:

      self.module          a fresh Module() with set_options() applied
      self.parse(*argv)    argv -> parsed args namespace
      self.run_module()    run the module (--no_binary is added for tools)
      self.data            the sample database rows (see testing/fixtures.py)
      self.tmpdir          a scratch directory, deleted afterwards

    ...plus every assert* method from unittest, and a transaction rollback
    around each test so writes never persist.
    """

    def test_message_is_optional(self):
        with self.captured_output() as out:
            self.run_module()
        self.assertIn("Running!", out.getvalue())
        self.assertNotIn("Printing message", out.getvalue())

    def test_message_is_printed(self):
        with self.captured_output() as out:
            self.run_module("--print_message", "hello from the test suite")
        self.assertIn("hello from the test suite", out.getvalue())

    def test_the_sample_database_is_populated(self):
        # Every test starts from the same fixture data, so a module's
        # process_output has something realistic to work against.
        self.assertEqual(self.data.host.ip_address, "192.0.2.10")
        self.assertIn(80, [p.port_number for p in self.data.host.port_set.all()])
