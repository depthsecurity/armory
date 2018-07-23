#!/usr/bin/python
import argparse
import sys

if sys.version_info[0] < 3:
    from subprocess32 import Popen
else:
    from subprocess import Popen

from multiprocessing import Pool as ThreadPool


class ModuleTemplate(object):
    """
    Master template for a module. Actual modules should just override this

    """
    name = "Template"
    db = None

    def __init__(self, db=None):

        pass


    def set_options(self):

        self.options = argparse.ArgumentParser(prog=self.name)

        


    def run(self, args):
        '''
        Execute the module, receives argparse arguments.
        '''
        pass


class ToolTemplate(ModuleTemplate):
    """
    Generic template for running a tool, and ingesting the output.
    """

    timeout = 0

    name="tool"
    db = None


    def set_options(self):
        super(Module, self).set_options()
        
        self.options.add_argument('-b', '--binary', help="Path to the binary")
        self.options.add_argument('-i', '--import_database', help="Import data from database", action="store_true")
        self.options.add_argument('-o', '--output_path', help="Relative path (to the base directory) to store Fierce output", default="fierceFiles")
        self.options.add_argument('--threads', help="Number of Armory threads to use", default="10")
        self.options.add_argument('--timeout', help="Thread timeout in seconds, default is 300.", default="300")
        self.options.add_argument('--extra_args', help="Additional arguments to be passed to the tool")


    def run(self, args):


        if not args.binary:
            self.binary = which.run(self.name)

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("%s binary not found. Please explicitly provide path with --binary" % self.name)

        self.timeout = int(self.args.timeout)

        targets = self.get_targets(args)

        cmd = self.build_cmd(args)


        pool = ThreadPool(int(self.args.threads))

    def run_cmd(self, cmd):
        display("Executing command: %s" % ' '.join(cmd))
        timeout = self.timeout
        try:
            Popen(cmd).wait(timeout=timeout)
        except:
            display_error("Timeout of %s reached. Aborting thread for command: %s" % (timeout, ' '.join(cmd)))


        
