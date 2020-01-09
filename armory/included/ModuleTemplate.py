#!/usr/bin/python
from multiprocessing import Pool as ThreadPool
from armory.included.utilities.color_display import display, display_error, display_purple
from armory.included.utilities import which
import shlex
import os
import time

import argparse
import sys

if sys.version_info[0] < 3:
    from subprocess32 import Popen, STDOUT
else:
    from subprocess import Popen, STDOUT


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
        """
        Execute the module, receives argparse arguments.
        """
        pass


class ToolTemplate(ModuleTemplate):
    """
    Generic template for running a tool, and ingesting the output.
    """

    timeout = 0
    binary_name = ""

    def set_options(self):
        super(ToolTemplate, self).set_options()

        self.options.add_argument("-b", "--binary", help="Path to the binary")
        self.options.add_argument(
            "-o",
            "--output_path",
            help="Relative path (to the base directory) to store output",
            default=os.path.join("output", self.name),
        )
        self.options.add_argument(
            "--threads", help="Number of Armory threads to use", default="10"
        )
        self.options.add_argument(
            "--timeout",
            help="Thread timeout in seconds, default is never timeout",
            default="0",
        )
        self.options.add_argument(
            "--hard_timeout",
            help="Hard timeout in seconds. When this is elapsed, the thread will be kill -9'd",
            default="0",
        )
        self.options.add_argument(
            "--tool_args",
            help="Additional arguments to be passed to the tool",
            nargs=argparse.REMAINDER,
        )
        self.options.add_argument(
            "--no_binary",
            help="Runs through without actually running the binary. Useful for if you already ran the tool and just want to process the output.",
            action="store_true",
        )
        self.options.add_argument(
            "--profile1", help="Append profile1_data to command", action="store_true"
        )
        self.options.add_argument(
            "--profile1_data", help="Additional arguments to be appended", default=""
        )
        self.options.add_argument(
            "--profile2", help="Append profile1_data to command", action="store_true"
        )
        self.options.add_argument(
            "--profile2_data", help="Additional arguments to be appended", default=""
        )
        self.options.add_argument(
            "--profile3", help="Append profile1_data to command", action="store_true"
        )
        self.options.add_argument(
            "--profile3_data", help="Additional arguments to be appended", default=""
        )
        self.options.add_argument(
            "--profile4", help="Append profile1_data to command", action="store_true"
        )
        self.options.add_argument(
            "--profile4_data", help="Additional arguments to be appended", default=""
        )

        # self.options.add_argument('--profile1', help="Use first profile options")

    def run(self, args):
        if args.tool_args:
            args.tool_args = " ".join(args.tool_args)
        else:
            args.tool_args = ""

        if args.profile1:
            args.tool_args += " " + args.profile1_data

        elif args.profile2:
            args.tool_args += " " + args.profile2_data
        elif args.profile3:
            args.tool_args += " " + args.profile3_data
        elif args.profile4:
            args.tool_args += " " + args.profile4_data

        if not args.binary:
            self.binary = which.run(self.binary_name)
        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print(
                "%s binary not found. Please explicitly provide path with --binary"
                % self.name
            )

        else:
            if args.timeout and args.timeout != "0":
                timeout = int(args.timeout)
            else:
                timeout = None
            # Currently not used, therefor to please flake8 commenting out.
            # if args.hard_timeout and args.hard_timeout != "0":
            #    hard_timeout = int(args.hard_timeout)
            # else:
            #    hard_timeout = None

            targets = self.get_targets(args)

            if not args.no_binary and targets:
                cmd = self.build_cmd(args).strip()

                cmds = [shlex.split(cmd.format(**t)) + [timeout] for t in targets]

                # if hard_timeout:
                #     Popen(['./kill_process.py', str(os.getpid()), self.binary, str(hard_timeout)], preexec_fn=os.setpgrp)

                self.pre_run(args)
                pool = ThreadPool(int(args.threads))

                total_commands = len(cmds)
                done = 1
                for i in pool.imap_unordered(run_cmd, cmds):
                    display_purple("Processing results from command {} of {}.".format(done, total_commands))
                    done += 1
                    # display("DEBUG: i: {}".format(i))
                    # display("DEBUG: target: {}".format(targets[cmds.index(i)]))
                    self.process_output([targets[cmds.index(i)]])
                self.post_run(args)
            if targets and args.no_binary:
                self.process_output(targets)

    def get_targets(self, args):
        """
        This module is used to build out a target list and output file list, depending on the arguments. Should return a
        list in the format [{'target':'target', 'output':'output'}), {'target':'target', 'output':'output'}, etc, etc]
        """

        return []

    def build_cmd(self, args):
        """
        Create the actual command that will be executed. Use {target} and {output} as placeholders.
        """

        return ""

    def pre_run(self, args):
        """
        Does anything you need to be done before the actual commands are threaded and executed. Has access to self and args.
        """

        return

    def post_run(self, args):
        """
        Any cleanup you need to do. This runs before process_output, has access to args.
        """

        return

    def process_output(self, cmds):
        """
        Process the output generated by the earlier commands.
        """


def run_cmd(cmd_data):
    cmd = cmd_data[0]
    output = cmd_data[1]
    c = cmd[:-1]
    timeout = cmd[-1]
    display("Executing command: %s" % " ".join(c))

    current_time = time.time()
    f = open(output, 'w')
    if timeout:
        
        process = Popen(c, stdout=f)
        while time.time() < current_time + timeout and process.poll() is None:
            time.sleep(5)
        if process.poll() is None:

            display_error(
                "Timeout of %s reached. Aborting thread for command: %s"
                % (timeout, " ".join(c))
            )
            process.terminate()

    else:
        Popen(c, stdout=f).wait()
    f.close()
    return cmd


class ToolTemplateNoOutput(ToolTemplate):
    """
    Generic template for running a tool, and ingesting the output.
    """
    
    def run(self, args):
        if args.tool_args:
            args.tool_args = " ".join(args.tool_args)
        else:
            args.tool_args = ""

        if args.profile1:
            args.tool_args += " " + args.profile1_data

        elif args.profile2:
            args.tool_args += " " + args.profile2_data
        elif args.profile3:
            args.tool_args += " " + args.profile3_data
        elif args.profile4:
            args.tool_args += " " + args.profile4_data

        if not args.binary:
            self.binary = which.run(self.binary_name)
        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print(
                "%s binary not found. Please explicitly provide path with --binary"
                % self.name
            )

        else:
            if args.timeout and args.timeout != "0":
                timeout = int(args.timeout)
            else:
                timeout = None
            # Currently not used, therefor to please flake8 commenting out.
            # if args.hard_timeout and args.hard_timeout != "0":
            #    hard_timeout = int(args.hard_timeout)
            # else:
            #    hard_timeout = None

            targets = self.get_targets(args)

            if not args.no_binary and targets:
                cmd = self.build_cmd(args).strip()

                cmds = [(shlex.split(cmd.format(**t)) + [timeout], t['output']) for t in targets]

                # if hard_timeout:
                #     Popen(['./kill_process.py', str(os.getpid()), self.binary, str(hard_timeout)], preexec_fn=os.setpgrp)

                self.pre_run(args)
                pool = ThreadPool(int(args.threads))

                total_commands = len(cmds)
                done = 1
                for i in pool.imap_unordered(run_cmd_noout, cmds):
                    display_purple("Processing results from command {} of {}.".format(done, total_commands))
                    done += 1
                    # display("DEBUG: i: {}".format(i))
                    # display("DEBUG: target: {}".format(targets[cmds.index(i)]))
                    self.process_output([targets[cmds.index(i)]])
                self.post_run(args)
            if targets and args.no_binary:
                
                self.process_output(targets)

            


def run_cmd(cmd):
    c = cmd[:-1]
    timeout = cmd[-1]
    display("Executing command: %s" % " ".join(c))

    current_time = time.time()

    if timeout:
        process = Popen(c)
        while time.time() < current_time + timeout and process.poll() is None:
            time.sleep(5)
        if process.poll() is None:

            display_error(
                "Timeout of %s reached. Aborting thread for command: %s"
                % (timeout, " ".join(c))
            )
            process.terminate()

    else:
        Popen(c).wait()

    return cmd


def run_cmd_noout(cmd_data):
    cmd = cmd_data[0]
    output = cmd_data[1]
    c = cmd[:-1]
    timeout = cmd[-1]
    display("Executing command: %s" % " ".join(c))

    current_time = time.time()
    f = open(output, 'w')
    if timeout:
        
        process = Popen(c, stdout=f, stderr=STDOUT)
        while time.time() < current_time + timeout and process.poll() is None:
            time.sleep(5)
        if process.poll() is None:

            display_error(
                "Timeout of %s reached. Aborting thread for command: %s"
                % (timeout, " ".join(c))
            )
            process.terminate()

    else:
        Popen(c, stdout=f, stderr=STDOUT).wait()
    f.close()
    return cmd_data