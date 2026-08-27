#!/usr/bin/python
from multiprocessing import Pool as ThreadPool
from armory2.armory_main.included.utilities.color_display import (
    display,
    display_error,
    display_purple,
)
from armory2.armory_main.included.utilities import which
import shlex
import os
import time

import argparse
import sys

if sys.version_info[0] < 3:
    from subprocess32 import Popen, STDOUT, PIPE
else:
    from subprocess import Popen, STDOUT, PIPE

import threading
import uuid as _uuid
import pdb
from pathlib import Path

# When set to '1' (by armory-web's module runner), each run_cmd call wraps
# the subprocess stdout with structured markers so the web UI can route output
# to per-process terminal windows.
_STRUCTURED = os.getenv('ARMORY_STRUCTURED_OUTPUT') == '1'
from armory2.armory_cmd import get_config_options

def get_docker_run(obj):

    config = get_config_options()

    base_path = config['ARMORY_BASE_PATH']
    docker_extra = config.get('DOCKER_FOLDERS', '')

    binary = f"docker run -it --rm {obj.args.docker_options[1:-1]} {docker_extra} -v \"{base_path}:{base_path}\" {obj.docker_name} "

    if hasattr(obj, 'docker_run_binary'):
        binary += f" {obj.docker_run_binary}"

    return binary

def get_binary(obj, args):
    use_docker = False

    if obj.docker_name and obj.use_docker:
        binary = get_docker_run(obj)

        return binary


    if not args.binary:
        binary = which.run(obj.binary_name)
    else:
        binary = which.run(args.binary)

    if binary:
        resolved_path = str(Path(binary).expanduser().resolve())
        
        if 'pipx' in resolved_path:
            pipx_path, pipx_bin = resolved_path.rsplit('/', 1)
            binary = f"{os.path.join(pipx_path, 'python')} {resolved_path}"
            
        return binary
            # Is a python pipx app. 
            

    if obj.docker_name:
        binary = get_docker_run(obj)
        return binary

    if args.no_binary:
        return None
    raise Exception(
        "%s binary not found. Please explicitly provide path with --binary"
        % obj.name
    )

class ModuleTemplate(object):
    """
    Master template for a module. Actual modules should just override this

    """

    name = "Template"
    requirements = []
    
    def __init__(self):

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
    no_threading = False
    docker_name = ''
    use_docker = False
    docker_repo = None

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
            "--delay", help="Delay in between requests", default=0, type=int
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

        self.options.add_argument(
            "--docker_options", help="Options to pass to docker", default = ""
        )
        # self.options.add_argument('--profile1', help="Use first profile options")

    def run(self, args):
        self.args = args

        delay = args.delay
        if self.args.tool_args:
            tool_args = []
            for t in self.args.tool_args:
                if " " in t:
                    tool_args.append('"' + t.replace('"', '\\"') + '"')
                else:
                    tool_args.append(t)
            self.args.tool_args = " ".join(tool_args)

        else:
            self.args.tool_args = ""

        if self.args.profile1:
            self.args.tool_args += " " + self.args.profile1_data

        elif self.args.profile2:
            self.args.tool_args += " " + self.args.profile2_data
        elif self.args.profile3:
            self.args.tool_args += " " + self.args.profile3_data
        elif self.args.profile4:
            self.args.tool_args += " " + self.args.profile4_data

        self.binary = get_binary(self, args)
        
        if self.args.timeout and self.args.timeout != "0":
            timeout = int(self.args.timeout)
        else:
            timeout = None
        # Currently not used, therefor to please flake8 commenting out.
        # if self.args.hard_timeout and self.args.hard_timeout != "0":
        #    hard_timeout = int(self.args.hard_timeout)
        # else:
        #    hard_timeout = None

        targets = self.get_targets(self.args)

        if not self.args.no_binary and targets:
            cmd = self.build_cmd(self.args).strip()
            cmds = self.populate_cmds(cmd, timeout, targets, delay)

            # if hard_timeout:
            #     Popen(['./kill_process.py', str(os.getpid()), self.binary, str(hard_timeout)], preexec_fn=os.setpgrp)

            self.pre_run(self.args)

            if self.no_threading:
                total_commands = len(cmds)
                for i, cmd in enumerate(cmds):
                    run_cmd(cmd)
                    display_purple(
                        "Processing results from command {} of {}.".format(
                            i + 1, total_commands
                        )
                    )
                    self.process_output([targets[i]])
            else:
                pool = ThreadPool(int(self.args.threads))

                total_commands = len(cmds)
                done = 1
                for i in pool.imap_unordered(run_cmd, cmds):
                    display_purple(
                        "Processing results from command {} of {}.".format(
                            done, total_commands
                        )
                    )
                    done += 1
                    # display("DEBUG: i: {}".format(i))
                    # display("DEBUG: target: {}".format(targets[cmds.index(i)]))
                    self.process_output([targets[cmds.index(i)]])
            self.post_run(self.args)
        if targets and self.args.no_binary:
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

    def populate_cmds(self, cmd, timeout, targets, delay):
        """
        Populate the cmds, if you need to do it in a custom manner.
        """

        return [shlex.split(cmd.format(**t)) + [timeout, delay] for t in targets]

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

    def build_generic_targets(self, targets, output_path):
        """
        Helper function that can be used to create targets dictionary
        """
        res = []
        for t in targets:
            if type(t) == list and len(t) > 1 and t[1]:

                res.append(
                    {
                        "target": t[0] if "FUZZ" in t[0] else f"{t[0]}/FUZZ",
                        "output": os.path.join(
                            output_path,
                            t[0]
                            .replace(":", "_")
                            .replace("/", "_")
                            .replace("?", "_")
                            .replace("&", "_")
                            + f"-{t[1]}-dir.txt",  # noqa: W503
                        ),
                        "virtualhost": t[1],
                    }
                )
            else:
                if type(t) == list:
                    t = t[0]
                # pdb.set_trace()
                res.append(
                    {
                        "target": t,
                        "output": os.path.join(
                            output_path,
                            t.replace(":", "_")
                            .replace("/", "_")
                            .replace("?", "_")
                            .replace("&", "_")
                            + "-dir.txt",  # noqa: W503
                        ),
                    }
                )

        return res


class ToolTemplateNoOutput(ToolTemplate):
    """
    Generic template for running a tool, and ingesting the output.
    """

    def run(self, args):
        delay = args.delay
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

        self.binary = get_binary(self, args)

        
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

            cmds = [
                (shlex.split(cmd.format(**t)) + [timeout, delay], t["output"])
                for t in targets
            ]

            # if hard_timeout:
            #     Popen(['./kill_process.py', str(os.getpid()), self.binary, str(hard_timeout)], preexec_fn=os.setpgrp)

            self.pre_run(args)
            pool = ThreadPool(int(args.threads))

            total_commands = len(cmds)
            done = 1
            for i in pool.imap_unordered(run_cmd_noout, cmds):
                display_purple(
                    "Processing results from command {} of {}.".format(
                        done, total_commands
                    )
                )
                done += 1
                # display("DEBUG: i: {}".format(i))
                # display("DEBUG: target: {}".format(targets[cmds.index(i)]))
                self.process_output([targets[cmds.index(i)]])
            self.post_run(args)
        if targets and args.no_binary:

            self.process_output(targets)


def run_cmd(cmd):
    c = cmd[:-2]
    timeout = cmd[-2]
    delay = cmd[-1]
    cmd_str = " ".join(c)

    if _STRUCTURED:
        proc_id = _uuid.uuid4().hex[:16]
        print(f'__ARMORY:S:{proc_id}:{cmd_str}', flush=True)
    else:
        display("Executing command: %s" % cmd_str)

    current_time = time.time()

    if timeout:
        if _STRUCTURED:
            process = Popen(c, stdout=PIPE, stderr=STDOUT, text=True, bufsize=1)
            print(f'__ARMORY:P:{proc_id}:{process.pid}', flush=True)
            def _drain():
                for ln in process.stdout:
                    print(f'__ARMORY:L:{proc_id}:{ln.rstrip()}', flush=True)
            t = threading.Thread(target=_drain, daemon=True)
            t.start()
            while time.time() < current_time + timeout and process.poll() is None:
                time.sleep(0.5)
            if process.poll() is None:
                display_error("Timeout of %s reached. Aborting thread for command: %s" % (timeout, cmd_str))
                process.terminate()
            t.join()
        else:
            process = Popen(c)
            while time.time() < current_time + timeout and process.poll() is None:
                time.sleep(5)
            if process.poll() is None:
                display_error("Timeout of %s reached. Aborting thread for command: %s" % (timeout, cmd_str))
                process.terminate()
    else:
        if _STRUCTURED:
            process = Popen(c, stdout=PIPE, stderr=STDOUT, text=True, bufsize=1)
            print(f'__ARMORY:P:{proc_id}:{process.pid}', flush=True)
            for ln in process.stdout:
                print(f'__ARMORY:L:{proc_id}:{ln.rstrip()}', flush=True)
            process.wait()
        else:
            process = Popen(c)
            process.wait()

    if _STRUCTURED:
        print(f'__ARMORY:E:{proc_id}:{process.returncode}', flush=True)

    if delay:
        display(f"Sleeping for {delay} seconds")
        time.sleep(delay)
    return cmd


def run_cmd_noout(cmd_data):
    cmd = cmd_data[0]
    output = cmd_data[1]
    c = cmd[:-2]
    timeout = cmd[-2]
    delay = cmd[-1]
    cmd_str = " ".join(c)

    if _STRUCTURED:
        proc_id = _uuid.uuid4().hex[:16]
        print(f'__ARMORY:S:{proc_id}:{cmd_str}', flush=True)
    else:
        display("Executing command: %s" % cmd_str)

    current_time = time.time()
    f = open(output, "w")

    if timeout:
        process = Popen(c, stdout=f, stderr=STDOUT)
        while time.time() < current_time + timeout and process.poll() is None:
            time.sleep(5)
        if process.poll() is None:
            display_error("Timeout of %s reached. Aborting thread for command: %s" % (timeout, cmd_str))
            process.terminate()
    else:
        process = Popen(c, stdout=f, stderr=STDOUT)
        process.wait()

    f.close()

    if _STRUCTURED:
        print(f'__ARMORY:E:{proc_id}:{process.returncode}', flush=True)

    if delay:
        display(f"Sleeping for {delay} seconds")
        time.sleep(delay)
    return cmd_data
