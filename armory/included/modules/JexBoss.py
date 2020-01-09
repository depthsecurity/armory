#!/usr/bin/python

from armory.database.repositories import IPRepository
from ..ModuleTemplate import ToolTemplate
from ..utilities.color_display import display_error
from ..utilities import get_urls
import os
import tempfile
from time import time
import sys

if sys.version[0] == "3":
    xrange = range


class Module(ToolTemplate):

    name = "JexBoss"
    binary_name = "jexboss.py"

    def __init__(self, db):
        self.db = db
        self.IPAddress = IPRepository(db, self.name)

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument(
            "-i",
            "--import_database",
            help="Import URLs from the database",
            action="store_true",
        )
        self.options.add_argument("-f", "--import_file", help="Import URLs from file")


    def get_targets(self, args):

        timestamp = str(int(time()))
        targets = []
        if args.import_file:
            targets += [t for t in open(args.import_file).read().split("\n") if t]

        if args.import_database:
            if args.rescan:
                targets += get_urls.run(self.db, scope_type="active")
            else:
                targets += get_urls.run(self.db, scope_type="active", tool=self.name)

        if targets:
            if args.output_path[0] == "/":
                self.path = os.path.join(
                    self.base_config["PROJECT"]["base_path"],
                    args.output_path[1:],
                    timestamp,
                )
            else:
                self.path = os.path.join(
                    self.base_config["PROJECT"]["base_path"],
                    args.output_path,
                    timestamp,
                )
            if not os.path.exists(self.path):
                os.makedirs(self.path)

            res = []
            i = 0
            if args.group_size == 0:
                args.group_size = len(targets)

            for url_chunk in self.chunks(targets, args.group_size):
                i += 1

                _, file_name = tempfile.mkstemp()
                open(file_name, "w").write("\n".join(url_chunk))

                res.append(
                    {
                        "target": file_name,
                        "output": self.path + "-results-{}.txt".format(i),
                    }
                )

            return res
        else:
            display_error("No hosts provided to scan.")
            sys.exit(1)

    def build_cmd(self, args):

        command = self.binary + " -m file-scan -file {target} -out {output} "

        if args.tool_args:
            command += args.tool_args

        return command

    def process_output(self, cmds):
        """
        """

        self.IPAddress.commit()

    def chunks(self, chunkable, n):
        """ Yield successive n-sized chunks from l.
        """
        for i in xrange(0, len(chunkable), n):
            yield chunkable[i : i + n]  # noqa: E203
