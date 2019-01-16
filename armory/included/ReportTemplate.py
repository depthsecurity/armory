#!/usr/bin/python
import json
import argparse
import pyperclip
import codecs
import pdb


def get_marker(txt, marker):
    m = txt.count(marker)

    while m > 0:
        if txt[:m] == marker * m:
            return m, txt[m:]
        m -= 1

    return 0, txt


class ReportTemplate(object):
    """Template report"""

    name = "ReportTemplate"

    depth_marker = "\t"
    markdown = ["", "#", "##", "-", "--", "---", "----", "-----", "------"]

    table_delim = "|"
    table_newline = "\n"

    def __init__(self, db=None):
        pass

    def set_options(self):

        self.options = argparse.ArgumentParser(prog=self.name)
        self.options.add_argument(
            "-j", "--json", help="Output as JSON", action="store_true"
        )
        self.options.add_argument(
            "-c", "--cmd", help="Output as Custom MarkDown", action="store_true"
        )
        self.options.add_argument(
            "-p", "--plain", help="Output as plain, with tabs", action="store_true"
        )
        self.options.add_argument(
            "-x", "--clipboard", help="Copy output to clipboard", action="store_true"
        )
        self.options.add_argument("-o", "--output", help="Save output to file")
        self.options.add_argument(
            "--custom_depth", help="Comma separated list of custom markdown"
        )
        self.options.add_argument(
            "-s",
            "--scope",
            help="Scoping restrictions for report.",
            choices=["active", "passive", "all"],
            default="all",
        )

    def run(self, args):
        """
        Execute the module, receives argparse arguments.
        """
        pass

    def process_output(self, text, args):

        if args.json:
            res = self.output_as_json(text)
            print(res)

        elif args.cmd:
            if args.custom_depth:
                self.markdown = args.custom_depth.split(",")
            res = self.output_as_cmd(text)
            print(res)

        elif args.plain:
            res = "\n".join(text)
            print(res)
        else:
            print(text)
            res = text
        if args.clipboard:
            pyperclip.copy(res)

        if args.output:
            codecs.open(args.output, "w", encoding="utf-8").write(u"{}".format(res))

    def output_as_json(self, data):
        return json.dumps(data)

    def output_as_cmd(self, data):
        """
        This pretty much needs to be defined on a report by report basis
        """
        text = ""
        for d in data:
            parts = get_marker(d, self.depth_marker)
            text += "%s%s\n" % (self.markdown[parts[0]], parts[1])

        return text
