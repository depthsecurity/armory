#!/usr/bin/python

from included.ReportTemplate import ReportTemplate
from database.repositories import UserRepository
import pdb
import json


class Report(ReportTemplate):
    """
    This report displays all of the found email addresses.
    """

    name = "EmailReport"
    markdown = ["####", "-"]

    def __init__(self, db):
        self.User = UserRepository(db)

    def set_options(self):
        super(Report, self).set_options()
        self.options.add_argument("-t", "--tool", help="Source tool")

    def run(self, args):
        # Cidrs = self.CIDR.
        results = {}
        res = []

        users = self.User.all()

        for u in users:
            if u.email != None and u.email != "None":
                if args.tool:
                    # pdb.set_trace()
                    if not u.meta.get(args.tool, False):
                        continue
                if u.domain:
                    domain = u.domain.domain
                else:
                    domain = u.email.split("@")[1]
                if not results.get(domain, False):
                    results[domain] = []

                results[domain].append(u.email.lower())

        for d in results.keys():
            res.append(d)
            for e in sorted(results[d]):
                res.append("\t" + e)

        self.process_output(res, args)
