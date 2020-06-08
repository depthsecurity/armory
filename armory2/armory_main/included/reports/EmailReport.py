#!/usr/bin/python
from armory2.armory_main.models import User
from armory2.armory_main.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This report displays all of the found email addresses.
    """

    name = "EmailReport"
    markdown = ["####", "-"]

    def set_options(self):
        super(Report, self).set_options()
        self.options.add_argument("-t", "--tool", help="Source tool")

    def run(self, args):
        # Cidrs = self.CIDR.
        results = {}
        res = []

        users = User.objects.all()

        for u in users:
            if u.email is not None and u.email is not "None":
                if args.tool:
                    # pdb.set_trace()
                    if not u.meta.get(args.tool, False):
                        continue
                if u.domain:
                    domain = u.domain.name
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
