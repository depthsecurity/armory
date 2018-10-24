#!/usr/bin/python

from included.ReportTemplate import ReportTemplate
from database.repositories import BaseDomainRepository, UserRepository, CredRepository
import pdb
import json


class Report(ReportTemplate):
    """
    This report displays data related to discovered user accounts.
    """

    name = "UserReport"

    def __init__(self, db):

        self.BaseDomain = BaseDomainRepository(db)
        self.User = UserRepository(db)
        self.Cred = CredRepository(db)

    def set_options(self):

        super(Report, self).set_options()

        self.options.add_argument(
            "-u1",
            "--usernames_passwords",
            help="Prints out username/password pairs",
            action="store_true",
        )
        self.options.add_argument(
            "-u2",
            "--emails_passwords",
            help="Prints out email/password pairs",
            action="store_true",
        )
        self.options.add_argument(
            "-u3", "--emails", help="Prints out e-mail addresses", action="store_true"
        )
        self.options.add_argument(
            "-u4", "--accounts", help="Prints out user accounts", action="store_true"
        )
        self.options.add_argument(
            "-u5", "--full", help="Prints out full user data", action="store_true"
        )

    def run(self, args):

        results = []

        domains = self.BaseDomain.all()
        for d in domains:
            for user in d.users:
                if args.emails:
                    results.append(user.email)
                elif args.accounts:
                    results.append(user.email.split("@")[0])
                elif args.full:
                    results.append(
                        "{}|{}|{}|{}".format(
                            user.first_name, user.last_name, user.email, user.job_title
                        )
                    )
                else:
                    for cred in user.creds:
                        if cred.password and cred.password != "None":
                            if args.emails_passwords:
                                txt = "%s:%s" % (user.email, cred.password)

                            elif args.usernames_passwords:
                                txt = "%s:%s" % (
                                    user.email.split("@")[0],
                                    cred.password,
                                )

                            if txt not in results:
                                results.append(txt)

        self.process_output(results, args)
