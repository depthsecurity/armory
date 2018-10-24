#!/usr/bin/python
# -*- coding: utf-8 -*-

from included.ReportTemplate import ReportTemplate
import pdb
import json
from fuzzywuzzy import process
import datetime


class Report(ReportTemplate):
    """
    This report takes a dumped NTDS file and a cracked NTDS file (from hashcat).
    It will then match up users and passwords, as well as do a password
    strength audit.
    """

    table_delim = u"λ"
    table_newline = u"Δ"

    name = "ADUserCreds"

    def __init__(self, db):

        pass

    def set_options(self):
        super(Report, self).set_options()

        self.options.add_argument(
            "-ih", "--hashes", help="Input ntds export containing hashes"
        )
        self.options.add_argument(
            "-ic",
            "--cracked",
            help="Input file containing cracked hashes (hash:plaintext)",
        )

        self.options.add_argument(
            "-o1",
            "--user_passwords",
            help="Report of all user names with plaintext passwords.",
            action="store_true",
        )
        self.options.add_argument(
            "--columns",
            help="Print out user/passwords by columns (Useful for screenshots)",
            action="store_true",
        )
        self.options.add_argument(
            "-o2",
            "--lm_hashes",
            help="export of all lines containing lm hashes",
            action="store_true",
        )
        self.options.add_argument(
            "-o3",
            "--password_audit",
            help="Display a password audit of the compromised data",
            action="store_true",
        )
        self.options.add_argument(
            "-d",
            "--delimiter",
            help="Delimiter for output of user passwords (Default :)",
            default=":",
        )
        self.options.add_argument(
            "-k",
            "--keywords",
            help="Additional keywords to search for the export report (Comma separated",
        )

    def run(self, args):
        td = self.table_delim
        nd = self.table_newline

        results = []
        length_count = {}
        hash_map = {}
        pw_count = {}
        hash_count = {}
        if args.user_passwords:
            if not (args.hashes and args.cracked):
                print("Error - you need to supply NTDS hashes and your crack results")
                return
            user_map = {}
            hash_map = {}

            cracked_data = open(args.cracked, "rb").read()
            if cracked_data[:2] == b"\xff\xfe":
                cracked_data = (
                    cracked_data[2:].replace(b"\x00", b"").replace(b"\r", b"")
                )
            cracked_data = cracked_data.decode()
            for c in cracked_data.split("\n"):
                h = c[:32]
                pw = c[33:]

                hash_map[h] = pw

            with open(args.hashes) as hash_file:
                for l in hash_file:
                    try:
                        username = l.split(":")[0]
                        h = l.split(":")[3]

                        if hash_map.get(h, False):
                            user_map[username] = hash_map[h]
                    except:
                        print("couldn't parse", l)

            if args.columns:
                maxlen = max([len(a) for a in user_map.keys()]) + 1

                for k in sorted(user_map.keys()):
                    results.append("%s%s%s" % (k, (maxlen - len(k)) * " ", user_map[k]))
            else:
                for k in sorted(user_map.keys()):
                    results.append("%s%s%s" % (k, args.delimiter, user_map[k]))

        elif args.lm_hashes:
            with open(args.hashes) as hash_file:
                for l in hash_file:

                    lm = l.split(":")[2]
                    if lm != "aad3b435b51404eeaad3b435b51404ee":
                        results.append(l.strip())

            results.sort()

        elif args.password_audit:
            if not (args.hashes and args.cracked):
                print("Error - you need to supply NTDS hashes and your crack results")
                return

            cracked_data = open(args.cracked).read()
            if cracked_data[:2] == "\xff\xfe":
                cracked_data = cracked_data[2:].replace("\x00", "").replace("\r", "")

            for c in cracked_data.split("\n"):
                h = c[:32]

                pw = c[33:]
                if pw[:5] == "$HEX[" and pw[-1] == "]":
                    pw = pw[5:-1].lower().decode("hex")
                hash_map[h] = pw

            with open(args.hashes) as hash_file:
                for l in hash_file:
                    try:
                        h = l.split(":")[3]

                        if hash_map.get(h, False):
                            if not pw_count.get(hash_map[h], False):
                                pw_count[hash_map[h]] = {
                                    "count": 0,
                                    "length": len(hash_map[h]),
                                }

                            pw_count[hash_map[h]]["count"] += 1

                            if not length_count.get(len(hash_map[h]), False):
                                length_count[len(hash_map[h])] = {"count": 0, "pws": []}

                            length_count[len(hash_map[h])]["count"] += 1
                            length_count[len(hash_map[h])]["pws"].append(hash_map[h])

                        if not hash_count.get(h, False):
                            hash_count[h] = 0

                        hash_count[h] += 1
                    except:
                        print("Couldn't parse", l)

            # Build out the stats

            results.append("\t\tGeneral Statistics")
            results.append("Count%sDescription" % td)

            total_hashes = sum([hash_count[c] for c in hash_count.keys()])
            total_hashes_unique = len(hash_count.keys())

            total_pws = sum([pw_count[h]["count"] for h in pw_count.keys()])
            total_pws_unique = len(pw_count.keys())

            total_cracked = int(total_pws / float(total_hashes) * 1000) / 10.0
            total_cracked_unique = (
                int(total_pws_unique / float(total_hashes_unique) * 1000) / 10.0
            )

            results.append("%s%sPassword Hashes" % (total_hashes, td))
            results.append("%s%sUnique Password Hashes" % (total_hashes_unique, td))
            results.append(
                "%s%sPasswords Discovered Through Cracking" % (total_pws, td)
            )
            results.append(
                "%s%sUnique Passwords Discovered Through Cracking"
                % (total_pws_unique, td)
            )
            results.append("%s%sPercent of Passwords Cracked" % (total_cracked, td))
            results.append(
                "%s%sPercent of Unique Passwords Cracked" % (total_cracked_unique, td)
            )

            shortest_passwords = length_count[sorted(length_count.keys())[0]]["pws"]
            longest_passwords = length_count[sorted(length_count.keys())[-1]]["pws"]

            if len(shortest_passwords) > 1:
                results.append(
                    "%s%sShortest Passwords"
                    % (nd.join(list(set(shortest_passwords[:3]))), td)
                )
            else:
                results.append("%s%sShortest Password" % (shortest_passwords[0], td))

            if len(longest_passwords) > 1:
                results.append(
                    "%s%sLongest Passwords"
                    % (nd.join(list(set(longest_passwords[:3]))), td)
                )
            else:
                results.append("%s%sLongest Password" % (longest_passwords[0], td))

            months = [
                "January",
                "February",
                "March",
                "April",
                "May",
                "June",
                "July",
                "August",
                "September",
                "October",
                "November",
                "December",
            ]
            seasons = ["Winter", "Spring", "Summer", "Fall"]
            years = [
                str(y)
                for y in range(
                    datetime.datetime.now().year, datetime.datetime.now().year - 15, -1
                )
            ]

            results.append(
                "%s%sPasswords Containing a Season"
                % (self.search_term(seasons, pw_count), td)
            )
            results.append(
                "%s%sPasswords Containing a Month"
                % (self.search_term(months, pw_count), td)
            )
            results.append(
                "%s%sPasswords Containing a Year"
                % (self.search_term(years, pw_count), td)
            )

            if args.keywords:
                keywords = [k.strip() for k in args.keywords.split(",")]
                for k in keywords:
                    results.append(
                        '%s%s Passwords Containing "%s"'
                        % (self.search_term(k, pw_count), td, k)
                    )

            results.append("")
            results.append("\t\tPassword Length Statistics")
            results.append("Password Length%sCount" % td)

            for l in sorted(length_count.keys()):
                results.append("%s%s%s" % (l, td, length_count[l]["count"]))

            count_totals = []

            for k in pw_count.keys():
                count_totals.append([pw_count[k]["count"], k])

            top20 = sorted(count_totals)[::-1][:20]

            results.append("")
            results.append("\t\tTop %s Passwords" % len(top20))
            results.append("Password%sCount" % td)

            for t in top20:
                results.append(
                    "%s%s%s" % (t[1].replace("\n", "").replace("\r", ""), td, t[0])
                )

        self.process_output(results, args)

    def search_term(self, txt, pw_count):
        pws = pw_count.keys()
        if type(txt) == str:
            txt = [txt]
        total_matches = 0
        for t in txt:
            matches = [r[0] for r in process.extract(t, pws, limit=None) if r[1] > 75]

            total_matches += sum([pw_count[p]["count"] for p in matches])

        return total_matches
