#!/usr/bin/python
from armory.database.repositories import PortRepository
from ..ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This report displays all of the certificates
    from https boxes.
    """

    markdown = ["###", "`"]

    name = "CertReport"

    def __init__(self, db):
        self.Port = PortRepository(db)

    def set_options(self):
        super(Report, self).set_options()
        self.options.add_argument("-t", "--tool", help="Source tool")

    def run(self, args):

        results = []
        services = self.Port.all(service_name="https")
        certs = {}
        for s in services:

            if (
                (args.scope == "passive" and s.ip_address.passive_scope)
                or (args.scope == "active" and s.ip_address.in_scope)  # noqa: W503
                or (args.scope == "all")  # noqa: W503
            ):
                if s.cert:

                    cert = s.cert.split("-----")[0]
                    # pdb.set_trace()
                    if not certs.get(cert, False):
                        certs[cert] = []
                    if s.ip_address.domains:
                        certs[cert].append(
                            s.ip_address.domains[0].domain + ":" + str(s.port_number)
                        )
                    else:
                        certs[cert].append(
                            s.ip_address.ip_address + ":" + str(s.port_number)
                        )

        for k in certs.keys():
            results.append(", ".join(sorted(list(set(certs[k])))))
            for l in k.split("\n"):
                results.append("\t" + l)

        self.process_output(results, args)
