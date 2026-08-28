#!/usr/bin/python
from armory2.armory_main.included.ReportTemplate import ReportTemplate
from armory2.armory_main.included.TestTemplate import ReportTest
from armory2.armory_main.models import IPAddress


class Report(ReportTemplate):
    """
    Minimal example report: every host, with its open ports.
    """

    name = "SampleReport"

    markdown = ["###", "`"]

    def set_options(self):
        super(Report, self).set_options()
        self.options.add_argument(
            "--open_only", help="Only list ports marked open", action="store_true"
        )

    def run(self, args):
        results = []

        for ip in IPAddress.get_set(scope_type=args.scope).order_by("ip_address"):
            results.append(ip.ip_address)
            ports = ip.port_set.all()
            if args.open_only:
                ports = ports.filter(status="open")
            for port in ports:
                results.append(
                    "\t%s/%s\t%s" % (port.proto, port.port_number, port.service_name)
                )

        self.process_output(results, args)


class Tests(ReportTest):
    """
    Example of the tests a report can carry. `armory -t SampleReport` runs
    these alongside the built-in smoke checks.

    Available out of the box:

      self.report              a fresh Report() with set_options() applied and
                               silent_run on, so nothing hits the terminal
      self.run_report(*argv)   run it, return what it produced
      self.run_report_json()   run it with -j, return the parsed JSON
      self.data                the sample database rows
    """

    def test_lists_every_host(self):
        output = self.run_report()
        self.assertIn("192.0.2.10", output)
        self.assertIn("192.0.2.11", output)

    def test_ports_are_indented_under_their_host(self):
        output = self.run_report()
        self.assertIn("\ttcp/80\thttp", output)

    def test_scope_filter_is_honoured(self):
        self.data.host_b.active_scope = False
        self.data.host_b.save()
        output = self.run_report("--scope", "active")
        self.assertNotIn("192.0.2.11", output)

    def test_json_round_trips(self):
        self.assertIn("192.0.2.10", self.run_report_json())

    def test_open_only_drops_filtered_ports(self):
        self.data.ssh.status = "filtered"
        self.data.ssh.save()
        self.assertNotIn("tcp/22", self.run_report("--open_only"))
