"""
Tests for the findings webapp, focused on the URL evidence tied to each
VulnOutput row (``Url.vuln_output``).

The sample dataset already links one URL — ``http://www.example.com/login`` on
the fixture's HTTP port — to the fixture vulnerability's output row, so most of
these assert against ``self.data.url``.
"""

from armory2.armory_main.included.TestTemplate import WebappTest
from armory2.armory_main.models import Url, VulnOutput


class Tests(WebappTest):

    def test_index_reports_the_linked_url_total(self):
        response = self.assertRenders("")
        self.assertEqual(response.context["total_urls"], 1)

    def test_result_row_counts_the_urls(self):
        response = self.post("finding_data")
        row = self._row_for(response, self.data.vuln.id)
        self.assertEqual(row["url_count"], 1)
        self.assertEqual(response.context["url_total"], 1)

    def test_url_filter_matches_a_substring(self):
        response = self.post("finding_data", {"url": "/login"})
        self.assertEqual(response.context["total"], 1)

        response = self.post("finding_data", {"url": "/nothing-here"})
        self.assertEqual(response.context["total"], 0)

    def test_has_urls_filter_excludes_findings_without_any(self):
        self.data.url.delete()
        response = self.post("finding_data", {"has_urls": "on"})
        self.assertEqual(response.context["total"], 0)

        response = self.post("finding_data")
        self.assertEqual(response.context["total"], 1)

    def test_search_output_also_matches_url_text(self):
        response = self.post("finding_data", {"search": "/login"})
        self.assertEqual(response.context["total"], 0)

        response = self.post(
            "finding_data", {"search": "/login", "search_output": "on"}
        )
        self.assertEqual(response.context["total"], 1)

    def test_a_second_url_does_not_duplicate_the_finding(self):
        """The urls join is multi-valued; distinct() has to absorb it."""
        Url.objects.create(
            name="http://www.example.com/admin",
            method="post",
            port=self.data.http,
            vuln_output=self.data.vuln_output,
        )
        response = self.post("finding_data", {"url": "http://"})
        self.assertEqual(response.context["total"], 1)
        self.assertEqual(self._row_for(response, self.data.vuln.id)["url_count"], 2)

    def test_detail_lists_the_urls_on_the_affected_instance(self):
        response = self.assertRenders("detail/%d" % self.data.vuln.id)
        self.assertEqual(response.context["url_count"], 1)
        instance = self._instance_for(response, self.data.http.id)
        self.assertEqual([u.name for u in instance["urls"]], [self.data.url.name])
        self.assertContains(response, self.data.url.name)

    def test_detail_leaves_other_instances_empty(self):
        response = self.assertRenders("detail/%d" % self.data.vuln.id)
        self.assertEqual(self._instance_for(response, self.data.https.id)["urls"], [])

    def test_orphan_output_keeps_its_urls(self):
        """An output row whose port left the vuln still shows its evidence."""
        self.data.vuln.ports.remove(self.data.http)
        response = self.assertRenders("detail/%d" % self.data.vuln.id)
        orphans = response.context["orphan_outputs"]
        self.assertEqual(len(orphans), 1)
        self.assertEqual([u.name for u in orphans[0]["urls"]], [self.data.url.name])
        self.assertEqual(response.context["url_count"], 1)

    def test_raw_output_page_lists_the_urls(self):
        response = self.assertRenders("output/%d" % self.data.vuln_output.id)
        self.assertEqual([u.name for u in response.context["urls"]], [self.data.url.name])
        self.assertContains(response, self.data.url.name)

    def test_output_with_no_urls_renders_clean(self):
        output = VulnOutput.objects.create(
            port=self.data.https, vulnerability=self.data.vuln, data="no urls here"
        )
        response = self.assertRenders("output/%d" % output.id)
        self.assertEqual(list(response.context["urls"]), [])

    def test_sorting_by_url_count_is_accepted(self):
        response = self.post("finding_data", {"sort": "urls_desc"})
        self.assertEqual(response.context["total"], 1)

    # -- helpers ---------------------------------------------------------

    def _row_for(self, response, vuln_id):
        for row in response.context["rows"]:
            if row["obj"].id == vuln_id:
                return row
        self.fail("vuln %s not in the result rows" % vuln_id)

    def _instance_for(self, response, port_id):
        for instance in response.context["instances"]:
            if instance["port"].id == port_id:
                return instance
        self.fail("port %s not in the affected instances" % port_id)
