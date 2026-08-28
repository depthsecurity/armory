"""
Tests for the host_scoping webapp -- and the reference example for how a
webapp declares its own.

A webapp's tests live in ``tests.py`` beside its ``config.json``, in a class
named ``Tests``. ``armory -t host_scoping`` runs these alongside the built-in
checks (config.json is valid, urls.py loads, every parameterless page comes
back without a 500).

Available out of the box:

  self.client                a Django test client with an authenticated
                             session, so ARMORY_WEB_USERNAME/PASSWORD does not
                             have to be unset to run tests
  self.get(path) / .post()   relative to this webapp's URL prefix
  self.assertRenders(path)   GET and assert the status code
  self.config                the parsed config.json
  self.data                  the sample database rows
"""

from armory2.armory_main.included.TestTemplate import WebappTest


class Tests(WebappTest):

    def test_index_lists_the_cidrs(self):
        response = self.assertRenders("")
        self.assertIn(self.data.cidr.id, response.context["cidr_ids"])

    def test_cidr_fragment_renders(self):
        response = self.assertRenders("get_cidr/%d" % self.data.cidr.id)
        self.assertContains(response, self.data.cidr.name)

    def test_missing_cidr_is_a_404(self):
        self.assertRenders("get_cidr/999999", status=404)

    def test_toggling_active_scope_persists(self):
        ip = self.data.host_b
        ip.active_scope = False
        ip.save()

        self.assertRenders("change_scope/ip/active/%d" % ip.id)
        ip.refresh_from_db()
        self.assertTrue(ip.active_scope)

        self.assertRenders("change_scope/ip/active/%d" % ip.id)
        ip.refresh_from_db()
        self.assertFalse(ip.active_scope)

    def test_cloud_toggle_flips_the_flag(self):
        ip = self.data.host
        self.assertFalse(ip.cloud)
        self.assertRenders("toggle_cloud/%d" % ip.id)
        ip.refresh_from_db()
        self.assertTrue(ip.cloud)
