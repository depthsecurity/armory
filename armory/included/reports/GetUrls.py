from armory.included.utilities import get_urls
from armory.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This report displays all of the hosts sorted by service.
    """

    markdown = ["", "# ", "- "]

    name = "GetUrls"

    def __init__(self, db):
        self.db = db

    def run(self, args):
        res = []
        self.process_output(get_urls.run(self.db), args)
