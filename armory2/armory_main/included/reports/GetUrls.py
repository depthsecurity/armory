from armory2.armory_main.included.utilities import get_urls
from armory2.armory_main.included.ReportTemplate import ReportTemplate


class Report(ReportTemplate):
    """
    This report displays all of the hosts sorted by service.
    """

    markdown = ["", "# ", "- "]

    name = "GetUrls"


    def run(self, args):
        
        if args.scope not in ['active', 'passive']:
            args.scope = None


        self.process_output(get_urls.run(scope_type=args.scope), args)
