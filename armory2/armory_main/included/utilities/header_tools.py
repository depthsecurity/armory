import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys

from armory2.armory_main.included.utilities.color_display import (
    display,
    display_error,
    display_warning,
    display_new,
)

def process_urls(data):
    # silence insecure url warnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    u = data[0]
    timeout = data[1]
    blacklist = [
        "Date",
        "Connection",
        "Content-Type",
        "Content-Length",
        "Keep-Alive",
        "Content-Encoding",
        "Vary",
    ]
    new_headers = {}
    new_cookies = {}

    display("Processing %s" % u)
    try:
        res = requests.get(u, timeout=int(timeout), verify=False, headers={"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:10.0) Gecko/20100101 Firefox/89.0"})
        res.raise_for_status()
        for k in res.headers.keys():
            if k not in blacklist:
                if not new_headers.get(u, False):
                    new_headers[u] = []
                new_headers[u].append("{}: {}".format(k, res.headers[k]))
            new_cookies[u] = dict(res.cookies)
    except requests.exceptions.HTTPError as http_error:
        display_error("Http Error: {}".format(http_error))
    except requests.exceptions.ConnectionError as connect_error:
        display_error("Error Connecting: {}".format(connect_error))
    except KeyboardInterrupt:
        display_warning("Got Ctrl+C, exiting")
        sys.exit(1)
    except Exception as e:
        display_error("{} no good, skipping: {}".format(u, e))
    return (new_headers, new_cookies)
