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
    if type(data[0]) == list:
        u, virtualhost = data[0]
    else:
        u = data[0]
        virtualhost = None
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
    data = {"virtualhost": virtualhost, "url": u, "headers": [], "cookies": {}}

    if virtualhost:
        display(f"Processing {u} ({virtualhost})")
    else:
        display("Processing %s" % u)
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:10.0) Gecko/20100101 Firefox/89.0"
        }
        if virtualhost:
            headers["Host"] = virtualhost
        res = requests.get(u, timeout=int(timeout), verify=False, headers=headers)
        res.raise_for_status()
        for k in res.headers.keys():
            if k not in blacklist:
                data["headers"].append("{}: {}".format(k, res.headers[k]))
            data["cookies"] = dict(res.cookies)
    except requests.exceptions.HTTPError as http_error:
        display_error("Http Error: {}".format(http_error))
    except requests.exceptions.ConnectionError as connect_error:
        display_error("Error Connecting: {}".format(connect_error))
    except KeyboardInterrupt:
        display_warning("Got Ctrl+C, exiting")
        sys.exit(1)
    except Exception as e:
        display_error("{} no good, skipping: {}".format(u, e))
    return data
