import requests
import sys

from armory2.armory_main.included.utilities.color_display import (
    display,
    display_error,
    display_warning,
    display_new,
)

def process_urls(data):

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
        res = requests.get(u, timeout=int(timeout), verify=False)

        for k in res.headers.keys():
            if k not in blacklist:
                if not new_headers.get(u, False):
                    new_headers[u] = []

                new_headers[u].append("%s: %s" % (k, res.headers[k]))
        new_cookies[u] = dict(res.cookies)

    except KeyboardInterrupt:
        display_warning("Got Ctrl+C, exiting")
        sys.exit(1)
    except Exception as e:
        display_error("%s no good, skipping: %s" % (u, e))
    return (new_headers, new_cookies)