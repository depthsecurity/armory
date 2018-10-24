import whois
from tld import get_tld


def run(domains):
    whois_domains = {}
    if type(domains) == str:
        domains = [domains]

    for domain in domains:
        tld = get_tld("blah://%s" % domain)

        if whois_domains.get(tld, False):
            whois_domains[tld]["subdomains"].append(domain.lower())
        else:
            whois_domains[tld] = {"subdomains": [domain.lower()]}

    return whois_domains
