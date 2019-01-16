import dns.resolver


def run(domain):
    ips = []
    try:
        answers = dns.resolver.query(domain, "A")
        for a in answers:
            ips.append(a.address)
        return ips
    except:
        return []
