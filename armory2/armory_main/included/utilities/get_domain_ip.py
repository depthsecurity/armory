import dns.resolver
import socket

def run(domain):
    ips = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 5.0

    try:
        answers = resolver.query(domain, "A")
        for a in answers:
            ips.append(a.address)
        return ips
    except Exception:
        # print("Regular DNS Not Resolved\n")
    # Temporarily disabling - seems to cause massive delays at times.

    #     pass
    # try:
    #    ips = [ str(i[4][0]) for i in socket.getaddrinfo(domain, 443) ] 
    #    return ips
    # except Exception:
    #    print("Unable to Resolve\n")
       return ips
