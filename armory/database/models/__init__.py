from .domain import Domain
from .ipaddress import IPAddress
from .basedomain import BaseDomain
from .cidr import CIDR
from .user import User
from .cred import Cred
from .vulnerability import Vulnerability
from .port import Port
from .url import Url
from .scopecidr import ScopeCIDR
from .cve import CVE


class Models(object):
    def __init__(self):
        for m in [
            Domain,
            IPAddress,
            CIDR,
            BaseDomain,
            User,
            Cred,
            Vulnerability,
            Port,
            Url,
            ScopeCIDR,
            CVE,
        ]:
            setattr(self, m.__name__, m)


Models = Models()
