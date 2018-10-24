from .. import BaseModel, Base
from sqlalchemy import Column, ForeignKey, Table, Integer, String
from sqlalchemy.orm import relationship


domain_ip_table = Table(
    "domain_ip_table",
    Base.metadata,
    Column("domain_id", Integer, ForeignKey("domain.id")),
    Column("ip_id", Integer, ForeignKey("ipaddress.id")),
)


class Domain(BaseModel):
    __tablename__ = "domain"
    __repr_attrs__ = ["domain"]
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True)
    ip_addresses = relationship(
        "IPAddress", secondary=domain_ip_table, backref="domains"
    )
    base_domain_id = Column(Integer, ForeignKey("basedomain.id"))
    whois = Column(String, unique=False)

    # base_domain = relationship("BaseDomain", back_populates="subdomains")
