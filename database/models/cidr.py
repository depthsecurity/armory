from .. import BaseModel
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship


class CIDR(BaseModel):
    __tablename__ = "cidr"
    __repr_attrs__ = ["cidr", "org_name"]
    id = Column(Integer, primary_key=True)
    cidr = Column(String, unique=True)
    org_name = Column(String, unique=False)
    ip_addresses = relationship("IPAddress", backref="cidr")
