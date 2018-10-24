from .. import BaseModel
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from database import JsonType


class BaseDomain(BaseModel):
    __tablename__ = "basedomain"
    # __repr_attrs__ = ['domain']
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True)
    subdomains = relationship("Domain", backref="base_domain")
    users = relationship("User", backref="domain")
    dns = Column(JsonType, unique=False)
