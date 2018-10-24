from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from database import JsonType


class Port(BaseModel):
    __tablename__ = "port"
    __repr_attrs__ = ["port_number"]
    id = Column(Integer, primary_key=True)
    port_number = Column(Integer, unique=False)
    proto = Column(String, unique=False)
    status = Column(String, unique=False)
    service_name = Column(String, unique=False)
    ip_address_id = Column(Integer, ForeignKey("ipaddress.id"))
    urls = relationship("Url", backref="port")
    cert = Column(String)
    info = Column(JsonType)
