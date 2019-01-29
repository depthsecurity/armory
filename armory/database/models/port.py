from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import relationship
from .. import JsonType


class Port(BaseModel):
    __tablename__ = "port"
    __repr_attrs__ = ["port_number"]
    id = Column(Integer, primary_key=True)
    port_number = Column(Integer, unique=False)
    proto = Column(String(32), unique=False)
    status = Column(String(32), unique=False)
    service_name = Column(String(32), unique=False)
    ip_address_id = Column(Integer, ForeignKey("ipaddress.id"))
    urls = relationship("Url", backref="port")
    cert = Column(Text)
    info = Column(JsonType)

    def __repr__(self):
        return "Port: {}/{}/{} - {}".format(self.proto, self.port_number, self.service_name, self.status)