from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database import JsonType

class Service(BaseModel):
    __tablename__ = 'service'
    __repr_attrs__ = ['name']
    id = Column(Integer, primary_key=True)
    name = Column(String)
    ip_address_id = Column(Integer, ForeignKey('ipaddress.id'))
    port_id = Column(Integer, ForeignKey('port.id'))
    cert = Column(String)
    info = Column(JsonType)
    
