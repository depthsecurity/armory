from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship


class Url(BaseModel):
    __tablename__ = "url"
    __repr_attrs__ = ["path"]
    id = Column(Integer, primary_key=True)

    path = Column(String, unique=False)
    method = Column(String, unique=False)
    status_code = Column(Integer, unique=False)
    port_id = Column(Integer, ForeignKey("port.id"))
