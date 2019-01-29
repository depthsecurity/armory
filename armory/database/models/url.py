from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey


class Url(BaseModel):
    __tablename__ = "url"
    __repr_attrs__ = ["path"]
    id = Column(Integer, primary_key=True)

    path = Column(String(128), unique=False)
    method = Column(String(16), unique=False)
    status_code = Column(Integer, unique=False)
    port_id = Column(Integer, ForeignKey("port.id"))

    def __repr__(self):
        return "URL: {}".format(self.path)