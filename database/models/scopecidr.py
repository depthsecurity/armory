from .. import BaseModel
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship


class ScopeCIDR(BaseModel):
    __tablename__ = "scopecidr"
    __repr_attrs__ = ["cidr", "org_name"]
    id = Column(Integer, primary_key=True)
    cidr = Column(String, unique=True)
    org_name = Column(String, unique=False)
