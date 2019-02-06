from .. import BaseModel
from sqlalchemy import Column, Integer, String


class ScopeCIDR(BaseModel):
    __tablename__ = "scopecidr"
    __repr_attrs__ = ["cidr", "org_name"]
    id = Column(Integer, primary_key=True)
    cidr = Column(String(18), unique=True)
    org_name = Column(String(32), unique=False)

    def __repr__(self):
        return "Scoped CIDR: {}".format(self.cidr)