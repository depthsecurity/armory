from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship


class Cred(BaseModel):
    __tablename__ = "cred"
    __repr_attrs__ = ["password"]
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user.id"))
    password = Column(String, unique=False)
    passhash = Column(String, unique=False)
    source = Column(String, unique=False)
