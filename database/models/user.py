from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship


class User(BaseModel):
    __tablename__ = "user"
    __repr_attrs__ = ["email"]
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    first_name = Column(String, unique=False)
    last_name = Column(String, unique=False)
    user_name = Column(String, unique=False)
    domain_id = Column(Integer, ForeignKey("basedomain.id"))
    creds = relationship("Cred", backref="user")
    job_title = Column(String, unique=False)
    location = Column(String, unique=False)
