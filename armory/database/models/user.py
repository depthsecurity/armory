from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship


class User(BaseModel):
    __tablename__ = "user"
    __repr_attrs__ = ["email"]
    id = Column(Integer, primary_key=True)
    email = Column(String(128), unique=True)
    first_name = Column(String(128), unique=False)
    last_name = Column(String(128), unique=False)
    user_name = Column(String(128), unique=False)
    domain_id = Column(Integer, ForeignKey("basedomain.id"))
    creds = relationship("Cred", backref="user")
    job_title = Column(String(512), unique=False)
    location = Column(String(128), unique=False)

    def __repr__(self):
        return "User: {} {}".format(self.first_name, self.last_name)