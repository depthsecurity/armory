from .. import BaseModel
from sqlalchemy import Column, Integer, String, ForeignKey


class Cred(BaseModel):
    __tablename__ = "cred"
    __repr_attrs__ = ["password"]
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user.id"))
    password = Column(String(64), unique=False)
    passhash = Column(String(128), unique=False)
    source = Column(String(128), unique=False)

    def __repr__(self):
        return "Cred: {} ({}): {}".format(self.user_id, self.source, self.password)

        