from .. import BaseModel, Base
from sqlalchemy import Column, Integer, String, ForeignKey, Table, Float
from sqlalchemy.orm import relationship

cve_vulnerability_table = Table(
    "cve_vulnerability_table",
    Base.metadata,
    Column("vulnerability_id", Integer, ForeignKey("vulnerability.id")),
    Column("cve_id", Integer, ForeignKey("cve.id")),
)


class CVE(BaseModel):
    __tablename__ = "cve"
    __repr_attrs__ = ["name"]
    id = Column(Integer, primary_key=True)
    name = Column(String(128))
    vulnerabilities = relationship(
        "Vulnerability", secondary=cve_vulnerability_table, backref="cves"
    )

    temporal_score = Column(Float)
    description = Column(String(256))

    def __repr__(self):
        return "CVE: {}".format(self.name)