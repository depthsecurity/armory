from sqlalchemy import create_engine, Column, String, DateTime, MetaData, types, Boolean
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_mixins import ActiveRecordMixin, ReprMixin
from sqlalchemy.ext.mutable import MutableDict
from datetime import datetime
import json
import pdb

def create_database(connect_str, init_db=True):
    return Database(connect_str, init_db)


Base = declarative_base()


class JSONEncodedDict(types.TypeDecorator):
    
    impl = types.UnicodeText(length=2**31)

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value


JsonType = MutableDict.as_mutable(JSONEncodedDict)

Base.metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)


class BaseModel(Base, ActiveRecordMixin, ReprMixin):
    __abstract__ = True
    __repr__ = ReprMixin.__repr__
    source_tool = Column(String(64), unique=False)
    created_date = Column(DateTime, default=datetime.now)
    modified_date = Column(DateTime, onupdate=datetime.now)
    meta = Column(JsonType)
    in_scope = Column(Boolean(create_constraint=False), default=False)
    passive_scope = Column(Boolean(create_constraint=False), default=False)

    def set_tool(self, tool):
        meta = self.meta
        if meta:
            if meta.get(tool, False):
                if not meta[tool].get("created", False):
                    meta[tool]["created"] = str(datetime.now())
            else:
                meta[tool] = {"created": str(datetime.now())}
        else:
            meta = {tool: {"created": str(datetime.now())}}
            self.meta = meta
            self.save()


class Database(object):
    def __init__(self, connect_str, init_db=True):
        from .models import Models

        self.engine = create_engine(connect_str, convert_unicode=True)
        self.db_session = scoped_session(
            sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        )
        self.BaseModel = BaseModel()
        Base.query = self.db_session.query_property()
        self.models = Models
        self.Base = Base
        if init_db:
            self.init_db()

    def init_db(self):
        # import all modules here that might define models so that
        # they will be registered properly on the metadata.  Otherwise
        # you will have to import them first before calling init_db()
        Base.metadata.create_all(bind=self.engine)
        self.BaseModel.set_session(self.db_session)
