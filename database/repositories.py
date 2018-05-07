#!/usr/bin/env python
from .models import Models
import datetime
import pdb
from netaddr import IPNetwork, IPAddress
import tldextract

class BaseRepository(object):
    model = None
    def __init__(self, db, toolname=None):
        self.db = db
        self.toolname = toolname

    def find(self, **kwargs):
        '''
        This function can be used to find an object, but won't create one.
        '''
        obj = self.db.db_session.query(self.model).filter_by(**kwargs).one_or_none()

        return obj

    def find_or_create(self, only_tool=False,**kwargs):
        '''
        This function can be used to look for one object. If it doesn't
        exist, it'll be created. The 'only_tool' parameter will only
        return newly created if the object has never been touched by
        that tool before.
        '''

        created = False
        
        obj = self.db.db_session.query(self.model).filter_by(**kwargs).one_or_none()
        

        if only_tool:
            if obj is None:
                created = True
                obj = self.model.create(**kwargs)
                meta = {self.toolname:{'created':str(datetime.datetime.now())}}
                obj.meta=meta
                obj.save()
            else:
                # pdb.set_trace()
                meta = obj.meta
                if meta:
                    if meta.get(self.toolname, False):
                        if meta[self.toolname].get('created', False):
                            created = False
                        else:
                            meta[self.toolname]['created'] = str(datetime.datetime.now())
                            created = True
                    else:
                        meta[self.toolname] = {'created':str(datetime.datetime.now())}
                        created = True
                else:
                    meta = {self.toolname:{'created':str(datetime.datetime.now())}}
                    created = True
                        
                               
                # pdb.set_trace()
                obj.meta=meta
                obj.save()
            return (created, obj)
        else:
            if obj is None:
                created = True
                try:
                    obj = self.model.create(**kwargs)
                except:
                    pdb.set_trace()
                meta = {self.toolname:{'created':str(datetime.datetime.now())}}
                obj.meta=meta
                obj.save()
            else:
                meta = obj.meta
                if meta:
                    if meta.get(self.toolname, False):
                        if meta[self.toolname].get('created', False):
                            created = False
                        else:
                            meta[self.toolname]['created'] = str(datetime.datetime.now())
                            created = False
                    else:
                        meta[self.toolname] = {'created':str(datetime.datetime.now())}
                        created = False
                else:
                    meta = {self.toolname:{'created':str(datetime.datetime.now())}}
                    created = False
                
                    obj.meta=meta
                    obj.save()
            return (created, obj)

    def all(self, tool=False, in_scope=True, **kwargs):
        # obj = self.db.db_session.query(self.model).all()
        obj = self.db.db_session.query(self.model).filter_by(in_scope=in_scope, **kwargs).all()
        if not tool:
            
            return obj
        
        else:
            objects = []
            for o in obj:
                if o.meta and o.meta.get(tool, False) and o.meta[tool].get('created', False):
                    pass
                else:
                    objects.append(o)

            return objects

                
            
    def commit(self):
        return self.db.db_session.commit()

class DomainRepository(BaseRepository):
    model = Models.Domain
    def find_or_create(self, only_tool=False, force_in_scope=False, **kwargs):

        created, d = super(DomainRepository, self).find_or_create(only_tool, **kwargs)
        if created:
            base_domain = '.'.join([t for t in tldextract.extract(d.domain)[1:] if t])
            BaseDomains = BaseDomainRepository(self.db, "")
            created, bd = BaseDomains.find_or_create(only_tool, force_in_scope, domain=base_domain)
            
            d.base_domain = bd

            if force_in_scope:
                d.in_scope = True
                d.update()
            else:
                
                d.in_scope = bd.in_scope

                d.update()

        return created, d

class IPRepository(BaseRepository):
    model = Models.IPAddress
    def find_or_create(self, only_tool=False, force_in_scope=False, **kwargs):

        created, ip = super(IPRepository, self).find_or_create(only_tool, **kwargs)
        if created:
            if force_in_scope:
                ip.in_scope = True
                ip.update()
            else:
                ScopeCidrs = ScopeCIDRRepository(self.db, "")
                addr = IPAddress(ip.ip_address)
                ip.in_scope = False

                cidrs = ScopeCidrs.all(in_scope=True)
                for c in cidrs:
                    if addr in IPNetwork(c.cidr):
                        ip.in_scope = True
                ip.update()

        return created, ip

class CIDRRepository(BaseRepository):
    model = Models.CIDR

class BaseDomainRepository(BaseRepository):
    model = Models.BaseDomain


    def find_or_create(self, only_tool=False, force_in_scope=False, **kwargs):

        created, bd = super(BaseDomainRepository, self).find_or_create(only_tool, **kwargs)
        if created:
            
            if force_in_scope:
                bd.in_scope = True
                bd.update()
            else:
                
                bd.in_scope = False
                bd.update()

        return created, bd

class UserRepository(BaseRepository):
    model = Models.User

class CredRepository(BaseRepository):
    model = Models.Cred

class VulnRepository(BaseRepository):
    model = Models.Vulnerability

class PortRepository(BaseRepository):
    model = Models.Port

class UrlRepository(BaseRepository):
    model = Models.Url

class ScopeCIDRRepository(BaseRepository):
    model = Models.ScopeCIDR

class CVERepository(BaseRepository):
    model = Models.CVE