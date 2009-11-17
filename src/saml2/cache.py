#!/usr/bin/env python

import shelve
import time

# The assumption is that any subject may consist of data 
# gathered from several different sources, all with their own
# timeout time.

class To_old(Exception):
    pass
    
class Cache(object):
    def __init__(self, filename=None):
        if filename:
            self._db = shelve.open(filename, writeback=True)
            self._sync = True
        else:
            self._db = {}
            self._sync = False
        
    def get_all( self, subject_id, issuers=[] ):
        if not issuers:
            try:
                issuers = self._db[subject_id].keys()
            except KeyError:
                return ({},[])
            
        res = {}
        oldees = []
        for issuer in issuers:
            try:
                ava = self.get(subject_id, issuer)
            except To_old:
                oldees.append(issuer)
                continue
            for key, vals in ava.items():            
                try:
                    tmp = set(res[key]).union(set(vals))
                    res[key] = list(tmp)
                except KeyError:
                    res[key] = vals
        return (res, oldees)
        
    def get( self, subject_id, issuer ):
        (not_on_or_after, ava) = self._db[subject_id][issuer]
        now = time.gmtime()
        if not_on_or_after < now:
            self.reset(subject_id, issuer)
            raise To_old()
        else:
            return ava
    
    def set( self, subject_id, issuer, ava, not_on_or_after):
        if subject_id not in self._db:
            self.reset(subject_id)

        self._db[subject_id][issuer] = (not_on_or_after, ava)
        if self._sync:
            self._db.sync()
            
    def reset(self, subject_id, issuer=None):
        if issuer:
            self.set(subject_id, issuer, {}, 0)
        else:
            self._db[subject_id] = {}
            if self._sync:
                self._db.sync()
            
    def issuers(self, subject_id):
        return self._db[subject_id].keys()
        
    def active(self, subject_id, issuer):
        try:
            (not_on_or_after, _) = self._db[subject_id][issuer]
        except KeyError:
            return False
        now = time.gmtime()
        if not_on_or_after < now:
            return False
        else:
            return True
        
    def subjects(self):
        return self._db.keys()
