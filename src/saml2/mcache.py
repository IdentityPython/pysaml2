#!/usr/bin/env python

import memcache
import time
from saml2 import time_util

# The assumption is that any subject may consist of data 
# gathered from several different sources, all with their own
# timeout time.

class ToOld(Exception):
    pass

def _key(prefix, name):
    return "%s_%s" % (prefix, name)
    
def _valid(not_on_or_after):
    if isinstance(not_on_or_after, time.struct_time):
        not_on_or_after = time.mktime(not_on_or_after)
    now = time_util.daylight_corrected_now()

    if not_on_or_after and not_on_or_after < now:
        #self.reset(subject_id, entity_id)
        raise ToOld("%s < %s" % (not_on_or_after, now))
    else:
        return True
        
class Cache(object):
    def __init__(self, servers, debug=0):
        self._cache = memcache.Client(servers, debug)
        
    def delete(self, subject_id):
        entities = self.entities(subject_id)
        if entities:
            for entity_id in entities:
                self._cache.delete(_key(subject_id, entity_id))
    
        self._cache.delete(subject_id)
        subjects = self._cache.get("subjects")
        if subjects and subject_id in subjects:
            subjects.remove(subject_id)
            self._cache.set("subjects", subjects)
        
    def get_identity(self, subject_id, entities=None):
        """ Get all the identity information that has been received and 
        are still valid about the subject.
        
        :param subject_id: The identifier of the subject
        :param entities: The identifiers of the entities whoes assertions are
            interesting. If the list is empty all entities are interesting.
        :return: A 2-tuple consisting of the identity information (a
            dictionary of attributes and values) and the list of entities 
            whoes information has timed out.
        """
        if not entities:
            entities = self.entities(subject_id)
            if not entities:
                return ({}, [])
            
        res = {}
        oldees = []
        for (entity_id, item) in self._cache.get_multi(entities, 
                                                    subject_id+'_').items():
            try:
                info = self.get_info(item)
            except ToOld:
                oldees.append(entity_id)
                continue
            for key, vals in info["ava"].items():            
                try:
                    tmp = set(res[key]).union(set(vals))
                    res[key] = list(tmp)
                except KeyError:
                    res[key] = vals
        return (res, oldees)

    def get_info(self, item):
        """ Get session information about a subject gotten from a
        specified IdP/AA.

        :param item: Information stored
        :return: The session information as a dictionary
        """
        try:
            (not_on_or_after, info) = item
        except ValueError:
            raise ToOld()
            
        if _valid(not_on_or_after):
            return info
        else:
            raise ToOld()

    def get(self, subject_id, entity_id):
        res = self._cache.get(_key(subject_id, entity_id))
        if not res:
            return {}
        else:
            return self.get_info(res)
        
    def set(self, subject_id, entity_id, info, not_on_or_after=0):
        """ Stores session information in the cache. Assumes that the subject_id
        is unique within the context of the Service Provider.
        
        :param subject_id: The subject identifier
        :param entity_id: The identifier of the entity_id/receiver of an 
            assertion
        :param info: The session info, the assertion is part of this
        :param not_on_or_after: A time after which the assertion is not valid.
        """
        entities = self._cache.get(subject_id)
        if not entities:
            entities = []
            subjects = self._cache.get("subjects")
            if not subjects:
                subjects = []
            if subject_id not in subjects:
                subjects.append(subject_id)
                self._cache.set("subjects", subjects)
        
        if entity_id not in entities:
            entities.append(entity_id)
            self._cache.set(subject_id, entities)
          
        # Should use memcache's expire
        self._cache.set(_key(subject_id, entity_id), (not_on_or_after, info))
            
    def reset(self, subject_id, entity_id):
        """ Scrap the assertions received from a IdP or an AA about a special
        subject.
        
        :param subject_id: The subjects identifier
        :param entity_id: The identifier of the entity_id of the assertion
        :return:
        """
        self._cache.set(_key(subject_id, entity_id), {}, 0)
            
    def entities(self, subject_id):
        """ Returns all the entities of assertions for a subject, disregarding
        whether the assertion still is valid or not.
        
        :param subject_id: The identifier of the subject
        :return: A possibly empty list of entity identifiers
        """
        res = self._cache.get(subject_id)
        if not res:
            raise KeyError("No such subject")
        else:
            return res
        
    def receivers(self, subject_id):
        """ Another name for entities() just to make it more logic in the IdP 
            scenario """
        return self.entities(subject_id)
        
    def active(self, subject_id, entity_id):
        """ Returns the status of assertions from a specific entity_id.
        
        :param subject_id: The ID of the subject
        :param entity_id: The entity ID of the entity_id of the assertion
        :return: True or False depending on if the assertion is still
            valid or not.
        """
        try:
            (not_on_or_after, _) = self._cache.get(_key(subject_id, entity_id))
        except ValueError:
            return False
            
        try:
            return _valid(not_on_or_after)
        except ToOld:
            return False
        
    def subjects(self):
        """ Return identifiers for all the subjects that are in the cache.
        
        :return: list of subject identifiers
        """
        return self._cache.get("subjects")

    def update(self, subject_id, entity_id, ava):
        res = self._cache.get(_key(subject_id, entity_id))
        if res == None:
            raise KeyError("No such subject")
        else:
            info = self.get_info(res)
            if info:
                info.update(ava)
                self.set(subject_id, entity_id, info, res[0])
                
    def valid_to(self, subject_id, entity_id, newtime):
        try:
            (not_on_or_after, info) = self._cache.get(_key(subject_id, entity_id))
        except ValueError:
            return False
            
        self._cache.set(_key(subject_id, entity_id), (newtime, info))
