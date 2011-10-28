#!/usr/bin/env python

import shelve
from saml2 import time_util

# The assumption is that any subject may consist of data 
# gathered from several different sources, all with their own
# timeout time.

class ToOld(Exception):
    pass

class CacheError(Exception):
    pass

class Cache(object):
    def __init__(self, filename=None):
        if filename:
            self._db = shelve.open(filename, writeback=True)
            self._sync = True
        else:
            self._db = {}
            self._sync = False
        
    def delete(self, subject_id):
        del self._db[subject_id]

        if self._sync:
            self._db.sync()
        
    def get_identity(self, subject_id, entities=None,
                     check_not_on_or_after=True):
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
            try:
                entities = self._db[subject_id].keys()
            except KeyError:
                return {}, []
            
        res = {}
        oldees = []
        for entity_id in entities:
            try:
                info = self.get(subject_id, entity_id, check_not_on_or_after)
            except ToOld:
                oldees.append(entity_id)
                continue

            if not info:
                oldees.append(entity_id)
                continue
                
            for key, vals in info["ava"].items():            
                try:
                    tmp = set(res[key]).union(set(vals))
                    res[key] = list(tmp)
                except KeyError:
                    res[key] = vals
        return res, oldees
        
    def get(self, subject_id, entity_id, check_not_on_or_after=True):
        """ Get session information about a subject gotten from a
        specified IdP/AA.
        
        :param subject_id: The identifier of the subject
        :param entity_id: The identifier of the entity_id
        :param check_not_on_or_after: if True it will check if this
             subject is still valid or if it is too old. Otherwise it
             will not check this. True by default.
        :return: The session information
        """
        (timestamp, info) = self._db[subject_id][entity_id]
        if check_not_on_or_after and time_util.after(timestamp):
            raise ToOld("past %s" % timestamp)

        return info or None
    
    def set(self, subject_id, entity_id, info, not_on_or_after=0):
        """ Stores session information in the cache. Assumes that the subject_id
        is unique within the context of the Service Provider.
        
        :param subject_id: The subject identifier
        :param entity_id: The identifier of the entity_id/receiver of an 
            assertion
        :param info: The session info, the assertion is part of this
        :param not_on_or_after: A time after which the assertion is not valid.
        """
        if subject_id not in self._db:
            self._db[subject_id] = {}

        self._db[subject_id][entity_id] = (not_on_or_after, info)
        if self._sync:
            self._db.sync()
            
    def reset(self, subject_id, entity_id):
        """ Scrap the assertions received from a IdP or an AA about a special
        subject.
        
        :param subject_id: The subjects identifier
        :param entity_id: The identifier of the entity_id of the assertion
        :return:
        """
        self.set(subject_id, entity_id, {}, 0)
            
    def entities(self, subject_id):
        """ Returns all the entities of assertions for a subject, disregarding
        whether the assertion still is valid or not.
        
        :param subject_id: The identifier of the subject
        :return: A possibly empty list of entity identifiers
        """
        return self._db[subject_id].keys()
        
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
            (timestamp, info) = self._db[subject_id][entity_id]
        except KeyError:
            return False

        if not info:
            return False
        else:
            return time_util.not_on_or_after(timestamp)
        
    def subjects(self):
        """ Return identifiers for all the subjects that are in the cache.
        
        :return: list of subject identifiers
        """
        return self._db.keys()
