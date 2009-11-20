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
        
    def get_identity(self, subject_id, entities=[]):
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
                return ({},[])
            
        res = {}
        oldees = []
        for entity_id in entities:
            try:
                info = self.get(subject_id, entity_id)
            except To_old:
                oldees.append(entity_id)
                continue
            for key, vals in info["ava"].items():            
                try:
                    tmp = set(res[key]).union(set(vals))
                    res[key] = list(tmp)
                except KeyError:
                    res[key] = vals
        return (res, oldees)
        
    def get(self, subject_id, entity_id):
        """ Get seesion information about a the session when an 
        assertion was received from an IdP or an AA or sent to a SP.
        
        :param subject_id: The identifier of the subject
        :param entity_id: The identifier of the entity_id
        :return: The session information
        """
        (not_on_or_after, info) = self._db[subject_id][entity_id]
        now = time.gmtime()
        if not_on_or_after < now:
            self.reset(subject_id, entity_id)
            raise To_old()
        else:
            return info
    
    def set( self, subject_id, entity_id, info, not_on_or_after=0):
        """ Stores session information in the cache
        
        :param subject_id: The subjects identifier
        :param entity_id: The identifier of the entity_id/receiver of an assertion
        :param info: The session info, the assertion is part of this
        :param not_on_or_after: A time after which the assertion is not valid.
        """
        if subject_id not in self._db:
            self.reset(subject_id)

        self._db[subject_id][entity_id] = (not_on_or_after, info)
        if self._sync:
            self._db.sync()
            
    def reset(self, subject_id, entity_id=None):
        """ Scrap the assertions received from a IdP or an AA.
        
        :param subject_id: The subjects identifier
        :param entity_id: The identifier of the entity_id of the assertion
        :return:
        """
        if entity_id:
            self.set(subject_id, entity_id, {}, 0)
        else:
            self._db[subject_id] = {}
            if self._sync:
                self._db.sync()
            
    def entities(self, subject_id):
        """ Returns all the entities of assertions for a subject, disregarding
        whether the assertion still is valid or not.
        
        :param subject_id: The identifier of the subject
        :return: A possibly empty list of entity identifiers
        """
        return self._db[subject_id].keys()
        
    def receivers(self, subject_id):
        return entities(subject_id)
        
    def active(self, subject_id, entity_id):
        """ Returns the status of assertions from a specific entity_id.
        
        :param subject_id: The ID of the subject
        :param entity_id: The entity ID of the entity_id of the assertion
        :return: True or False depending on if the assertion is still
            valid or not.
        """
        try:
            (not_on_or_after, _) = self._db[subject_id][entity_id]
        except KeyError:
            return False
        now = time.gmtime()
        if not_on_or_after < now:
            return False
        else:
            return True
        
    def subjects(self):
        """ Return identifiers for all the subjects that are in the cache.
        
        :return: list of subject identifiers
        """
        return self._db.keys()
