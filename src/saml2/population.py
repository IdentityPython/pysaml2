
from saml2.cache import Cache

class Population(object):
    def __init__(self, cache=None):
        if cache:
            if isinstance(cache, basestring):
                self.cache = Cache(cache)
            else:
                self.cache = cache
        else:
            self.cache = Cache()

    def add_information_about_person(self, session_info):
        """If there already are information from this source in the cache 
        this function will overwrite that information"""
        
        subject_id = session_info["name_id"]
        issuer = session_info["issuer"]
        del session_info["issuer"]
        self.cache.set(subject_id, issuer, session_info, 
                        session_info["not_on_or_after"])
        return subject_id
    
    def stale_sources_for_person(self, subject_id, sources=None):
        if not sources: # assume that all the members has be asked
                        # once before, hence they are represented in the cache
            sources = self.cache.entities(subject_id)
        sources = [m for m in sources \
                        if not self.cache.active(subject_id, m)]
        return sources                       
        
    def issuers_of_info(self, subject_id):
        return self.cache.entities(subject_id)

    def get_identity(self, subject_id, entities=None, check_not_on_or_after=True):
        return self.cache.get_identity(subject_id, entities, check_not_on_or_after)

    def get_info_from(self, subject_id, entity_id):
        return self.cache.get(subject_id, entity_id)
        
    def subjects(self):
        """Returns the name id's for all the persons in the cache"""
        return self.cache.subjects()

    def remove_person(self, subject_id):
        self.cache.delete(subject_id)
        
    def get_entityid(self, subject_id, source_id, check_not_on_or_after=True):
        try:
            return self.cache.get(subject_id, source_id,
                                  check_not_on_or_after)["name_id"]
        except (KeyError, ValueError):
            return ""
            
    def sources(self, subject_id):
        return self.cache.entities(subject_id)
