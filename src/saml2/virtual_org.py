from saml2.attribute_resolver import AttributeResolver

class VirtualOrg(object):
    def __init__(self, metadata, vo_org, population, log=None, vorg_conf=None):
        self.metadata = metadata
        self.log = log
        self.vorg_conf = vorg_conf
        self.vorg = vo_org
        self.population = population
        
    def members_to_ask(self, subject_id):
        # Find the member of the Virtual Organization that I haven't 
        # alrady spoken too 
        vo_members = [
            member for member in self.metadata.vo_members(self.vorg)\
                if member not in self.srv["idp"].keys()]
            
        self.log and self.log.info("VO members: %s" % vo_members)

        # Remove the ones I have cached data from about this subject
        vo_members = [m for m in vo_members \
                        if not self.cache.active(subject_id, m)]                        
        self.log and self.log.info(
                        "VO members (not cached): %s" % vo_members)
        return vo_members
        
    def do_aggregation(self, subject_id):
        if self.log:
            self.log.info("** Do VO aggregation **")
            self.log.info("SubjectID: %s, VO:%s" % (subject_id, self.vorg))
        
        vo_members = self.members_to_ask(subject_id)
        
        if vo_members:
            # Find the NameIDFormat and the SPNameQualifier
            if self.vorg_conf and "name_id_format" in self.vorg_conf:
                name_id_format = self.vorg_conf["name_id_format"]
                sp_name_qualifier = ""
            else:
                sp_name_qualifier = self.vorg
                name_id_format = ""
            
            resolver = AttributeResolver(environ, self.metadata, self.conf)
            # extends returns a list of session_infos      
            for session_info in resolver.extend(subject_id, 
                                    self.conf["entityid"], vo_members, 
                                    name_id_format=name_id_format,
                                    sp_name_qualifier=sp_name_qualifier, 
                                    log=self.log):
                _ignore = self._cache_session(session_info)

            if self.log:
                self.log.info(
                    ">Issuers: %s" % self.population.issuers_of_info(subject_id))
                self.log.info(
                    "AVA: %s" % (self.population.get_identity(subject_id),))
            
            return True
        else:
            return False