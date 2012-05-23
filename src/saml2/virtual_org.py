from saml2.attribute_resolver import AttributeResolver

class VirtualOrg(object):
    def __init__(self, sp, vorg, log=None):
        self.sp = sp # The parent SP client instance 
        self.config = sp.config
        self.vorg_name = vorg
        if log is None:
            self.log = self.sp.logger
        else:
            self.log = log
        self.vorg_conf = self.config.vo_conf(self.vorg_name)
        
    def _cache_session(self, session_info):
        return True
        
    def _affiliation_members(self):
        """
        Get the member of the Virtual Organization from the metadata, 
        more specifically from AffiliationDescriptor.
        """
        return self.config.metadata.vo_members(self.vorg_name)
    
    def _vo_conf_members(self):
        """
        Get the member of the Virtual Organization from the configuration. 
        """
        
        try:
            return self.vorg_conf["member"]
        except (KeyError, TypeError):
            return []
        
    def members_to_ask(self, subject_id):
        """Find the member of the Virtual Organization that I haven't already 
        spoken too 
        """

        vo_members = self._affiliation_members()
        for member in self._vo_conf_members():
            if member not in vo_members:
                vo_members.append(member)

        # Remove the ones I have cached data from about this subject
        vo_members = [m for m in vo_members if not self.sp.users.cache.active(
                                                                subject_id, m)]
        if self.log:
            self.log.info("VO members (not cached): %s" % vo_members)
        return vo_members
    
    def get_common_identifier(self, subject_id):
        (ava, _) = self.sp.users.get_identity(subject_id)
        if ava == {}:
            return None
            
        ident = self.vorg_conf["common_identifier"]

        try:
            return ava[ident][0]
        except KeyError:
            return None
        
    def do_aggregation(self, subject_id, log=None):
        if log is None:
            log = self.log
            
        if log:
            log.info("** Do VO aggregation **")
            log.info("SubjectID: %s, VO:%s" % (subject_id, self.vorg_name))
        
        to_ask = self.members_to_ask(subject_id)
        if to_ask:
            # Find the NameIDFormat and the SPNameQualifier
            if self.vorg_conf and "nameid_format" in self.vorg_conf:
                name_id_format = self.vorg_conf["nameid_format"]
                sp_name_qualifier = ""
            else:
                sp_name_qualifier = self.vorg_name
                name_id_format = ""
            
            com_identifier = self.get_common_identifier(subject_id)
                
            resolver = AttributeResolver(saml2client=self.sp)
            # extends returns a list of session_infos      
            for session_info in resolver.extend(com_identifier,
                                        self.sp.config.entityid, 
                                        to_ask, 
                                        name_id_format=name_id_format,
                                        sp_name_qualifier=sp_name_qualifier,
                                        log=log, real_id=subject_id):
                _ = self._cache_session(session_info)

            if log:
                log.info(
                    ">Issuers: %s" % self.sp.users.issuers_of_info(subject_id))
                log.info(
                    "AVA: %s" % (self.sp.users.get_identity(subject_id),))
            
            return True
        else:
            return False