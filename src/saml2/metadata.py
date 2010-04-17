#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2009 Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Contains classes and functions to alleviate the handling of SAML metadata
"""

import httplib2
import sys
from decorator import decorator

from saml2 import md, BINDING_HTTP_POST
from saml2 import samlp, BINDING_HTTP_REDIRECT, BINDING_SOAP
#from saml2.time_util import str_to_time
from saml2.sigver import make_temp, cert_from_key_info, verify_signature
from saml2.sigver import pem_format
from saml2.time_util import valid
from saml2.attribute_converter import ava_fro

@decorator
def keep_updated(func, self, entity_id, *args, **kwargs):
    #print "In keep_updated"
    try:
        if not valid(self.entity[entity_id]["valid_until"]):
            self.reload_entity(entity_id)
    except KeyError:
        pass
    
    return func(self, entity_id, *args, **kwargs)

class MetaData(object):
    """ A class to manage metadata information """
    
    def __init__(self, xmlsec_binary=None, attrconv=None, log=None):
        self.log = log
        self.xmlsec_binary = xmlsec_binary
        self.attrconv = attrconv or []
        self._loc_key = {}
        self._loc_bind = {}
        self.entity = {}
        self.valid_to = None
        self.cache_until = None
        self.http = httplib2.Http()
        self._import = {}
        self._wants = {}
    
    def _vo_metadata(self, entity_descriptor, entity, tag):
        """
        Pick out the Affiliation descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descriptor: A EntityDescriptor instance
        """
        try:
            afd = entity_descriptor.affiliation_descriptor
        except AttributeError:
            return
        
        members = []
        for tafd in afd: # should really never be more than one
            members.extend(
                [member.text.strip() for member in tafd.affiliate_member])
        
        if members != []:
            entity[tag] = members
    
    def _sp_metadata(self, entity_descriptor, entity, tag):
        """
        Pick out the SP SSO descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descriptor: A EntityDescriptor instance
        """
        try:
            ssd = entity_descriptor.sp_sso_descriptor
        except AttributeError:
            return
        
        ssds = []
        required = []
        optional = []
        #print "..... %s ..... " % entity_descriptor.entity_id
        for tssd in ssd:
            # Only want to talk to SAML 2.0 entities
            if samlp.NAMESPACE not in \
                    tssd.protocol_support_enumeration.split(" "):
                #print "<<<", idp.protocol_support_enumeration
                continue
            
            ssds.append(tssd)
            certs = []
            for key_desc in tssd.key_descriptor:
                certs.extend(cert_from_key_info(key_desc.key_info))
            
            certs = [make_temp(pem_format(c), ".pem", False) for c in certs]
            
            for acs in tssd.attribute_consuming_service:
                for attr in acs.requested_attribute:
                    print "==", attr
                    if attr.is_required == "true":
                        required.append(attr)
                    else:
                        optional.append(attr)
            
            for acs in tssd.assertion_consumer_service:
                self._loc_key[acs.location] = certs
        
        if required or optional:
            #print "REQ",required
            #print "OPT",optional
            self._wants[entity_descriptor.entity_id] = (ava_fro(self.attrconv,
                                                                required),
                                                        ava_fro(self.attrconv,
                                                                optional))
        
        if ssds:
            entity[tag] = ssds
    
    def _idp_metadata(self, entity_descriptor, entity, tag):
        """
        Pick out the IdP SSO descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descriptor: A EntityDescriptor instance
        """
        try:
            isd = entity_descriptor.idp_sso_descriptor
        except AttributeError:
            return
        
        idps = []
        for tidp in isd:
            if samlp.NAMESPACE not in \
                    tidp.protocol_support_enumeration.split(" "):
                #print "<<<", idp.protocol_support_enumeration
                continue
            
            idps.append(tidp)
            certs = []
            for key_desc in tidp.key_descriptor:
                certs.extend(cert_from_key_info(key_desc.key_info))
            
            certs = [make_temp(c, suffix=".der") for c in certs]
            for sso in tidp.single_sign_on_service:
                self._loc_key[sso.location] = certs
        
        if idps:
            entity[tag] = idps
    
    def _aad_metadata(self, entity_descriptor, entity, tag):
        """
        Pick out the attribute authority descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descriptor: A EntityDescriptor instance
        """
        try:
            attr_auth_descr = entity_descriptor.attribute_authority_descriptor
        except AttributeError:
            #print "No Attribute AD: %s" % entity_descriptor.entity_id
            return
        
        aads = []
        for taad in attr_auth_descr:
            # Remove everyone that doesn't talk SAML 2.0
            #print "supported protocols", taad.protocol_support_enumeration
            if samlp.NAMESPACE not in \
                    taad.protocol_support_enumeration.split(" "):
                continue
            
            # remove the bindings I can't handle
            aserv = []
            for attr_serv in taad.attribute_service:
                #print "binding", attr_serv.binding
                if attr_serv.binding == BINDING_SOAP:
                    aserv.append(attr_serv)
            
            if aserv == []:
                continue
            
            taad.attribute_service = aserv
            
            # gather all the certs and place them in temporary files
            certs = []
            for key_desc in taad.key_descriptor:
                certs.extend(cert_from_key_info(key_desc.key_info))
            
            certs = [make_temp(c, suffix=".der") for c in certs]
            for sso in taad.attribute_service:
                try:
                    self._loc_key[sso.location].append(certs)
                except KeyError:
                    self._loc_key[sso.location] = certs
            
            aads.append(taad)
        
        if aads != []:
            entity[tag] = aads
    
    def clear_from_source(self, source):
        for eid in self._import[source]:
            del self.entity[eid]
    
    def reload_entity(self, entity_id):
        for source, eids in self._import.items():
            if entity_id in eids:
                if source == "-":
                    return
                self.clear_from_source(source)
                if isinstance(source, basestring):
                    fil = open(source)
                    self.import_metadata( fil.read(), source)
                    fil.close()
                else:
                    self.import_external_metadata(source[0], source[1])
    
    def import_metadata(self, xml_str, source):
        """ Import information; organization distinguish name, location and
        certificates from a metadata file.
        
        :param xml_str: The metadata as a XML string.
        """
        
        # now = time.gmtime()
        
        entities_descriptor = md.entities_descriptor_from_string(xml_str)
        
        try:
            valid(entities_descriptor.valid_until)
        except AttributeError:
            pass
        
        for entity_descriptor in entities_descriptor.entity_descriptor:
            try:
                if not valid(entity_descriptor.valid_until):
                    if self.log:
                        self.log.info(
                            "Entity descriptor (entity id:%s) to old" % \
                            entity_descriptor.entity_id)
                    else:
                        print >> sys.stderr, \
                            "Entity descriptor (entity id:%s) to old" % \
                            entity_descriptor.entity_id
                    continue
            except AttributeError:
                pass
            
            try:
                self._import[source].append(entity_descriptor.entity_id)
            except KeyError:
                self._import[source] = [entity_descriptor.entity_id]
            
            entity = self.entity[entity_descriptor.entity_id] = {}
            entity["valid_until"] = entities_descriptor.valid_until
            self._idp_metadata(entity_descriptor, entity, "idp_sso")
            self._sp_metadata(entity_descriptor, entity, "sp_sso")
            self._aad_metadata(entity_descriptor, entity,
                                "attribute_authority")
            self._vo_metadata(entity_descriptor, entity, "affiliation")
            try:
                entity["organization"] = entity_descriptor.organization
            except AttributeError:
                pass
            try:
                entity["contact"] = entity_descriptor.contact
            except AttributeError:
                pass
    
    def import_external_metadata(self, url, cert=None):
        """ Imports metadata by the use of HTTP GET.
        If the fingerprint is known the file will be checked for
        compliance before it is imported.
        
        :param url: The URL pointing to the metadata
        :param hexdigest: A 40 character long hexdigest
        :return: True if the import worked out, otherwise False
        """
        (response, content) = self.http.request(url, "GET")
        if response.status == 200:
            if verify_signature(content, self.xmlsec_binary, cert, "pem",
                    "%s:%s" % (md.EntitiesDescriptor.c_namespace,
                            md.EntitiesDescriptor.c_tag)):
                self.import_metadata(content, (url, cert))
                return True
        else:
            self.log and self.log.info("Response status: %s" % response.status)
        return False

    
    @keep_updated
    def single_sign_on_services(self, entity_id,
                                binding = BINDING_HTTP_REDIRECT):
        """ Get me all single-sign-on services that supports the specified
        binding version.
        
        :param entity_id: The EntityId
        :param binding: A binding identifier
        :return: list of single-sign-on service location run by the entity
            with the specified EntityId.
        """
        
        # May raise KeyError
        idps = self.entity[entity_id]["idp_sso"]
        
        loc = []
        #print idps
        for idp in idps:
            #print "==",idp.keyswv()
            for sso in idp.single_sign_on_service:
                #print "SSO",sso
                if binding == sso.binding:
                    loc.append(sso.location)
        return loc
    
    @keep_updated
    def attribute_services(self, entity_id):
        try:
            return self.entity[entity_id]["attribute_authority"]
        except KeyError:
            return []
    
    def locations(self):
        """ Returns all the locations that are know using this metadata file.
        
        :return: A list of IdP locations
        """
        return self._loc_key.keys()
    
    def certs(self, loc):
        """ Get all certificates that are used by a IdP at the specified
        location. There can be more than one because of overlapping lifetimes
        of the certs.
        
        :param loc: The location of the IdP
        :return: a list of 2-tuples (file pointer,file name) that represents
            certificates used by the IdP at the location loc.
        """
        try:
            return self._loc_key[loc]
        except KeyError:
            return []
    
    @keep_updated
    def vo_members(self, entity_id):
        try:
            return self.entity[entity_id]["affiliation"]
        except KeyError:
            return []
    
    @keep_updated
    def consumer_url(self, entity_id, binding=BINDING_HTTP_POST, _log=None):
        try:
            ssos = self.entity[entity_id]["sp_sso"]
        except KeyError:
            raise
        
        # any default ?
        for sso in ssos:
            for acs in sso.assertion_consumer_service:
                if acs.binding == binding:
                    if acs.is_default:
                        return acs.location
            # No default, grab the first in the sequence
            for acs in sso.assertion_consumer_service:
                if acs.binding == binding:
                    return acs.location
        
        return None
    
    @keep_updated
    def name(self, entity_id):
        """ Find a name from the metadata about this entity id.
        The name is either the display name, the name or the url
        ,in that order, for the organization.
        
        :param entityid: The Entity ID
        :return: A name
        """
        try:
            org = self.entity[entity_id]["organization"]
            try:
                names = org.organization_display_name
            except KeyError:
                try:
                    names = org.organization_name
                except KeyError:
                    try:
                        names = org.organization_url
                    except KeyError:
                        names = None
            if names:
                name = names[0].text
        except KeyError:
            name = ""
        
        return name
    
    @keep_updated
    def wants(self, entity_id):
        try:
            return self._wants[entity_id]
        except KeyError:
            return ([], [])
    
    @keep_updated
    def attribute_consumer(self, entity_id):
        try:
            ssos = self.entity[entity_id]["sp_sso"]
        except KeyError:
            return ([], [])
        
        required = []
        optional = []
        # What if there is more than one ? Can't be ?
        for acs in ssos[0].attribute_consuming_service:
            for attr in acs.requested_attribute:
                if attr.is_required == "true":
                    required.append(attr)
                else:
                    optional.append(attr)
        
        return (required, optional)
    
    def _orgname(self, org, lang="en"):
        if not org:
            return ""
        for spec in [lang, None]:
            for name in org.organization_display_name:
                if name.lang == spec:
                    return name.text.strip()
            for name in org.organization_name:
                if name.lang == spec:
                    return name.text.strip()
            for name in org.organization_url:
                if name.lang == spec:
                    return name.text.strip()
        return ""
    
    def _location(self, idpsso):
        loc = []
        for idp in idpsso:
            for sso in idp.single_sign_on_service:
                loc.append(sso.location)
        
        return loc
    
    # @keep_updated
    # def _valid(self, entity_id):
    #     return True
    
    def idps(self):
        idps = {}
        for entity_id, edict in self.entity.items():
            if "idp_sso" in edict:
#idp_aa_check                self._valid(entity_id)
                if "organization" in edict:
                    name = self._orgname(edict["organization"],"en")
                if not name:
                    name = self._location(edict["idp_sso"])[0]
                idps[entity_id] = (name, edict["idp_sso"])
        return idps