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

import base64
import time
from tempfile import NamedTemporaryFile
from saml2 import md, BINDING_HTTP_POST
from saml2 import samlp, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.time_util import str_to_time
from saml2.sigver import make_temp, cert_from_key_info, verify_signature
import httplib2
try:
    from hashlib import md5
except ImportError:
    from md5 import md5
        
class MetaData(object):
    """ A class to manage metadata information """
    
    def __init__(self, xmlsec_binary=None, log=None):
        self._loc_key = {}
        self._loc_bind = {}
        self.entity = {}
        self.valid_to = None
        self.cache_until = None
        self.log = log
        self.xmlsec_binary = xmlsec_binary
        self.http = httplib2.Http()

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
            
            certs = [make_temp(c, suffix=".der") for c in certs]
            for acs in tssd.assertion_consumer_service:
                self._loc_key[acs.location] = certs
                
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
            
    def import_metadata(self, xml_str):
        """ Import information; organization distinguish name, location and
        certificates from a metadata file.
    
        :param xml_str: The metadata as a XML string.
        """

        now = time.gmtime()
        
        entities_descriptor = md.entities_descriptor_from_string(xml_str)

        try:
            valid_until = str_to_time(entities_descriptor.valid_until)
        except AttributeError:
            valid_until = None
            
        for entity_descriptor in entities_descriptor.entity_descriptor:
            entity = self.entity[entity_descriptor.entity_id] = {}
            self._idp_metadata(entity_descriptor, entity, "idp_sso")
            self._sp_metadata(entity_descriptor, entity, "sp_sso")
            self._aad_metadata(entity_descriptor, entity, 
                                "attribute_authority")
            self._vo_metadata(entity_descriptor, entity, "affiliation")
            try:
                entity["organization"] = entity_descriptor.organization
            except:
                pass
            try:
                entity["contact"] = entity_descriptor.contact
            except:
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
            if verify_signature(self.xmlsec_binary, content, cert, "pem",
                    "%s:%s" % (md.EntitiesDescriptor.c_namespace,
                            md.EntitiesDescriptor.c_tag)):
                self.import_metadata(content)
                return True
        else:
            print "Response status", response.status
        return False


    def single_sign_on_services(self, entity_id, 
                                binding = BINDING_HTTP_REDIRECT):
        """ Get me all single-sign-on services that supports the specified
        binding version.
        
        :param entity_id: The EntityId
        :param binding: A binding identifier
        :return: list of single-sign-on service location run by the entity 
            with the specified EntityId.
        """
        try:
            idps = self.entity[entity_id]["idp_sso"]
        except KeyError:
            return []
        loc = []
        #print idps
        for idp in idps:
            #print "==",idp.keyswv()
            for sso in idp.single_sign_on_service:
                #print "SSO",sso
                if binding == sso.binding:
                    loc.append(sso.location)
        return loc
        
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
    
    def vo_members(self, entity_id):
        try:
            return self.entity[entity_id]["affiliation"]
        except KeyError:
            return []
        
    def consumer_url(self, entity_id, binding=BINDING_HTTP_POST, log=None):
        try:
            ssos = self.entity[entity_id]["sp_sso"]
        except KeyError:
            log and log.info("%s" % (self.sp.keys(),))
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
        
    def name(self, entityid):
        """ Find a name from the metadata about this entity id.
        The name is either the display name, the name or the url
        ,in that order, for the organization.
        
        :param entityid: The Entity ID
        :return: A name 
        """
        try:
            org = self.entity[entityid]["organization"]
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

    def requests(self, entityid):
        try:
            ssos = self.entity[entity_id]["sp_sso"]
        except KeyError:
            ([],[])
            
        try:
            requested = ssos["attribute_consuming_service"][
                                                    "requested_attribute"]
        except KeyError:
            ([],[])
            
        required = []
        optional = []
        for attr in requested:
            if "is_required" in attr and attr["is_required"] == "true":
                required.append(attr)
            else:
                optional.append(attr)
    
        return (required, optional)
        