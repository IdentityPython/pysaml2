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
from saml2 import md
from saml2 import samlp, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.time_util import str_to_time
from saml2.sigver import make_temp, cert_from_key_info
    
class MetaData(object):
    """ A class to manage metadata information """
    
    def __init__(self):
        self._loc_key = {}
        self._loc_bind = {}
        self.idp = {}
        self.aad = {}
        self.vo = {}
        self.sp = {}
        self.valid_to = None
        self.cache_until = None
        
    def _vo_metadata(self, entity_descriptor):
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
            self.vo[entity_descriptor.entity_id] = members
    
    def _sp_metadata(self, entity_descriptor):
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
            for sso in tssd.single_sign_on_service:
                self._loc_key[sso.location] = certs
                
        if ssds != []:            
            self.sp[entity_descriptor.entity_id] = ssds
    
    def _idp_metadata(self, entity_descriptor):
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
                
        if idps != []:            
            self.idp[entity_descriptor.entity_id] = idps
    
    def _aad_metadata(self,entity_descriptor):
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
            self.aad[entity_descriptor.entity_id] = aads
            
    def import_metadata(self, xml_str):
        """ Import information; organization distinguish name, location and
        certificates from a metadata file.
    
        :param xml_str: The metadata as a XML string.
        :return: Dictionary with location as keys and 2-tuples of organization
            distinguised names and certs as values.
        """

        now = time.gmtime()
        
        entities_descriptor = md.entities_descriptor_from_string(xml_str)

        try:
            valid_until = str_to_time(entities_descriptor.valid_until)
        except AttributeError:
            valid_until = None
            
        for entity_descriptor in entities_descriptor.entity_descriptor:
            self._idp_metadata(entity_descriptor)
            self._aad_metadata(entity_descriptor)
            self._vo_metadata(entity_descriptor)

                    
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
            idps = self.idp[entity_id]
        except KeyError:
            return []
        loc = []
        for idp in idps:
            for sso in idp.single_sign_on_service:
                if binding == sso.binding:
                    loc.append(sso.location)
        return loc
        
    def attribute_services(self, entity_id):
        try:
            return self.aad[entity_id]
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
        return self._loc_key[loc]
    
    def vo_members(self, entity_id):
        try:
            return self.vo[entity_id]
        except KeyError:
            return []
        
def make_vals(val, klass, klass_inst=None, prop=None, part=False):
    """
    Creates a class instance with a specified value, the specified
    class instance are a value on a property in a defined class instance.
    
    :param klass_inst: The class instance which has a property on which 
        what this function returns is a value.
    :param val: The value
    :param prop: The property which the value should be assigned to.
    :param klass: The value class
    :param part: If the value is one of a possible list of values it should be
        handled slightly different compared to if it isn't.
    :return: Value class instance
    """
    ci = None
    #print "_make_val: %s %s (%s)" % (prop,val,klass)
    if isinstance(val, bool):
        ci = klass(text="%s" % val)
    elif isinstance(val, int):
        ci = klass(text="%d" % val)
    elif isinstance(val, basestring):
        ci = klass(text=val)
    elif val == None:
        ci = klass()
    elif isinstance(val, dict):
        ci = make_instance(klass, val)
    elif not part:
        cis = [make_vals(sval, klass, klass_inst, prop, True) for sval in val]
        setattr(klass_inst, prop, cis)
    else:
        raise ValueError("strange instance type: %s on %s" % (type(val),val))
        
    if part:
        return ci
    else:        
        if ci:
            cis = [ci]
        setattr(klass_inst, prop, cis)
    
def make_instance(klass, spec):
    """
    Constructs a class instance containing the specified information
    
    :param klass: The class
    :param spec: Information to be placed in the instance
    :return: The instance
    """
    klass_inst = klass()
    for prop in klass.c_attributes.values():
        if prop in spec:
            if isinstance(spec[prop],bool):
                setattr(klass_inst,prop,"%s" % spec[prop])
            elif isinstance(spec[prop], int):
                setattr(klass_inst,prop,"%d" % spec[prop])
            else:
                setattr(klass_inst,prop,spec[prop])
    if "text" in spec:
        setattr(klass_inst,"text",spec["text"])
        
    for prop, klass in klass.c_children.values():
        if prop in spec:
            if isinstance(klass, list): # means there can be a list of values
                make_vals(spec[prop], klass[0], klass_inst, prop)
            else:
                ci = make_vals(spec[prop], klass, klass_inst, prop, True)
                setattr(klass_inst, prop, ci)
    return klass_inst
