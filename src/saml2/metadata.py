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
import xmldsig as ds

from saml2 import md, samlp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP, class_name
from saml2.s_utils import factory
from saml2.saml import NAME_FORMAT_URI
from saml2.time_util import in_a_while
from saml2.time_util import valid
from saml2.attribute_converter import from_local_name, ac_factory
from saml2.attribute_converter import ava_fro, AttributeConverter
from saml2.sigver import pre_signature_part
from saml2.sigver import make_temp, cert_from_key_info, verify_signature
from saml2.sigver import pem_format

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
    
    def _vo_metadata(self, entity_descr, entity, tag):
        """
        Pick out the Affiliation descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descriptor: A EntityDescriptor instance
        """

        afd = entity_descr.affiliation_descriptor
    
        if afd:
            members = [member.text.strip() for member in afd.affiliate_member]
        
            if members != []:
                entity[tag] = members
    
    def _sp_metadata(self, entity_descr, entity, tag):
        """
        Pick out the SP SSO descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descr: A EntityDescriptor instance
        """
        try:
            ssd = entity_descr.spsso_descriptor
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
                    #print "==", attr
                    if attr.is_required == "true":
                        required.append(attr)
                    else:
                        optional.append(attr)
            
            for acs in tssd.assertion_consumer_service:
                self._loc_key[acs.location] = certs
        
        if required or optional:
            #print "REQ",required
            #print "OPT",optional
            self._wants[entity_descr.entity_id] = (ava_fro(self.attrconv,
                                                                required),
                                                        ava_fro(self.attrconv,
                                                                optional))
        
        if ssds:
            entity[tag] = ssds
    
    def _idp_metadata(self, entity_descr, entity, tag):
        """
        Pick out the IdP SSO descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descr: A EntityDescriptor instance
        """
        try:
            isd = entity_descr.idpsso_descriptor
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
    
    def _aad_metadata(self, entity_descr, entity, tag):
        """
        Pick out the attribute authority descriptors from an entity
        descriptor and store the information in a way which is easily
        accessible.
        
        :param entity_descr: A EntityDescriptor instance
        """
        try:
            attr_auth_descr = entity_descr.attribute_authority_descriptor
        except AttributeError:
            #print "No Attribute AD: %s" % entity_descr.entity_id
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
        """ Remove all the metadata references I have gotten from this source
        
        :param source: The matadata source
        """
        
        for eid in self._import[source]:
            del self.entity[eid]
    
    def reload_entity(self, entity_id):
        """ Reload metadata about an entity_id, means reload the whole
        metadata file that this entity_id belonged to.
        
        :param entity_id: The Entity ID
        """
        for source, eids in self._import.items():
            if entity_id in eids:
                if source == "-":
                    return
                
                self.clear_from_source(source)
                
                if isinstance(source, basestring):
                    fil = open(source)
                    self.import_metadata(fil.read(), source)
                    fil.close()
                else:
                    self.import_external_metadata(source[0], source[1])
    
    def import_metadata(self, xml_str, source):
        """ Import information; organization distinguish name, location and
        certificates from a metadata file.
        
        :param xml_str: The metadata as a XML string.
        :param source: A name by which this source should be known, has to be
            unique within this session.
        """
        
        # now = time.gmtime()
        
        entities_descr = md.entities_descriptor_from_string(xml_str)
        
        try:
            valid(entities_descr.valid_until)
        except AttributeError:
            pass
        
        for entity_descr in entities_descr.entity_descriptor:
            try:
                if not valid(entity_descr.valid_until):
                    if self.log:
                        self.log.info(
                            "Entity descriptor (entity id:%s) to old" % \
                            entity_descr.entity_id)
                    else:
                        print >> sys.stderr, \
                            "Entity descriptor (entity id:%s) to old" % \
                            entity_descr.entity_id
                    continue
            except AttributeError:
                pass
            
            try:
                self._import[source].append(entity_descr.entity_id)
            except KeyError:
                self._import[source] = [entity_descr.entity_id]
            
            # have I seen this entity_id before ? If so log and ignore it
            if entity_descr.entity_id in self.entity:
                print >> sys.stderr, \
                    "Duplicated Entity descriptor (entity id:%s)" % \
                    entity_descr.entity_id
                continue
                
            entity = self.entity[entity_descr.entity_id] = {}
            entity["valid_until"] = entities_descr.valid_until
            self._idp_metadata(entity_descr, entity, "idp_sso")
            self._sp_metadata(entity_descr, entity, "sp_sso")
            self._aad_metadata(entity_descr, entity,
                                "attribute_authority")
            self._vo_metadata(entity_descr, entity, "affiliation")
            try:
                entity["organization"] = entity_descr.organization
            except AttributeError:
                pass
            try:
                entity["contact_person"] = entity_descr.contact_person
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
                name = org.organization_display_name[0]
            except IndexError:
                try: 
                    name = org.organization_name[0]
                except IndexError:
                    try:
                        name = org.organization_url[0]
                    except IndexError:
                        pass
            
            if name:
                name = name.text
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
        

DEFAULTS = {
    "want_assertions_signed": "true",
    "authn_requests_signed": "false",
    "want_authn_requests_signed": "true",
}

ORG_ATTR_TRANSL = {
    "organization_name": ("name", md.OrganizationName),
    "organization_display_name": ("display_name", md.OrganizationDisplayName),
    "organization_url": ("url", md.OrganizationURL)
}

def _localized_name(val, klass):
    try:
        (text, lang) = val
        return klass(text=text, lang=lang)
    except ValueError:
        return klass(text=val)

def do_organization_info(conf):
    """ decription of an organization in the configuration is
    a dictionary of keys and values, where the values might be tuples.

    "organization": {
        "name": ("AB Exempel", "se"),
        "display_name": ("AB Exempel", "se"),
        "url": "http://www.example.org"
    }
    """
    try:
        corg = conf["organization"]
        org = md.Organization()
        for dkey, (ckey, klass) in ORG_ATTR_TRANSL.items():
            if ckey not in corg:
                continue
            if isinstance(corg[ckey], basestring):
                setattr(org, dkey, [_localized_name(corg[ckey], klass)])
            elif isinstance(corg[ckey], list):
                setattr(org, dkey, 
                            [_localized_name(n, klass) for n in corg[ckey]])
            else:
                setattr(org, dkey, [_localized_name(corg[ckey], klass)])
        return org
    except KeyError:
        return None

def do_contact_person_info(conf):
    """ Creates a ContactPerson instance from configuration information"""
    
    contact_person = md.ContactPerson
    cps = []
    try:
        for corg in conf["contact_person"]:
            cper = md.ContactPerson()
            for (key, classpec) in contact_person.c_children.values():
                try:
                    value = corg[key]
                    data = []
                    if isinstance(classpec, list):
                        # What if value is not a list ?
                        if isinstance(value, basestring):
                            data = [classpec[0](text=value)]
                        else:
                            for val in value:
                                data.append(classpec[0](text=val))
                    else:
                        data = classpec(text=value)
                    setattr(cper, key, data)
                except KeyError:
                    pass
            for (prop, classpec, _) in contact_person.c_attributes.values():
                try:
                    # should do a check for valid value
                    setattr(cper, prop, corg[prop])
                except KeyError:
                    pass
            cps.append(cper)
    except KeyError:
        pass
    return cps

def do_key_descriptor(cert):
    return md.KeyDescriptor(
        key_info = ds.KeyInfo(
            x509_data=ds.X509Data(
                x509_certificate=ds.X509DataType_X509Certificate(text=cert)
                )
            )
        )

def do_requested_attribute(attributes, acs, is_required="false"):
    lista = []
    for attr in attributes:
        attr = from_local_name(acs, attr, NAME_FORMAT_URI)
        args = {}
        for key in attr.keyswv():
            args[key] = getattr(attr, key)
        args["is_required"] = is_required
        lista.append(md.RequestedAttribute(**args))
    return lista

ENDPOINTS = {
    "sp": {
        "artifact_resolution_service": (md.ArtifactResolutionService, True),
        "single_logout_service": (md.SingleLogoutService, False),
        "manage_name_id_service": (md.ManageNameIDService, False),        
        "assertion_consumer_service": (md.AssertionConsumerService, True),
    },
    "idp":{
        "artifact_resolution_service": (md.ArtifactResolutionService, True),
        "single_logout_service": (md.SingleLogoutService, False),
        "manage_name_id_service": (md.ManageNameIDService, False),

        "single_sign_on_service": (md.SingleSignOnService, False),
        "name_id_mapping_service": (md.NameIDMappingService, False),

        "assertion_id_request_service": (md.AssertionIDRequestService, False),
    },
    "aa":{
        "artifact_resolution_service": (md.ArtifactResolutionService, True),
        "single_logout_service": (md.SingleLogoutService, False),
        "manage_name_id_service": (md.ManageNameIDService, False),

        "assertion_id_request_service": (md.AssertionIDRequestService, False),

        "attribute_service": (md.AttributeService, False)
    },
}

DEFAULT_BINDING = {
    "assertion_consumer_service": BINDING_HTTP_POST,
    "single_sign_on_service": BINDING_HTTP_POST,
    "single_logout_service": BINDING_HTTP_POST,
    "attribute_service": BINDING_SOAP,
    "artifact_resolution_service": BINDING_SOAP
}

def do_endpoints(conf, endpoints):
    service = {}

    for endpoint, (eclass, indexed) in endpoints.items():
        try:
            servs = []
            i = 1
            for args in conf[endpoint]:
                if isinstance(args, basestring): # Assume it's the location
                    args = {"location":args, 
                            "binding": DEFAULT_BINDING[endpoint]}
                if indexed:
                    args["index"] = "%d" % i
                servs.append(factory(eclass, **args))
                i += 1
                service[endpoint] = servs
        except KeyError:
            pass
    return service

def do_sp_sso_descriptor(servprov, acs, cert=None):
    spsso = md.SPSSODescriptor()
    spsso.protocol_support_enumeration = samlp.NAMESPACE

    if servprov["endpoints"]:
        for (endpoint, instlist) in do_endpoints(servprov["endpoints"],
                                                ENDPOINTS["sp"]).items():
            setattr(spsso, endpoint, instlist)

    if cert:
        spsso.key_descriptor = do_key_descriptor(cert)

    for key in ["want_assertions_signed", "authn_requests_signed"]:
        try:
            setattr(spsso, key, "%s" % servprov[key])
        except KeyError:
            setattr(spsso, key, DEFAULTS[key])

    requested_attributes = []
    if "required_attributes" in servprov:
        requested_attributes.extend(do_requested_attribute(
                                            servprov["required_attributes"],
                                            acs, 
                                            is_required="true"))

    if "optional_attributes" in servprov:
        requested_attributes.extend(do_requested_attribute(
                                            servprov["optional_attributes"], 
                                            acs, 
                                            is_required="false"))

    if requested_attributes:
        spsso.attribute_consuming_service = [md.AttributeConsumingService(
            requested_attribute=requested_attributes,
            service_name= [md.ServiceName(lang="en",text=servprov["name"])]
        )]
        try:
            spsso.attribute_consuming_service[0].service_description = [
                                md.ServiceDescription(
                                            text=servprov["description"])]
        except KeyError:
            pass

    # if "discovery_service" in sp:        
    #     spsso.extensions= {"extension_elements":[
    #         {
    #         "tag":"DiscoveryResponse",
    #         "namespace":md.IDPDISC,
    #         "attributes": {
    #             "index":"1",
    #             "binding": md.IDPDISC,
    #             "location":sp["url"]
    #             }
    #         }
    #     ]}

    return spsso

def do_idp_sso_descriptor(idp, cert=None):
    idpsso = md.IDPSSODescriptor()
    idpsso.protocol_support_enumeration = samlp.NAMESPACE

    if idp["endpoints"]:
        for (endpoint, instlist) in do_endpoints(idp["endpoints"],
                                                ENDPOINTS["idp"]).items():
            setattr(idpsso, endpoint, instlist)

    if cert:
        idpsso.key_descriptor = do_key_descriptor(cert)

    for key in ["want_authn_requests_signed"]:
        try:
            setattr(idpsso, key, "%s" % idp[key])
        except KeyError:
            setattr(idpsso, key, DEFAULTS[key])

    return idpsso

def do_aa_descriptor(ata, cert):
    aad = md.AttributeAuthorityDescriptor()
    aad.protocol_support_enumeration = samlp.NAMESPACE

    if ata["endpoints"]:
        for (endpoint, instlist) in do_endpoints(ata["endpoints"],
                                                ENDPOINTS["aa"]).items():
            setattr(aad, endpoint, instlist)

    if cert:
        aad.key_descriptor = do_key_descriptor(cert)

    return aad

def entity_descriptor(confd, valid_for):
    mycert = "".join(open(confd["cert_file"]).readlines()[1:-1])

    if "attribute_map_dir" in confd:
        attrconverters = ac_factory(confd["attribute_map_dir"])
    else:
        attrconverters = [AttributeConverter()]

    #if "attribute_maps" in confd:
    #    (forward,backward) = parse_attribute_map(confd["attribute_maps"])
    #else:
    #    backward = {}

    entd = md.EntityDescriptor()
    entd.entity_id = confd["entityid"]

    if valid_for:
        entd.valid_until = in_a_while(hours=valid_for)

    entd.organization = do_organization_info(confd)
    entd.contact_person = do_contact_person_info(confd)

    if "sp" in confd["service"]:
        # The SP
        entd.spsso_descriptor = do_sp_sso_descriptor(confd["service"]["sp"],
                                    attrconverters, mycert)
    if "idp" in confd["service"]:
        entd.idpsso_descriptor = do_idp_sso_descriptor(
                                            confd["service"]["idp"], mycert)
    if "aa" in confd["service"]:
        entd.attribute_authority_descriptor = do_aa_descriptor(
                                            confd["service"]["aa"], mycert)

    return entd

def entities_descriptor(eds, valid_for, name, ident, sign, secc):
    entities = md.EntitiesDescriptor(entity_descriptor= eds)
    if valid_for:
        entities.valid_until = in_a_while(hours=valid_for)
    if name:
        entities.name = name
    if ident:
        entities.id = ident

    if sign:
        entities.signature = pre_signature_part(ident)

    if sign:
        entities = secc.sign_statement_using_xmlsec("%s" % entities, 
                                                    class_name(entities))
    return entities
