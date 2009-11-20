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

"""Contains classes and functions that a SAML2.0 Identity provider (IdP) 
or attribute authority (AA) may use to conclude its tasks.
"""
import shelve

from saml2 import saml, samlp, VERSION
from saml2.utils import sid, decode_base64_and_inflate, make_instance
from saml2.time_util import instant, in_a_while
from saml2.metadata import MetaData
from saml2.config import Config
from saml2.cache import Cache

class VersionMismatch(Exception):
    pass
    
class UnknownPricipal(Exception):
    pass
    
class UnsupportedBinding(Exception):
    pass

class OtherError(Exception):
    pass
    
EXCEPTION2STATUS = {
    VersionMismatch: samlp.STATUS_VERSION_MISMATCH,
    UnknownPricipal: samlp.STATUS_UNKNOWN_PRINCIPAL,
    UnsupportedBinding: samlp.STATUS_UNSUPPORTED_BINDING,
    OtherError: samlp.STATUS_UNKNOWN_PRINCIPAL,
}

def properties(klass):
    props = [val[0] for key,val in klass.c_children.items()]
    props.extend(klass.c_attributes.values())
    return props
    
def klassdict(klass, text=None, **kwargs):
    spec = {}
    if text:
        spec["text"] = text
    props = properties(klass)
    #print props
    for key, val in kwargs.items():
        #print "?",key
        if key in props:
            spec[key] = val
    return spec
    
def kd_status_from_exception(exception):
    return klassdict(samlp.Status,
        status_code=klassdict(samlp.StatusCode,
            value=samlp.STATUS_RESPONDER,
            status_code=klassdict(samlp.StatusCode,
                            value=EXCEPTION2STATUS[exception.__class__])
            ),
        status_message=exception.args[0],
    )
    
def kd_name_id(text="", **kwargs):
    return klassdict(saml.NameID, text, **kwargs)

def kd_status_message(text="", **kwargs):
    return klassdict(samlp.StatusMessage, text, **kwargs)

def kd_status_code(text="", **kwargs):
    return klassdict(samlp.StatusCode, text, **kwargs)

def kd_status(text="", **kwargs):
    return klassdict(samlp.Status, text, **kwargs)
    
def kd_success_status():
    return kd_status(status_code=kd_status_code(value=samlp.STATUS_SUCCESS))
                            
def kd_audience(text="", **kwargs):
    return klassdict(saml.Audience, text, **kwargs)

def kd_audience_restriction(text="", **kwargs):
    return klassdict(saml.AudienceRestriction, text, **kwargs)

def kd_conditions(text="", **kwargs):
    return klassdict(saml.Conditions, text, **kwargs)
    
def kd_attribute(text="", **kwargs):
    return klassdict(saml.Attribute, text, **kwargs)

def kd_attribute_value(text="", **kwargs):
    return klassdict(saml.AttributeValue, text, **kwargs)
        
def kd_attribute_statement(text="", **kwargs):
    return klassdict(saml.AttributeStatement, text, **kwargs)

def kd_subject_confirmation_data(text="", **kwargs):
    return klassdict(saml.SubjectConfirmationData, text, **kwargs)
    
def kd_subject_confirmation(text="", **kwargs):
    return klassdict(saml.SubjectConfirmation, text, **kwargs)        
    
def kd_subject(text="", **kwargs):
    return klassdict(saml.Subject, text, **kwargs)        

def kd_authn_statement(text="", **kwargs):
    return klassdict(saml.Subject, text, **kwargs)        
    
def kd_assertion(text="", **kwargs):
    kwargs.update({
        "version": VERSION,
        "id" : sid(),
        "issue_instant" : instant(),
    })
    return klassdict(saml.Assertion, text, **kwargs)        
    
def kd_response(signature=False, encrypt=False, **kwargs):

    kwargs.update({
        "id" : sid(),
        "version": VERSION,
        "issue_instant" : instant(),
    })
    if signature:
        kwargs["signature"] = sigver.pre_signature_part(kwargs["id"])
    
    return kwargs

def do_attribute_statement(identity):
    """
    :param identity: A dictionary with fiendly names as keys
    :return:
    """
    attrs = []
    for key, val in identity.items():
        dic = {}
        if isinstance(val,basestring):
            attrval = kd_attribute_value(val)
        elif isinstance(val,list):
            attrval = [kd_attribute_value(v) for v in val]
        else:
            raise OtherError("strange value type on: %s" % val)
        dic["attribute_value"] = attrval
        if isinstance(key, basestring):
            dic["name"] = key
        elif isinstance(key, tuple): # 3-tuple
            (name,format,friendly) = key
            if name:
                dic["name"] = name
            if format:
                dic["name_format"] = format
            if friendly:
                dic["friendly_name"] = friendly
        attrs.append(kd_attribute(**dic))

    return kd_attribute_statement(attribute=attrs)

def kd_issuer(text, **kwargs):
    return klassdict(saml.Issuer, text, **kwargs)        


class Server(object):
    def __init__(self, config_file="", config=None, cache="",
                    log=None, debug=0):
        if config_file:
            self.conf = Config()
            self.conf.load_file(config_file)
            if "subject_data" in self.conf:
                self.id_map = shelve.open(self.conf["subject_data"],
                                            writeback=True)
            else:
                self.id_map = None
        elif config:
            self.conf = config
        
        self.metadata = self.conf["metadata"]
        if cache:
            self.cache=Cache(cache)
        else:
            self.cache=Cache()
        self.log = log
        self.debug = debug
        
    def issuer(self):
        return kd_issuer( self.conf["entityid"], 
                        format=saml.NAMEID_FORMAT_ENTITY)
        
    def persistent_id(self, entity_id, subject_id):
        """ Keeps the link between a permanent identifier and a 
        temporary/pseudotemporary identifier for a subject
        
        :param entity_id: SP entity ID or VO entity ID
        :param subject_id: The local identifier of the subject
        :return: A arbitrary identifier for the subject unique to the
            entity_id
        """
        if self.debug:
            self.log and self.log.debug("Id map keys: %s" % self.id_map.keys())
            
        try:
            map = self.id_map[entity_id]
        except KeyError:
            map = self.id_map[entity_id] = {"forward":{}, "backward":{}}

        try:
            if self.debug:
                self.log.debug("map forward keys: %s" % map["forward"].keys())
            return map["forward"][subject_id]
        except KeyError:
            while True:
                temp_id = sid()
                if temp_id not in map["backward"]:
                    break
            map["forward"][subject_id] = temp_id
            map["backward"][temp_id] = subject_id
            self.id_map[entity_id]= map
            self.id_map.sync()
            
            return temp_id
        
    def parse_authn_request(self, enc_request):
        """Parse a Authentication Request
        
        :param enc_request: The request in its transport format
        :return: A tuple of
            consumer_url - as gotten from the SPs entity_id and the metadata
            id - the id of the request
            name_id_policy - how to chose the subjects identifier
            spentityid - the entity id of the SP
        """
        request_xml = decode_base64_and_inflate(enc_request)
        request = samlp.authn_request_from_string(request_xml)
        
        return_destination = request.assertion_consumer_service_url
        # request.destination should be me 
        id = request.id # put in in_reply_to
        if request.version != VERSION:
            raise VersionMismatch(
                        "can't work with version %s" % request.version)
        spentityid = request.issuer.text
        # used to find return address in metadata
        try:
            consumer_url = self.metadata.consumer_url(spentityid)
        except KeyError:
            self.log and self.log.info(
                    "entities: %s" % self.metadata.entity.keys())
            raise UnknownPricipal(spentityid)
        if not consumer_url: # what to do ?
            raise UnsupportedBinding(spentityid)

        if consumer_url != return_destination:
            # serious error on someones behalf
            self.log and self.log.info("%s != %s" % (consumer_url,
                            return_destination))
            print "%s != %s" % (consumer_url, return_destination)
            raise OtherError("ConsumerURL and return destination mismatch")
               
        self.log and self.log.info("AuthNRequest: %s" % request)
        return (consumer_url, id, request.name_id_policy, spentityid)
        
    def assertion_rule(self, issuer):
        """ """
        try:
            assertion_rules = self.conf["assertions"]
        except KeyError:
            return None
            
        try:
            return assertion_rules[issuer]
        except KeyError:
            try:
                return assertion_rules["default"]
            except KeyError:
                return {}
                
    def wants(self, sp_entity_id):
        """
        :param sp_entity_id: The entity id of the SP
        :return: 2-tuple, list of required and list of optional attributes
        """
        return self.metadata.requests(sp_entity_id)
        
    def parse_attribute_query(self, xml_string):
        query = samlp.attribute_query_from_string(xml_string)
        assert query.version == VERSION
        self.log and self.log.info(
            "%s ?= %s" % (query.destination, 
                            self.conf["service"]["aa"]["url"]))
        assert query.destination == self.conf["service"]["aa"]["url"]

        arule = self.assertion_rule(query.issuer)
        
        # verify signature
        
        subject = query.subject.name_id.text
        if query.attribute:
            attribute = query.attribute
        else:
            attribute = None
        return (subject, attribute, query)
        
    def find_subject(self, subject, attribute=None):
        pass
                
    def _not_on_or_after(self, sp_entity_id):
        if "assertions" in self.conf:
            try:
                spec = self.conf["assertions"][sp_entity_id]["lifetime"]
                return in_a_while(**spec)
            except KeyError:
                try:
                    spec = self.conf["assertions"]["default"]["lifetime"]
                    return in_a_while(**spec)
                except KeyError:
                    pass
        
        # default is a hour
        return in_a_while(0,0,0,0,0,1)
            
    def do_sso_response(self, consumer_url, in_response_to,
                        sp_entity_id, identity, name_id=None ):
        """ Create a Response the follows the ??? profile.
        
        :param consumer_url: The URL which should receive the response
        :param in_response_to: The session identifier of the request
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param name_id: The identifier of the subject 
        :return: A Response instance
        """
        attr_statement = do_attribute_statement(identity)
        
        
        # start using now and for a hour
        conds = kd_conditions(
                        not_before=instant(), 
                        # an hour from now
                        not_on_or_after=self._not_on_or_after(sp_entity_id), 
                        audience_restriction=kd_audience_restriction(
                                audience=kd_audience(sp_entity_id)))
        # temporary identifier or ??
        if not name_id:
            name_id = kd_name_id(sid(), format=saml.NAMEID_FORMAT_TRANSIENT)

        assertion=kd_assertion(
            attribute_statement = attr_statement,
            authn_statement= kd_authn_statement(
                        authn_instant=instant(),
                        session_index=sid()),
            conditions=conds,
            subject=kd_subject(
                name_id=name_id,
                method=saml.SUBJECT_CONFIRMATION_METHOD_BEARER,
                subject_confirmation=kd_subject_confirmation(
                    subject_confirmation_data=kd_subject_confirmation_data(
                            in_response_to=in_response_to))),
            ),
            
        tmp = kd_response(
            issuer=self.issuer(),
            in_response_to=in_response_to,
            destination=consumer_url,
            status=kd_success_status(),
            assertion=assertion,
            )
        
        # Store which assertion that has been sent to which SP about which
        # subject.
        self.cache.set(name_id["text"], sp_entity_id, assertion, 
                        conds["not_on_or_after"])
                        
        return make_instance(samlp.Response, tmp)

    def do_aa_response(self, consumer_url, in_response_to,
                        sp_entity_id, identity, name_id_policies=None, 
                        name_id=None, ip_address="", issuer=None):

        attr_statement = do_attribute_statement(identity)
        
        # start using now and for a hour
        conds = kd_conditions(
                        not_before=instant(), 
                        # an hour from now
                        not_on_or_after=in_a_while(hours=1), 
                        audience_restriction=kd_audience_restriction(
                                audience=kd_audience(sp_entity_id)))

        # temporary identifier or ??
        if not name_id:
            name_id = kd_name_id(sid(), format=saml.NAMEID_FORMAT_TRANSIENT)

        assertion=kd_assertion(
            subject = kd_subject(
                name_id=name_id,
                method=saml.SUBJECT_CONFIRMATION_METHOD_BEARER,
                subject_confirmation=kd_subject_confirmation(
                    subject_confirmation_data=kd_subject_confirmation_data(
                            in_response_to=in_response_to,
                            not_on_or_after=in_a_while(hours=1),
                            address=ip_address,
                            recipient=consumer_url))),
            attribute_statement = attr_statement,
            authn_statement= kd_authn_statement(
                        authn_instant=instant(),
                        session_index=sid()),
            conditions=conds,
            )
            
        self.cache.set(name_id["text"], sp_entity_id, assertion, 
                            conds["not_on_or_after"])
            
        tmp = kd_response(
            issuer=issuer,
            in_response_to=in_response_to,
            destination=consumer_url,
            status=kd_success_status(),
            assertion=assertion,
            )

        return make_instance(samlp.Response, tmp)
