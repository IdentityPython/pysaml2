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
from saml2 import saml, samlp
from saml2.utils import sid, decode_base64_and_inflate, make_instance
from saml2.time_util import instant, in_a_while
from saml2.metadata import MetaData

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
    
class Server(object):
    def __init__(self, config, log=None):
        if config:
            self.verify_conf(config)
        self.log = log

    def verify_conf(self, conf_file):
        """ """
        
        self.conf = eval(open(conf_file).read())
        
        # check for those that have to be there
        assert "xmlsec_binary" in self.conf
        #assert "service_url" in self.conf
        assert "entityid" in self.conf
        
        if "key_file" not in self.conf:
            self.conf["key_file"] = None
        else:
            # If you have a key file you have to have a cert file
            assert "cert_file" in self.conf
            
        if "metadata" in self.conf:
            md = MetaData()
            for mdfile in self.conf["metadata"]:
                md.import_metadata(open(mdfile).read())
            self.metadata = md
        else:
            self.metadata = None
        
        if "virtual_organization" in self.conf:
            if "nameid_format" not in self.conf:
                self.conf["nameid_format"] = NAMEID_FORMAT_TRANSIENT

        print "Configuration: %s" % (self.conf,)
        
    def issuer(self):
        return klassdict( saml.Issuer, self.conf["entityid"],
            format=saml.NAMEID_FORMAT_ENTITY)
        
    def status_from_exception(self, exception):
        return klassdict(samlp.Status,
            status_code=klassdict(samlp.StatusCode,
                value=samlp.STATUS_RESPONDER,
                status_code=klassdict(samlp.StatusCode,
                                value=EXCEPTION2STATUS[exception.__class__])
                ),
            status_message=exception.args[0],
        )
        
    def status_message(self, text="", **kwargs):
        return klassdict(samlp.StatusMessage, text, **kwargs)

    def status_code(self, text="", **kwargs):
        return klassdict(samlp.StatusCode, text, **kwargs)

    def status(self, text="", **kwargs):
        return klassdict(samlp.Status, text, **kwargs)
        
    def success_status(self):
        return self.status(status_code=self.status_code(
                                value=samlp.STATUS_SUCCESS))
                                
    def audience(self, text="", **kwargs):
        return klassdict(saml.Audience, text, **kwargs)

    def audience_restriction(self, text="", **kwargs):
        return klassdict(saml.AudienceRestriction, text, **kwargs)

    def conditions(self, text="", **kwargs):
        return klassdict(saml.Conditions, text, **kwargs)
        
    def attribute(self, text="", **kwargs):
        return klassdict(saml.Attribute, text, **kwargs)

    def attribute_value(self, text="", **kwargs):
        return klassdict(saml.AttributeValue, text, **kwargs)
            
    def attribute_statement(self, text="", **kwargs):
        return klassdict(saml.AttributeStatement, text, **kwargs)
    
    def subject_confirmation_data(self, text="", **kwargs):
        return klassdict(saml.SubjectConfirmationData, text, **kwargs)
        
    def subject_confirmation(self, text="", **kwargs):
        return klassdict(saml.SubjectConfirmation, text, **kwargs)        
        
    def subject(self, text="", **kwargs):
        return klassdict(saml.Subject, text, **kwargs)        

    def authn_statement(self, text="", **kwargs):
        return klassdict(saml.Subject, text, **kwargs)        
        
    def assertion(self, text="", **kwargs):
        kwargs.update({
            "version": "2.0",
            "id" : sid(),
            "issue_instant" : instant(),
        })
        return klassdict(saml.Assertion, text, **kwargs)        
        
    def response(self, signature=False, encrypt=False, **kwargs):

        kwargs.update({
            "id" : sid(),
            "version": "2.0",
            "issue_instant" : instant(),
        })
        if signature:
            kwargs["signature"] = sigver.pre_signature_part(kwargs["id"])
        
        return kwargs
    
    def parse_request(self, enc_request):
        request_xml = decode_base64_and_inflate(enc_request)
        request = samlp.authn_request_from_string(request_xml)
        
        return_destination = request.assertion_consumer_service_url
        # request.destination should be me 
        id = request.id # put in in_reply_to
        if request.version != "2.0":
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
            
        policy = request.name_id_policy
        if policy.allow_create.lower() == "true" and \
            policy.format == saml.NAMEID_FORMAT_TRANSIENT:
            name_id_policies = policy.format
                
        return (consumer_url, id, name_id_policies, spentityid)
        
    def do_attribute_statement(self, identity):
        """
        :param identity: A dictionary with fiendly names as keys
        :return:
        """
        attrs = []
        for key, val in identity.items():
            dic = {}
            if isinstance(val,basestring):
                attrval = self.attribute_value(val)
            elif isinstance(val,list):
                attrval = [self.attribute_value(v) for v in val]
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
            attrs.append(self.attribute(**dic))

        return self.attribute_statement(attribute=attrs)
        
    def do_sso_response(self, consumer_url, in_response_to,
                        sp_entity_id, identity, name_id_policies=None, 
                        subject_id=None ):
    
        attribute_statement = self.do_attribute_statement(identity)
        
        # start using now and for a hour
        conditions = self.conditions(
                        not_before=instant(), 
                        # an hour from now
                        not_on_or_after=in_a_while(0,0,0,0,0,1), 
                        audience_restriction=self.audience_restriction(
                                audience=self.audience(sp_entity_id)))
        # temporary identifier or ??
        subject_id = sid()
        tmp = self.response(
            in_response_to=in_response_to,
            destination=consumer_url,
            status=self.success_status(),
            assertion=self.assertion(
                subject = self.subject(subject_id,
                    name_id=saml.NAMEID_FORMAT_TRANSIENT,
                    method=saml.SUBJECT_CONFIRMATION_METHOD_BEARER,
                    subject_confirmation=self.subject_confirmation(
                        subject_confirmation_data=self.subject_confirmation_data(
                                in_response_to=in_response_to))),
                attribute_statement = attribute_statement,
                authn_statement= self.authn_statement(
                            authn_instant=instant(),
                            session_index=sid()),
                conditions=conditions,
                ),
            )
        return make_instance(samlp.Response, tmp)
