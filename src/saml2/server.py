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
from saml2.utils import sid, decode_base64_and_inflate
from saml2.time_util import instant
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
    props.extend(klass.c_attributes)
    return props
    
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
        return {
            "format": saml.NAMEID_FORMAT_ENTITY,
            "text": self.conf["entityid"]
        }
        
    def status_from_exception(self, exception):
        return {
            "status_code": {
                "value": samlp.STATUS_RESPONDER,
                "status_code": {
                    "value": EXCEPTION2STATUS[exception.__class__],
                },
            },
            "status_message": exception.args[0],
        }
        
    def status(self, status, message=None, status_code=None):
        res = {
            "status_code": {
                "value": status,
            }
        }
        if message:
            res["status_message"] = message
        if status_code:
            res["status_code"].update(status_code)
        return res
        
    def audience_restriction(self, audience):
        return { "audience": audience }

    def conditions(self, not_before=None, not_on_or_after=None, 
                    audience_restriction=None, condition=None,
                    one_time_use=None, proxy_restriction=None):
                    
        res = {}
        if not_before:
            res["not_before"] = not_before
        if not_on_or_after:
            res["not_on_or_after"] = not_on_or_after
        if audience_restriction:
            res["audience_restriction"] = audience_restriction
        # The ones below are hardly used
        if condition:
            res["condition"] = condition
        if one_time_use:
            res["one_time_use"] = one_time_use
        if proxy_restriction:
            res["proxy_restriction"] = proxy_restriction
        
        return res
        
    def attribute(self, value="", name="", name_format="", friendly_name=""):
        dic = {}
        if value:
            dic["attribute_value"] = value
        if name:
            dic["name"] = name
        if name_format:
            dic["name_format"] = name_format
        if friendly_name:
            dic["friendly_name"] = friendly_name
        return dic
        
    def attribute_statement(self, attribute):
        return { "attribute": attribute }
    
    def subject(self, name, name_id, subject_confirmation=None):
        spec = {
            "text": name,
            "name_id": name_id,
        }
        if subject_confirmation:
            spec["subject_confirmation"] = subject_confirmation
        return spec
        
    def assertion(self, subject, signature=False,
                            conditions=None, advice=None, statement=None,
                            authn_statement=None, authz_desc_statement=None,
                            attribute_statement=None):
                            
        spec = {
            "version": "2.0",
            "id" : sid(),
            "issue_instant" : instant(),
            "issuer": self.issuer(),
            "subject": subject,
        }
        
        if signature:
            spec["signature"] = sigver.pre_signature_part(spec["id"])
        if conditions:
            spec["conditions"] = conditions
        if advice:
            spec["advice"] = advice
        if statement:
            spec["statement"] = statement
        if authn_statement:
            spec["authn_statement"] = authn_statement
        if authz_desc_statement:
            spec["authz_desc_statement"] = authz_desc_statement
        if attribute_statement:
            spec["attribute_statement"] = attribute_statement
        
        return spec
        
    def response(self, in_response_to, destination, status,
                        consent=None, signature=False, assertion=None,
                        encrypt=False):

        spec = {
            "id" : sid(),
            "in_response_to": in_response_to,
            "version": "2.0",
            "issue_instant" : instant(),
            "issuer": self.issuer(),
            "destination": destination,
            "status": status,
        }
        if signature:
            spec["signature"] = sigver.pre_signature_part(spec["id"])
        if assertion:
            spec["assertion"] = assertion
        
        return spec
    
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
            raise UnknownPricipal(spentityid)
        if not consumer_url: # what to do ?
            raise UnsupportedBinding(spentityid)

        if consumer_url != return_destination:
            # serious error on someones behalf
            raise OtherError("ConsumerURL and return destination mismatch")
            
        policy = request.name_id_policy
        if policy.allow_create.lower() == "true" and \
            policy.format == saml.NAMEID_FORMAT_TRANSIENT:
            name_id_policies = policy.format
                
        return (consumer_url, id, name_id_policies)
        