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
from saml2 import saml
from saml2.utils import sid
from saml2.time_util import instant

def properties(klass):
    props = [val[0] for key,val in klass.c_children.items()]
    props.extend(klass.c_attributes)
    return props
    
class Server(object):
    def __init__(self, environ, config ):
        self.environ = environ
        if config:
            self.verify_conf(config)

    def verify_conf(self, conf_file):
        """ """
        
        self.conf = eval(open(conf_file).read())
        
        # check for those that have to be there
        assert "xmlsec_binary" in self.conf
        assert "service_url" in self.conf
        assert "entityid" in self.conf
        
        if "my_key" not in self.conf:
            self.conf["my_key"] = None
        else:
            # If you have a key file you have to have a cert file
            assert "my_cert" in self.conf
            
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
        
    def _issuer(self):
        return {
            "format": saml.NAMEID_FORMAT_ENTITY,
            "text": self.conf["entityid"]
        }
        
    def _status(self, status, message=None, status_code=None):
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
        
    def _audience_restriction(self, audience):
        return { "audience": audience }

    def _conditions(self, not_before=None, not_on_or_after=None, 
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
        
    def _attribute(self, value="", name="", name_format="", friendly_name=""):
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
        
    def _attribute_statement(self, attribute):
        return { "attribute": attribute }
    
    def _subject(self, name, name_id, subject_confirmation=None):
        spec = {
            "text": name,
            "name_id": name_id,
        }
        if subject_confirmation:
            spec["subject_confirmation"] = subject_confirmation
        return spec
        
    def _assertion(self, subject, signature=False,
                            conditions=None, advice=None, statement=None,
                            authn_statement=None, authz_desc_statement=None,
                            attribute_statement=None):
                            
        spec = {
            "version": "2.0",
            "id" : sid(),
            "issue_instant" : instant(),
            "issuer": self._issuer(),
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
        
    def _response(self, in_response_to, destination, status,
                        consent=None, signature=False, assertion=None,
                        encrypt=False):

        spec = {
            "id" : sid(),
            "in_response_to": in_response_to,
            "version": "2.0",
            "issue_instant" : instant(),
            "issuer": self._issuer(),
            "destination": destination,
            "status": status,
        }
        if signature:
            spec["signature"] = sigver.pre_signature_part(spec["id"])
        if assertion:
            spec["assertion"] = assertion
        
        return spec
    