#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Umeå University
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

import base64
import time

from saml2.time_util import str_to_time

from saml2 import samlp, saml
from saml2.sigver import security_context

from saml2.attribute_converter import to_local

# ---------------------------------------------------------------------------

def _use_on_or_after(condition, slack):
    now = time.mktime(time.gmtime())
    not_on_or_after = time.mktime(str_to_time(condition.not_on_or_after))
    # slack is +-
    high = not_on_or_after+slack
    if now > high:
        # To old ignore
        print "(%d > %d)" % (now,high)
        raise Exception("To old can't use it!")
    return not_on_or_after

def _use_before(condition, slack):
    not_before = time.mktime(str_to_time(condition.not_before))
    now = time.mktime(time.gmtime())
        
    if not_before > now + slack:
        # Can't use it yet
        raise Exception("Can't use it yet %s <= %s" % (not_before, now))
    
    return True

def for_me(condition, myself ):
    for restriction in condition.audience_restriction:
        audience = restriction.audience
        if audience.text.strip() == myself:
            return True
        else:
            print "%s != %s" % (audience.text.strip(), myself)

# ---------------------------------------------------------------------------

class IncorrectlySigned(Exception):
    pass
    
# ---------------------------------------------------------------------------
    
def authn_response(conf, requestor, outstanding_queries=None, log=None, 
                    timeslack=0):
    sec = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf["timeslack"])
        except KeyError:
            pass
            
    return AuthnResponse(sec, conf.attribute_converters, requestor, 
                            outstanding_queries, log, timeslack)
    
class AuthnResponse(object):
    
    def __init__(self, security_context, attribute_converters, requestor, 
                    outstanding_queries=None, log=None, timeslack=0, debug=0):
        self.sc = security_context
        self.attribute_converters = attribute_converters
        self.requestor = requestor
        if outstanding_queries:
            self.outstanding_queries = outstanding_queries
        else:
            self.outstanding_queries = {}
        self.context = "AuthnReq"
        self.timeslack = timeslack
        self.log = log
        self.debug = debug
        if self.debug and not self.log:
            self.debug = 0
        self.clear()
        
    def loads(self, xmldata, decode=True):
        if decode:
            decoded_xml = base64.b64decode(xmldata)
        else:
            decoded_xml = xmldata
        
        # own copy
        self.xmlstr = decoded_xml[:]        
        self.response = self.sc.correctly_signed_response(decoded_xml)
        
        if not self.response:
            if self.log:
                self.log.error("Response was not correctly signed")
                self.log.info(decoded_xml)
            raise IncorrectlySigned()

        if self.debug:
            self.log.debug("response: %s" % (response,))

        return self
        
    def clear(self):
        self.xmlstr = ""
        self.came_from = ""
        self.name_id = ""
        self.ava = None
        self.response = None
        self.not_on_or_after = 0
        self.assertion = None
        
    def status_ok(self):
        if self.response.status:
            status = self.response.status
            if status.status_code.value != samlp.STATUS_SUCCESS:
                if self.log:
                    self.log.info("Not successfull operation: %s" % status)
                raise Exception(
                    "Not successfull according to: %s" % \
                    status.status_code.value)

    def authn_statement_ok(self):
        # the assertion MUST contain one AuthNStatement
        assert len(self.assertion.authn_statement) == 1
        # authn_statement = assertion.authn_statement[0]
        # check authn_statement.session_index

    def condition_ok(self, lax=False):
        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert self.assertion.conditions
        condition = self.assertion.conditions
        if self.debug:
            self.log.info("condition: %s" % condition)

        try:
            self.not_on_or_after = _use_on_or_after(condition, self.timeslack)
            _use_before(condition, self.timeslack)
        except Exception:
            if not lax:
                raise
            else:
                self.not_on_or_after = 0
                
        if not for_me(condition, self.requestor):
            if not lax:
                raise Exception("Not for me!!!")
        
        return True
        
    def get_identity(self):
        # The assertion can contain zero or one attributeStatements
        if not self.assertion.attribute_statement:
            ava = {}
        else:
            assert len(self.assertion.attribute_statement) == 1
            ava = to_local(self.attribute_converters(),
                            self.assertion.attribute_statement[0])
        return ava
     
    def get_subject(self):
        # The assertion must contain a Subject
        assert self.assertion.subject
        subject = self.assertion.subject
        for subject_confirmation in subject.subject_confirmation:
            data = subject_confirmation.subject_confirmation_data
            if data.in_response_to in self.outstanding:
                self.came_from = self.outstanding[data.in_response_to]
                del self.outstanding[data.in_response_to]
            else:
                print data.in_response_to, self.outstanding.keys()
                raise Exception(
                    "Combination of session id and requestURI I don't recall")
        
        # The subject must contain a name_id
        assert subject.name_id
        self.name_id = subject.name_id.text.strip()

    def _assertion(self, assertion):
        self.assertion = assertion
        
        if self.debug:
            self.log.info("assertion context: %s" % (context,))
            self.log.info("assertion keys: %s" % (assertion.keyswv()))
            self.log.info("outstanding: %s" % (outstanding))
        
        if self.context == "AuthNReq":
            self.authn_statement_ok()

        if not self.condition_ok():
            return None
            
        self.ava = self.get_identity()
        
        if self.debug:
            self.log.debug("AVA: %s" % (self.ava,))

        self.get_subject()
         
        return True

    def _encrypted_assertion(self, xmlstr):
        decrypt_xml = self.sc.decrypt(self.xmlstr)
        
        if self.debug:
            self.log.debug("Decryption successfull")
        
        self.response = samlp.response_from_string(decrypt_xml)
        if self.debug:
            self.log.debug("Parsed decrypted assertion successfull")
        
        enc = self.response.encrypted_assertion[0].extension_elements[0]            
        assertion = extension_element_to_element(enc, 
                                                saml.ELEMENT_FROM_STRING,
                                                namespace=saml.NAMESPACE)
        if self.debug:
            self.log.debug("Decrypted Assertion: %s" % assertion)
        return self._assertion(assertion)

    def parse_assertion(self):
        try:
            assert len(self.response.assertion) == 1 or \
                    len(self.response.encrypted_assertion) == 1
        except AssertionError:
            raise Exception("No assertion part")

        if self.response.assertion:         
            self.debug and self.log.debug("***Unencrypted response***")
            return self._assertion(self.response.assertion[0])
        else:
            self.debug and self.log.info("***Encrypted response***")
            return self._encrypted_assertion(outstanding)
            
        return True
        
    def verify(self):
        """ """
        self.status_ok()
        if self.parse_assertion():
            return self
        else:
            return None
        
    def issuer(self):
        return self.response.issuer.text
        
    def session_id(self):
        return self.response.in_response_to
        
    def id(self):
        return self.response.id

    def session_info(self):
        return { "ava": self.ava, "name_id": name_id, 
                "came_from": self.came_from, "issuer": self.issuer(),
                "not_on_or_after": self.not_on_or_after }
    
# ======================================================================
                                    
   # session_info["ava"]["__userid"] = session_info["name_id"]
   # return session_info
