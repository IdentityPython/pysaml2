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

from saml2 import samlp
from saml2 import saml
from saml2 import extension_element_to_element

from saml2.sigver import security_context

from saml2.attribute_converter import to_local
from saml2.time_util import daylight_corrected_now

# ---------------------------------------------------------------------------

class IncorrectlySigned(Exception):
    pass
    
# ---------------------------------------------------------------------------

def _use_on_or_after(condition, slack):
    now = daylight_corrected_now()
    #print "NOW: %d" % now
    not_on_or_after = time.mktime(str_to_time(condition.not_on_or_after))
    #print "not_on_or_after: %d" % not_on_or_after
    # slack is +-
    high = not_on_or_after+slack
    if now > high:
        # To old ignore
        #print "(%d > %d)" % (now,high)
        raise Exception("To old can't use it! %d" % (now-high,))
    return not_on_or_after

def _use_before(condition, slack):
    now = daylight_corrected_now()
    #print "NOW: %s" % now
    not_before = time.mktime(str_to_time(condition.not_before))
    #print "not_before: %d" % not_before
    
    if not_before > now + slack:
        # Can't use it yet
        raise Exception("Can't use it yet %s <= %s" % (not_before, now))
    
    return True

def for_me(condition, myself ):
    # Am I among the intended audiences
    for restriction in condition.audience_restriction:
        for audience in restriction.audience:
            if audience.text.strip() == myself:
                return True
            else:
                #print "Not for me: %s != %s" % (audience.text.strip(), myself)
                pass
    
    return False

def authn_response(conf, requestor, outstanding_queries=None, log=None,
                    timeslack=0, debug=0):
    sec = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf["timeslack"])
        except KeyError:
            pass
    
    return AuthnResponse(sec, conf.attribute_converters, requestor,
                            outstanding_queries, log, timeslack, debug)

class AuthnResponse(object):
    
    def __init__(self, sec_context, attribute_converters, requestor,
                    outstanding_queries=None, log=None, timeslack=0, debug=0):
        self.sec = sec_context
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
        
        self.xmlstr = ""
        self.came_from = ""
        self.name_id = ""
        self.ava = None
        self.response = None
        self.not_on_or_after = 0
        self.assertion = None
    
    def loads(self, xmldata, decode=True):
        if self.debug:
            self.log.info("--- Loads AuthnResponse ---")
        if decode:
            decoded_xml = base64.b64decode(xmldata)
        else:
            decoded_xml = xmldata
        
        # own copy
        self.xmlstr = decoded_xml[:]
        if self.debug:
            self.log.info("xmlstr: %s" % (self.xmlstr,))
        try:
            self.response = self.sec.correctly_signed_response(decoded_xml)
        except Exception, excp:
            self.log and self.log.info("EXCEPTION: %s", excp)
        
        if not self.response:
            if self.log:
                self.log.error("Response was not correctly signed")
                self.log.info(decoded_xml)
            raise IncorrectlySigned()
        
        if self.debug:
            self.log.info("response: %s" % (self.response,))
        
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
            if self.log:
                self.log.info("status: %s" % (status,))
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
        except Exception, excp:
            self.log and self.log.error("Exception on condition: %s" % (excp,))
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
            self.log.error("Missing Attribute Statement")
            ava = {}
        else:
            assert len(self.assertion.attribute_statement) == 1
            
            if self.debug:
                self.log.info("Attribute Statement: %s" % (
                                    self.assertion.attribute_statement[0],))
                for aconv in self.attribute_converters():
                    self.log.info("Converts name format: %s" % (aconv.name_format,))
            
            ava = to_local(self.attribute_converters(),
                            self.assertion.attribute_statement[0])
        return ava
    
    def get_subject(self):
        # The assertion must contain a Subject
        assert self.assertion.subject
        subject = self.assertion.subject
        for subject_confirmation in subject.subject_confirmation:
            data = subject_confirmation.subject_confirmation_data
            if data.in_response_to in self.outstanding_queries:
                self.came_from = self.outstanding_queries[data.in_response_to]
                del self.outstanding_queries[data.in_response_to]
            else:
                if self.debug:
                    self.log.info("in response to: %s" % data.in_response_to)
                    self.log.info("outstanding queries: %s" % \
                                        self.outstanding_queries.keys())
                raise Exception(
                    "Combination of session id and requestURI I don't recall")
        
        # The subject must contain a name_id
        assert subject.name_id
        self.name_id = subject.name_id.text.strip()
        return self.name_id
    
    def _assertion(self, assertion):
        self.assertion = assertion
        
        if self.debug:
            self.log.info("assertion context: %s" % (self.context,))
            self.log.info("assertion keys: %s" % (assertion.keyswv()))
            self.log.info("outstanding_queries: %s" % (
                                                    self.outstanding_queries))
        
        if self.context == "AuthNReq":
            self.authn_statement_ok()
        
        if not self.condition_ok():
            return None
        
        if self.debug:
            self.log.info("--- Getting Identity ---")
        
        self.ava = self.get_identity()
        
        if self.debug:
            self.log.info("--- AVA: %s" % (self.ava,))
        
        self.get_subject()
        
        return True
    
    def _encrypted_assertion(self, xmlstr):
        decrypt_xml = self.sec.decrypt(xmlstr)
        
        if self.debug:
            self.log.info("Decryption successfull")
        
        self.response = samlp.response_from_string(decrypt_xml)
        if self.debug:
            self.log.info("Parsed decrypted assertion successfull")
        
        enc = self.response.encrypted_assertion[0].extension_elements[0]
        assertion = extension_element_to_element(enc,
                                                saml.ELEMENT_FROM_STRING,
                                                namespace=saml.NAMESPACE)
        if self.debug:
            self.log.info("Decrypted Assertion: %s" % assertion)
        return self._assertion(assertion)
    
    def parse_assertion(self):
        try:
            assert len(self.response.assertion) == 1 or \
                    len(self.response.encrypted_assertion) == 1
        except AssertionError:
            raise Exception("No assertion part")
        
        if self.response.assertion:
            self.debug and self.log.info("***Unencrypted response***")
            return self._assertion(self.response.assertion[0])
        else:
            self.debug and self.log.info("***Encrypted response***")
            return self._encrypted_assertion(
                                        self.response.encrypted_assertion[0])
        
        return True
    
    def verify(self):
        """ Verify that the assertion is syntactically correct and
        the signature is correct if present."""
        
        self.status_ok()
        if self.parse_assertion():
            return self
        else:
            return None
    
    def issuer(self):
        """ Return the issuer of the reponse """
        return self.response.issuer.text
    
    def session_id(self):
        """ Returns the SessionID of the response """ 
        return self.response.in_response_to
    
    def id(self):
        """ Return the ID of the response """
        return self.response.id
    
    def authn_info(self):
        res = []
        for astat in self.assertion.authn_statement:
            ac = astat.authn_context
            aclass = ac.authn_context_class_ref.text
            authn_auth = [aa.text for aa in ac.authenticating_authority]
            res.append((aclass, authn_auth))
        return res
        
    def session_info(self):
        """ Returns a predefined set of information gleened from the 
        response.
        :returns: Dictionary with information
        """
        return { "ava": self.ava, "name_id": self.name_id,
                "came_from": self.came_from, "issuer": self.issuer(),
                "not_on_or_after": self.not_on_or_after,
                "authn_info": self.authn_info() }
    
    def __str__(self):
        return "%s" % self.xmlstr

# ======================================================================
   
   # session_info["ava"]["__userid"] = session_info["name_id"]
   # return session_info
