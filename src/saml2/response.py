#!/usr/bin/env python
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

import calendar
import base64
import sys

from saml2 import samlp
from saml2 import saml
from saml2 import extension_element_to_element
from saml2 import time_util

from saml2.sigver import security_context, SignatureError
from saml2.attribute_converter import to_local
from saml2.time_util import str_to_time

from saml2.validate import validate_on_or_after
from saml2.validate import validate_before
from saml2.validate import valid_instance
from saml2.validate import valid_address
from saml2.validate import NotValid

# ---------------------------------------------------------------------------

class IncorrectlySigned(Exception):
    pass
    
# ---------------------------------------------------------------------------

def _dummy(_):
    return None

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

def authn_response(conf, return_addr, outstanding_queries=None,
                    log=None, timeslack=0, debug=0):
    sec = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf.accepted_time_diff)
        except TypeError:
            timeslack = 0
    
    return AuthnResponse(sec, conf.attribute_converters, conf.entityid,
                        return_addr, outstanding_queries, log, timeslack, 
                        debug)

# comes in over SOAP so synchronous
def attribute_response(conf, return_addr, log=None, timeslack=0,
                        debug=0):
    sec = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf.accepted_time_diff)
        except TypeError:
            timeslack = 0

    return AttributeResponse(sec, conf.attribute_converters, conf.entityid,
                                return_addr, log, timeslack, debug,
                                asynchop=False)

class StatusResponse(object):
    def __init__(self, sec_context, return_addr=None, log=None, timeslack=0, 
                    debug=0, request_id=0):
        self.sec = sec_context
        self.return_addr = return_addr
        self.timeslack = timeslack
        self.request_id = request_id
        self.log = log
        self.debug = debug
        if self.debug and not self.log:
            self.debug = 0
        
        self.xmlstr = ""
        self.name_id = ""
        self.response = None
        self.not_on_or_after = 0
        self.in_response_to = None
        self.signature_check = self.sec.correctly_signed_response
    
    def _clear(self):
        self.xmlstr = ""
        self.name_id = ""
        self.response = None
        self.not_on_or_after = 0
        
    def _postamble(self):
        if not self.response:
            if self.log:
                self.log.error("Response was not correctly signed")
                if self.xmlstr:
                    self.log.info(self.xmlstr)
            raise IncorrectlySigned()
    
        if self.debug:
            self.log.info("response: %s" % (self.response,))

        try:
            valid_instance(self.response)
        except NotValid, exc:
            if self.log:
                self.log.error("Not valid response: %s" % exc.args[0])
            else:
                print >> sys.stderr, "Not valid response: %s" % exc.args[0]
        
            self._clear()
            return self
        
        self.in_response_to = self.response.in_response_to
        return self
        
    def load_instance(self, instance):
        self.response = self.sec.check_signature(instance)
        return self._postamble()
        
    def _loads(self, xmldata, decode=True, origxml=None):
        if decode:
            decoded_xml = base64.b64decode(xmldata)
        else:
            decoded_xml = xmldata
    
        # own copy
        self.xmlstr = decoded_xml[:]
        if self.debug:
            self.log.info("xmlstr: %s" % (self.xmlstr,))
            fil = open("response.xml", "w")
            fil.write(self.xmlstr)
            fil.close()

        try:
            self.response = self.signature_check(decoded_xml, origdoc=origxml)
        except TypeError:
            raise
        except SignatureError:
            raise
        except Exception, excp:
            if self.log:
                self.log.info("EXCEPTION: %s", excp)
    
        #print "<", self.response
        
        return self._postamble()
    
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
        return True

    def issue_instant_ok(self):
        """ Check that the response was issued at a reasonable time """
        upper = time_util.shift_time(time_util.time_in_a_while(days=1),
                                    self.timeslack).timetuple()
        lower = time_util.shift_time(time_util.time_a_while_ago(days=1),
                                    -self.timeslack).timetuple()
        # print "issue_instant: %s" % self.response.issue_instant
        # print "%s < x < %s" % (lower, upper)
        issued_at = str_to_time(self.response.issue_instant)
        return issued_at > lower and issued_at < upper

    def _verify(self):
        if self.request_id and self.in_response_to and \
            self.in_response_to != self.request_id:
            if self.log:
                self.log.error("Not the id I expected: %s != %s" % (
                                                        self.in_response_to,
                                                        self.request_id))
            return None
            
        assert self.response.version == "2.0"
        if self.response.destination and \
            self.response.destination != self.return_addr:
            if self.log:
                self.log.error("%s != %s" % (self.response.destination, 
                                                self.return_addr))
            return None
            
        assert self.issue_instant_ok()

        assert self.status_ok()
        return self

    def loads(self, xmldata, decode=True, origxml=None):
        return self._loads(xmldata, decode, origxml)

    def verify(self):
        try:
            return self._verify()
        except AssertionError:
            return None

    def update(self, mold):
        self.xmlstr = mold.xmlstr
        self.in_response_to = mold.in_response_to
        self.response = mold.response
        
    def issuer(self):
        return self.response.issuer.text.strip()
        
class LogoutResponse(StatusResponse):
    def __init__(self, sec_context, return_addr=None, log=None, timeslack=0, 
                    debug=0):
        StatusResponse.__init__(self, sec_context, return_addr, log, timeslack, 
                                debug)
        self.signature_check = self.sec.correctly_signed_logout_response

#class AttributeResponse(StatusResponse):
#    def __init__(self, sec_context, attribute_converters, entity_id,
#                    return_addr=None, log=None, timeslack=0, debug=0):
#        StatusResponse.__init__(self, sec_context, return_addr, log, timeslack,
#                                debug)
#        self.entity_id = entity_id
#        self.attribute_converters = attribute_converters
#        self.assertion = None
#
#    def get_identity(self):
#        # The assertion can contain zero or one attributeStatements
#        if not self.assertion.attribute_statement:
#            self.log.error("Missing Attribute Statement")
#            ava = {}
#        else:
#            assert len(self.assertion.attribute_statement) == 1
#
#            if self.debug:
#                self.log.info("Attribute Statement: %s" % (
#                                    self.assertion.attribute_statement[0],))
#                for aconv in self.attribute_converters:
#                    self.log.info(
#                            "Converts name format: %s" % (aconv.name_format,))
#
#            ava = to_local(self.attribute_converters,
#                            self.assertion.attribute_statement[0])
#        return ava
#
#    def session_info(self):
#        """ Returns a predefined set of information gleened from the
#        response.
#        :returns: Dictionary with information
#        """
#        if self.session_not_on_or_after > 0:
#            nooa = self.session_not_on_or_after
#        else:
#            nooa = self.not_on_or_after
#
#        return { "ava": self.ava, "name_id": self.name_id,
#                "came_from": self.came_from, "issuer": self.issuer(),
#                "not_on_or_after": nooa,
#                "authn_info": self.authn_info() }
   
class AuthnResponse(StatusResponse):
    """ This is where all the profile complience is checked.
    This one does saml2int complience. """
    
    def __init__(self, sec_context, attribute_converters, entity_id, 
                    return_addr=None, outstanding_queries=None, log=None, 
                    timeslack=0, debug=0, asynchop=False):
        StatusResponse.__init__(self, sec_context, return_addr, log, 
                                    timeslack, debug)
        self.entity_id = entity_id
        self.attribute_converters = attribute_converters
        if outstanding_queries:
            self.outstanding_queries = outstanding_queries
        else:
            self.outstanding_queries = {}
        self.context = "AuthnReq"        
        self.came_from = ""
        self.ava = None
        self.assertion = None
        self.session_not_on_or_after = 0
        self.asynchop = asynchop

    def loads(self, xmldata, decode=True, origxml=None):
        self._loads(xmldata, decode, origxml)
        
        if self.asynchop and self.in_response_to in self.outstanding_queries:
            self.came_from = self.outstanding_queries[self.in_response_to]
            del self.outstanding_queries[self.in_response_to]

        return self
    
    def clear(self):
        self._clear()
        self.came_from = ""
        self.ava = None
        self.assertion = None
        
    def authn_statement_ok(self):
        # the assertion MUST contain one AuthNStatement
        assert len(self.assertion.authn_statement) == 1
        authn_statement = self.assertion.authn_statement[0]
        if authn_statement.session_not_on_or_after:
            if validate_on_or_after(authn_statement.session_not_on_or_after,
                                    self.timeslack):
                self.session_not_on_or_after = calendar.timegm(
                    time_util.str_to_time(authn_statement.session_not_on_or_after))
            else:
                return False
        return True
        # check authn_statement.session_index
    
    def condition_ok(self, lax=False):
        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert self.assertion.conditions
        condition = self.assertion.conditions
        if self.debug and self.log:
            self.log.info("condition: %s" % condition)
        
        try:
            self.not_on_or_after = validate_on_or_after(
                                                    condition.not_on_or_after,
                                                    self.timeslack)
            validate_before(condition.not_before, self.timeslack)
        except Exception, excp:
            if self.log:
                self.log.error("Exception on condition: %s" % (excp,))
            if not lax:
                raise
            else:
                self.not_on_or_after = 0
        
        if not for_me(condition, self.entity_id):
            if not lax:
                #print condition
                #print self.entity_id
                raise Exception("Not for me!!!")
        
        return True
    
    def get_identity(self):
        # The assertion can contain zero or one attributeStatements
        if not self.assertion.attribute_statement:
            if self.log:
                self.log.error("Missing Attribute Statement")
            ava = {}
        else:
            assert len(self.assertion.attribute_statement) == 1
            
            if self.debug and self.log:
                self.log.info("Attribute Statement: %s" % (
                                    self.assertion.attribute_statement[0],))
                for aconv in self.attribute_converters:
                    self.log.info(
                            "Converts name format: %s" % (aconv.name_format,))
            
            ava = to_local(self.attribute_converters,
                            self.assertion.attribute_statement[0])
        return ava
    
    def get_subject(self):
        """ The assertion must contain a Subject

        :param asynch: If the connection is asynchronous there is
            outstanding queries to connect to
        """
        assert self.assertion.subject
        subject = self.assertion.subject
        subjconf = []
        for subject_confirmation in subject.subject_confirmation:
            data = subject_confirmation.subject_confirmation_data
            if not data:
                # I don't know where this belongs so I ignore it
                continue
                
            if data.address:
                if not valid_address(data.address):
                    # ignore this subject_confirmation
                    continue
                    
            # These two will raise exception if untrue
            validate_on_or_after(data.not_on_or_after, self.timeslack)
            validate_before(data.not_before, self.timeslack)
            
            # not_before must be < not_on_or_after
            if not time_util.later_than(data.not_on_or_after, data.not_before):
                continue
            
            if self.asynchop and not self.came_from:
                if data.in_response_to in self.outstanding_queries:
                    self.came_from = self.outstanding_queries[
                                                        data.in_response_to]
                    del self.outstanding_queries[data.in_response_to]
                else:
                    # This is where I don't allow unsolicited reponses
                    # Either in_response_to == None or has a value I don't
                    # recognize
                    if self.debug and self.log:
                        self.log.info(
                                "in response to: '%s'" % data.in_response_to)
                        self.log.info("outstanding queries: %s" % \
                                            self.outstanding_queries.keys())
                    raise Exception(
                    "Combination of session id and requestURI I don't recall")
                        
            subjconf.append(subject_confirmation)
            
        if not subjconf:
            raise Exception("No valid subject confirmation")
            
        subject.subject_confirmation = subjconf
        
        # The subject must contain a name_id
        assert subject.name_id
        self.name_id = subject.name_id.text.strip()
        return self.name_id
    
    def _assertion(self, assertion):
        self.assertion = assertion
        
        if self.debug and self.log:
            self.log.info("assertion context: %s" % (self.context,))
            self.log.info("assertion keys: %s" % (assertion.keyswv()))
            self.log.info("outstanding_queries: %s" % (
                                                    self.outstanding_queries,))
        
        if self.context == "AuthnReq":
            self.authn_statement_ok()
        
        if not self.condition_ok():
            return None
        
        if self.debug and self.log:
            self.log.info("--- Getting Identity ---")
        
        self.ava = self.get_identity()
        
        if self.debug and self.log:
            self.log.info("--- AVA: %s" % (self.ava,))
        
        try:
            self.get_subject()
            if self.asynchop and not self.came_from:
                return False
            else:
                return True
        except Exception:
            return False
    
    def _encrypted_assertion(self, xmlstr):
        decrypt_xml = self.sec.decrypt(xmlstr)
        
        if self.debug and self.log:
            self.log.info("Decryption successfull")
        
        self.response = samlp.response_from_string(decrypt_xml)
        if self.debug and self.log:
            self.log.info("Parsed decrypted assertion successfull")
        
        enc = self.response.encrypted_assertion[0].extension_elements[0]
        assertion = extension_element_to_element(enc,
                                                saml.ELEMENT_FROM_STRING,
                                                namespace=saml.NAMESPACE)
        if self.debug and self.log:
            self.log.info("Decrypted Assertion: %s" % assertion)
        return self._assertion(assertion)
    
    def parse_assertion(self):
        try:
            assert len(self.response.assertion) == 1 or \
                    len(self.response.encrypted_assertion) == 1
        except AssertionError:
            raise Exception("No assertion part")
        
        if self.response.assertion:
            if self.debug and self.log:
                self.log.info("***Unencrypted response***")
            return self._assertion(self.response.assertion[0])
        else:
            if self.debug and self.log:
                self.log.info("***Encrypted response***")
            return self._encrypted_assertion(
                                        self.response.encrypted_assertion[0])
        

    def verify(self):
        """ Verify that the assertion is syntactically correct and
        the signature is correct if present."""
        
        try:
            self._verify()
        except AssertionError:
            return None
        
        if self.parse_assertion():
            return self
        else:
            return None
        
    def session_id(self):
        """ Returns the SessionID of the response """ 
        return self.response.in_response_to
    
    def id(self):
        """ Return the ID of the response """
        return self.response.id
    
    def authn_info(self):
        res = []
        for astat in self.assertion.authn_statement:
            context = astat.authn_context
            if context:
                aclass = context.authn_context_class_ref.text
                try:
                    authn_auth = [
                            a.text for a in context.authenticating_authority]
                except AttributeError:
                    authn_auth = []
                res.append((aclass, authn_auth))
        return res
        
    def session_info(self):
        """ Returns a predefined set of information gleened from the 
        response.
        :returns: Dictionary with information
        """
        if self.session_not_on_or_after > 0:
            nooa = self.session_not_on_or_after
        else:
            nooa = self.not_on_or_after
            
        return { "ava": self.ava, "name_id": self.name_id,
                "came_from": self.came_from, "issuer": self.issuer(),
                "not_on_or_after": nooa,
                "authn_info": self.authn_info() }
    
    def __str__(self):
        return "%s" % self.xmlstr

class AttributeResponse(AuthnResponse):
    def __init__(self, sec_context, attribute_converters, entity_id,
                    return_addr=None, log=None, timeslack=0, debug=0,
                    asynchop=True):
        AuthnResponse.__init__(self, sec_context, return_addr, log, timeslack,
                                debug, asynchop)
        self.entity_id = entity_id
        self.attribute_converters = attribute_converters
        self.assertion = None
        self.context = "AttrQuery"

def response_factory(xmlstr, conf, return_addr=None,
                        outstanding_queries=None, log=None, 
                        timeslack=0, debug=0, decode=True, request_id=0,
                        origxml=None):
    sec_context = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf.accepted_time_diff)
        except TypeError:
            timeslack = 0
            
    attribute_converters = conf.attribute_converters
    entity_id = conf.entityid

    response = StatusResponse(sec_context, return_addr, log, timeslack, 
                                        debug, request_id)
    try:
        response.loads(xmlstr, decode, origxml)
        if response.response.assertion:
            authnresp = AuthnResponse(sec_context, attribute_converters, 
                            entity_id, return_addr, outstanding_queries, log,
                            timeslack, debug)
            authnresp.update(response)
            return authnresp
    except TypeError:
        response.signature_check = sec_context.correctly_signed_logout_response
        response.loads(xmlstr, decode, origxml)
        logoutresp = LogoutResponse(sec_context, return_addr, log, 
                                        timeslack, debug)
        logoutresp.update(response)
        return logoutresp
        
    return response
