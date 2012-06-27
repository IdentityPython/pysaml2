#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2011 Umeå University
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
import logging

from saml2 import samlp
from saml2 import saml
from saml2 import extension_element_to_element
from saml2 import time_util

from saml2.saml import attribute_from_string
from saml2.saml import encrypted_attribute_from_string
from saml2.sigver import security_context
from saml2.sigver import SignatureError
from saml2.sigver import signed
from saml2.attribute_converter import to_local
from saml2.time_util import str_to_time

from saml2.validate import validate_on_or_after
from saml2.validate import validate_before
from saml2.validate import valid_instance
from saml2.validate import valid_address
from saml2.validate import NotValid

logger = logging.getLogger(__name__)

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

def authn_response(conf, return_addr, outstanding_queries=None, timeslack=0,
                   asynchop=True, allow_unsolicited=False):
    sec = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf.accepted_time_diff)
        except TypeError:
            timeslack = 0
    
    return AuthnResponse(sec, conf.attribute_converters, conf.entityid,
                        return_addr, outstanding_queries, timeslack,
                        asynchop=asynchop, allow_unsolicited=allow_unsolicited)

# comes in over SOAP so synchronous
def attribute_response(conf, return_addr, timeslack=0, asynchop=False,
                       test=False):
    sec = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf.accepted_time_diff)
        except TypeError:
            timeslack = 0

    return AttributeResponse(sec, conf.attribute_converters, conf.entityid,
                                return_addr, timeslack, asynchop=asynchop,
                                test=test)

class StatusResponse(object):
    def __init__(self, sec_context, return_addr=None, timeslack=0,
                 request_id=0):
        self.sec = sec_context
        self.return_addr = return_addr

        self.timeslack = timeslack
        self.request_id = request_id

        self.xmlstr = ""
        self.name_id = ""
        self.response = None
        self.not_on_or_after = 0
        self.in_response_to = None
        self.signature_check = self.sec.correctly_signed_response
        self.not_signed = False
    
    def _clear(self):
        self.xmlstr = ""
        self.name_id = ""
        self.response = None
        self.not_on_or_after = 0
        
    def _postamble(self):
        if not self.response:
            logger.error("Response was not correctly signed")
            if self.xmlstr:
                logger.info(self.xmlstr)
            raise IncorrectlySigned()

        logger.debug("response: %s" % (self.response,))

        try:
            valid_instance(self.response)
        except NotValid, exc:
            logger.error("Not valid response: %s" % exc.args[0])
            self._clear()
            return self
        
        self.in_response_to = self.response.in_response_to
        return self
        
    def load_instance(self, instance):
        if signed(instance):
            # This will check signature on Assertion which is the default
            try:
                self.response = self.sec.check_signature(instance)
            except SignatureError: # The response as a whole might be signed or not
                self.response = self.sec.check_signature(instance,
                                                    samlp.NAMESPACE+":Response")
        else:
            self.not_signed = True
            self.response = instance
            
        return self._postamble()
        
    def _loads(self, xmldata, decode=True, origxml=None):
        if decode:
            decoded_xml = base64.b64decode(xmldata)
        else:
            decoded_xml = xmldata
    
        # own copy
        self.xmlstr = decoded_xml[:]
        logger.debug("xmlstr: %s" % (self.xmlstr,))
#            fil = open("response.xml", "w")
#            fil.write(self.xmlstr)
#            fil.close()

        try:
            self.response = self.signature_check(decoded_xml, origdoc=origxml)
        except TypeError:
            raise
        except SignatureError:
            raise
        except Exception, excp:
            logger.exception("EXCEPTION: %s", excp)
    
        #print "<", self.response
        
        return self._postamble()
    
    def status_ok(self):
        if self.response.status:
            status = self.response.status
            logger.info("status: %s" % (status,))
            if status.status_code.value != samlp.STATUS_SUCCESS:
                logger.info("Not successful operation: %s" % status)
                raise Exception("Not successful according to: %s" % (
                                                    status.status_code.value,))
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
        return lower < issued_at < upper

    def _verify(self):
        if self.request_id and self.in_response_to and \
            self.in_response_to != self.request_id:
            logger.error("Not the id I expected: %s != %s" % (
                                                        self.in_response_to,
                                                        self.request_id))
            return None
            
        assert self.response.version == "2.0"
        if self.response.destination and \
            self.response.destination != self.return_addr:
            logger.error("%s != %s" % (self.response.destination,
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
            logger.exception("verify")
            return None

    def update(self, mold):
        self.xmlstr = mold.xmlstr
        self.in_response_to = mold.in_response_to
        self.response = mold.response
        
    def issuer(self):
        return self.response.issuer.text.strip()
        
class LogoutResponse(StatusResponse):
    def __init__(self, sec_context, return_addr=None, timeslack=0):
        StatusResponse.__init__(self, sec_context, return_addr, timeslack)
        self.signature_check = self.sec.correctly_signed_logout_response

class AuthnResponse(StatusResponse):
    """ This is where all the profile compliance is checked.
    This one does saml2int compliance. """
    
    def __init__(self, sec_context, attribute_converters, entity_id, 
                    return_addr=None, outstanding_queries=None,
                    timeslack=0, asynchop=True, allow_unsolicited=False,
                    test=False):

        StatusResponse.__init__(self, sec_context, return_addr, timeslack)
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
        self.allow_unsolicited = allow_unsolicited
        self.test = test

    def loads(self, xmldata, decode=True, origxml=None):
        self._loads(xmldata, decode, origxml)
        
        if self.asynchop:
            if self.in_response_to in self.outstanding_queries:
                self.came_from = self.outstanding_queries[self.in_response_to]
                del self.outstanding_queries[self.in_response_to]
            elif self.allow_unsolicited:
                pass
            else:
                logger("Unsolicited response")
                raise Exception("Unsolicited response")
            
        return self
    
    def clear(self):
        self._clear()
        self.came_from = ""
        self.ava = None
        self.assertion = None
        
    def authn_statement_ok(self, optional=False):
        try:
            # the assertion MUST contain one AuthNStatement
            assert len(self.assertion.authn_statement) == 1
        except AssertionError:
            if optional:
                return True
            else:
                raise
            
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
        if self.test:
            lax = True
        assert self.assertion.conditions
        condition = self.assertion.conditions
        logger.debug("condition: %s" % condition)
        
        try:
            self.not_on_or_after = validate_on_or_after(
                                                    condition.not_on_or_after,
                                                    self.timeslack)
            validate_before(condition.not_before, self.timeslack)
        except Exception, excp:
            logger.error("Exception on condition: %s" % (excp,))
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

    def decrypt_attributes(self, attribute_statement):
        """
        Decrypts possible encrypted attributes and adds the decrypts to the
        list of attributes.

        :param attribute_statement: A SAML.AttributeStatement which might
            contain both encrypted attributes and attributes.
        """
#        _node_name = [
#            "urn:oasis:names:tc:SAML:2.0:assertion:EncryptedData",
#            "urn:oasis:names:tc:SAML:2.0:assertion:EncryptedAttribute"]

        for encattr in attribute_statement.encrypted_attribute:
            if not encattr.encrypted_key:
                _decr = self.sec.decrypt(encattr.encrypted_data)
                _attr = attribute_from_string(_decr)
                attribute_statement.attribute.append(_attr)
            else:
                _decr = self.sec.decrypt(encattr)
                enc_attr = encrypted_attribute_from_string(_decr)
                attrlist = enc_attr.extensions_as_elements("Attribute", saml)
                attribute_statement.attribute.extend(attrlist)

    def get_identity(self):
        """ The assertion can contain zero or one attributeStatements

        """
        if not self.assertion.attribute_statement:
            logger.error("Missing Attribute Statement")
            ava = {}
        else:
            assert len(self.assertion.attribute_statement) == 1
            _attr_statem = self.assertion.attribute_statement[0]

            logger.debug("Attribute Statement: %s" % (_attr_statem,))
            for aconv in self.attribute_converters:
                logger.info("Converts name format: %s" % (aconv.name_format,))

            self.decrypt_attributes(_attr_statem)
            ava = to_local(self.attribute_converters, _attr_statem)
        return ava
    
    def get_subject(self):
        """ The assertion must contain a Subject
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
                elif self.allow_unsolicited:
                    pass
                else:
                    # This is where I don't allow unsolicited reponses
                    # Either in_response_to == None or has a value I don't
                    # recognize
                    logger.debug("in response to: '%s'" % data.in_response_to)
                    logger.info("outstanding queries: %s" % (
                                            self.outstanding_queries.keys(),))
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

        logger.debug("assertion context: %s" % (self.context,))
        logger.debug("assertion keys: %s" % (assertion.keyswv()))
        logger.debug("outstanding_queries: %s" % (self.outstanding_queries,))
        
        #if self.context == "AuthnReq" or self.context == "AttrQuery":
        if self.context == "AuthnReq":
            self.authn_statement_ok()
#        elif self.context == "AttrQuery":
#            self.authn_statement_ok(True)

        if not self.condition_ok():
            return None

        logger.debug("--- Getting Identity ---")

        if self.context == "AuthnReq" or self.context == "AttrQuery":
            self.ava = self.get_identity()

            logger.debug("--- AVA: %s" % (self.ava,))
        
        try:
            self.get_subject()
            if self.asynchop:
                if self.allow_unsolicited:
                    pass
                elif not self.came_from:
                    return False
            return True
        except Exception, exc:
            logger.exception("get subject")
            return False
    
    def _encrypted_assertion(self, xmlstr):
        if xmlstr.encrypted_data:
            assertion_str = self.sec.decrypt(xmlstr.encrypted_data)
            assertion = saml.assertion_from_string(assertion_str)
        else:
            decrypt_xml = self.sec.decrypt(xmlstr)

            logger.debug("Decryption successfull")

            self.response = samlp.response_from_string(decrypt_xml)
            logger.debug("Parsed decrypted assertion successfull")

            enc = self.response.encrypted_assertion[0].extension_elements[0]
            assertion = extension_element_to_element(enc,
                                                    saml.ELEMENT_FROM_STRING,
                                                    namespace=saml.NAMESPACE)

        logger.debug("Decrypted Assertion: %s" % assertion)
        return self._assertion(assertion)
    
    def parse_assertion(self):
        try:
            assert len(self.response.assertion) == 1 or \
                    len(self.response.encrypted_assertion) == 1
        except AssertionError:
            raise Exception("No assertion part")
        
        if self.response.assertion:
            logger.debug("***Unencrypted response***")
            return self._assertion(self.response.assertion[0])
        else:
            logger.debug("***Encrypted response***")
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
            logger.error("Could not parse the assertion")
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

    def authz_decision_info(self):
        res = {"permit":[], "deny": [], "indeterminate":[] }
        for adstat in self.assertion.authz_decision_statement:
            # one of 'Permit', 'Deny', 'Indeterminate'
            res[adstat.decision.text.lower()] = adstat
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

        if self.context == "AuthzQuery":
            return {"name_id": self.name_id,
                    "came_from": self.came_from, "issuer": self.issuer(),
                    "not_on_or_after": nooa,
                    "authz_decision_info": self.authz_decision_info() }
        else:
            return { "ava": self.ava, "name_id": self.name_id,
                    "came_from": self.came_from, "issuer": self.issuer(),
                    "not_on_or_after": nooa,
                    "authn_info": self.authn_info() }
    
    def __str__(self):
        return "%s" % self.xmlstr

class AttributeResponse(AuthnResponse):
    def __init__(self, sec_context, attribute_converters, entity_id,
                    return_addr=None, timeslack=0, asynchop=False, test=False):

        AuthnResponse.__init__(self, sec_context, attribute_converters,
                                entity_id, return_addr, timeslack=timeslack,
                                asynchop=asynchop, test=test)
        self.entity_id = entity_id
        self.attribute_converters = attribute_converters
        self.assertion = None
        self.context = "AttrQuery"

class AuthzResponse(AuthnResponse):
    """ A successful response will be in the form of assertions containing
    authorization decision statements."""
    def __init__(self, sec_context, attribute_converters, entity_id,
                    return_addr=None, timeslack=0, asynchop=False):
        AuthnResponse.__init__(self, sec_context, attribute_converters,
                                entity_id, return_addr,
                                timeslack=timeslack, asynchop=asynchop)
        self.entity_id = entity_id
        self.attribute_converters = attribute_converters
        self.assertion = None
        self.context = "AuthzQuery"

def response_factory(xmlstr, conf, return_addr=None,
                        outstanding_queries=None,
                        timeslack=0, decode=True, request_id=0,
                        origxml=None, asynchop=True, allow_unsolicited=False):
    sec_context = security_context(conf)
    if not timeslack:
        try:
            timeslack = int(conf.accepted_time_diff)
        except TypeError:
            timeslack = 0
            
    attribute_converters = conf.attribute_converters
    entity_id = conf.entityid

    response = StatusResponse(sec_context, return_addr, timeslack, request_id)
    try:
        response.loads(xmlstr, decode, origxml)
        if response.response.assertion or response.response.encrypted_assertion:
            authnresp = AuthnResponse(sec_context, attribute_converters, 
                            entity_id, return_addr, outstanding_queries,
                            timeslack, asynchop, allow_unsolicited)
            authnresp.update(response)
            return authnresp
    except TypeError:
        response.signature_check = sec_context.correctly_signed_logout_response
        response.loads(xmlstr, decode, origxml)
        logoutresp = LogoutResponse(sec_context, return_addr, timeslack)
        logoutresp.update(response)
        return logoutresp
        
    return response
