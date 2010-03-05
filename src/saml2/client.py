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

"""Contains classes and functions that a SAML2.0 Service Provider (SP) may use
to conclude its tasks.
"""
import os
import urllib
import saml2
import base64
import time
import sys
from saml2.time_util import str_to_time, instant
from saml2.utils import sid, deflate_and_base64_encode, make_instance
from saml2.utils import kd_name_id, kd_subject, do_attributes

from saml2 import samlp, saml, extension_element_to_element
from saml2 import VERSION, class_name
from saml2.sigver import correctly_signed_response, decrypt
from saml2.sigver import pre_signature_part, sign_assertion_using_xmlsec
from saml2.sigver import sign_statement_using_xmlsec
from saml2.soap import SOAPClient

DEFAULT_BINDING = saml2.BINDING_HTTP_REDIRECT

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""

LAX = False

SESSION_INFO = {"ava":{}, "came from":"", "not_on_or_after":0,
                    "issuer":"", "session_id":-1}


def _use_on_or_after(condition, slack):
    now = time.mktime(time.gmtime())
    not_on_or_after = time.mktime(str_to_time(condition.not_on_or_after))
    if not_on_or_after < now + slack:
        # To old ignore
        raise Exception("To old can't use it")
    return not_on_or_after

def _use_before(condition, slack):
    not_before = time.mktime(str_to_time(condition.not_before))
    now = time.mktime(time.gmtime())
        
    if not_before > now + slack:
        # Can't use it yet
        raise Exception("Can't use it yet %s <= %s" % (not_before, now))
    
    return True

class Saml2Client(object):
    """ The basic pySAML2 service provider class """
    
    def __init__(self, environ, config=None):
        """
        :param environ:
        :param config: A saml2.config.Config instance
        """
        self.environ = environ
        if config:
            self.config = config
            if "metadata" in config:
                self.metadata = config["metadata"]

    def _init_request(self, request, destination):
        #request.id = sid()
        request.version = VERSION
        request.issue_instant = instant()
        request.destination = destination
        return request        

    def idp_entry(self, name=None, location=None, provider_id=None):
        res = {}
        if name: 
            res["name"] = name
        if location: 
            res["loc"] = location
        if provider_id: 
            res["provider_id"] = provider_id
        if res:
            return res
        else:
            return None
        
    def scoping(self, idp_ents):
        return {
            "idp_list": {
                "idp_entry": idp_ents
            }
        }

    def scoping_from_metadata(self, entityid, location):
        name = self.metadata.name(entityid)
        return make_instance(self.scoping([self.idp_entry(name, location)]))
                           
    def response(self, post, requestor, outstanding, log=None):
        """ Deal with the AuthnResponse
        
        :param post: The reply as a cgi.FieldStorage instance
        :param requestor: The issuer of the AuthN request
        :param outstanding: A dictionary with session IDs as keys and 
            the original web request from the user before redirection
            as values.
        :param log: where loggin should go.
        :return: A 2-tuple of identity information (in the form of a 
            dictionary) and where the user should really be sent. This
            might differ from what the IdP thinks since I don't want
            to reveal verything to it and it might not trust me.
        """
        # If the request contains a samlResponse, try to validate it
        if post.has_key("SAMLResponse"):
            saml_response =  post['SAMLResponse'].value
            if saml_response:
                return self.verify_response(saml_response, requestor, 
                                            outstanding, log, 
                                            context="AuthNReq")
        return None
            
    def authn_request(self, query_id, destination, service_url, spentityid, 
                        my_name, vorg="", scoping=None, log=None, sign=False):
        """ Creates an authentication request.
        
        :param query_id: The identifier for this request
        :param destination: Where the request should be sent.
        :param service_url: Where the reply should be sent.
        :param spentityid: The entity identifier for this service.
        :param my_name: The name of this service.
        :param vorg: The vitual organization the service belongs to.
        :param scoping: The scope of the request
        :param log: A service to which logs should be written
        :param sign: Whether the request should be signed or not.
        """
        prel = {
            "id": query_id,
            "version": VERSION,
            "issue_instant": instant(),
            "destination": destination,
            "assertion_consumer_service_url": service_url,
            "protocol_binding": saml2.BINDING_HTTP_POST,
            "provider_name": my_name,
        }
        
        if scoping:
            prel["scoping"] = scoping
            
        name_id_policy = {
            "allow_create": "true"
        }
        
        name_id_policy["format"] = saml.NAMEID_FORMAT_TRANSIENT
        if vorg:
            try:
                name_id_policy["sp_name_qualifier"] = vorg
                name_id_policy["format"] = saml.NAMEID_FORMAT_PERSISTENT
            except KeyError:
                pass
        
        if sign:
            prel["signature"] = pre_signature_part(prel["id"])

        prel["name_id_policy"] = name_id_policy
        prel["issuer"] = { "text": spentityid }
        
        if log:
            log.info("DICT VERSION: %s" % prel)
            
        request = make_instance(samlp.AuthnRequest, prel)
        if sign:
            return sign_statement_using_xmlsec("%s" % request, class_name(request),
                                    self.config["xmlsec_binary"], 
                                    key_file=self.config["key_file"])
            #return samlp.authn_request_from_string(sreq)
        else:
            return "%s" % request

    def authenticate(self, spentityid, location="", service_url="", 
                        my_name="", relay_state="",
                        binding=saml2.BINDING_HTTP_REDIRECT, log=None,
                        vorg="", scoping=None):
        """ Either verifies an authentication Response or if none is present
        send an authentication request.
        
        :param spentityid: The SP EntityID
        :param binding: How the authentication request should be sent to the 
            IdP
        :param location: Where the IdP is.
        :param service_url: The SP's service URL
        :param my_name: The providers name
        :param relay_state: To where the user should be returned after 
            successfull log in.
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param vorg: The entity_id of the virtual organization I'm a member of
        :param scoping: For which IdPs this query are aimed.
            
        :return: AuthnRequest response
        """
        
        if log:
            log.info("spentityid: %s" % spentityid)
            log.info("location: %s" % location)
            log.info("service_url: %s" % service_url)
            log.info("my_name: %s" % my_name)
        session_id = sid()
        authen_req = self.authn_request(session_id, location, 
                                service_url, spentityid, my_name, vorg, 
                                scoping, log)
        log and log.info("AuthNReq: %s" % authen_req)
        
        if binding == saml2.BINDING_HTTP_POST:
            # No valid ticket; Send a form to the client
            # THIS IS NOT TO BE USED RIGHT NOW
            response = []
            response.append("<head>")
            response.append("""<title>SAML 2.0 POST</title>""")
            response.append("</head><body>")
            #login_url = location + '?spentityid=' + "lingon.catalogix.se"
            response.append(FORM_SPEC % (location, base64.b64encode(authen_req),
                                os.environ['REQUEST_URI']))
            response.append("""<script type="text/javascript">""")
            response.append("     window.onload = function ()")
            response.append(" { document.forms[0].submit(); ")
            response.append("""</script>""")
            response.append("</body>")
        elif binding == saml2.BINDING_HTTP_REDIRECT:
            lista = ["SAMLRequest=%s" % urllib.quote_plus(
                                deflate_and_base64_encode(
                                    authen_req)),
                    "spentityid=%s" % spentityid]
            if relay_state:
                lista.append("RelayState=%s" % relay_state)
            login_url = "?".join([location, "&".join(lista)])
            response = ('Location', login_url)
        else:
            raise Exception("Unkown binding type: %s" % binding)
        return (session_id, response)
            
    def verify_response(self, xml_response, requestor, outstanding=None, 
                log=None, decode=True, context="", lax=False):
        """ Verify a response
        
        :param xml_response: The response as a XML string
        :param requestor: The hostname of the machine
        :param outstanding: A collection of outstanding authentication requests
        :param log: Where logging information should be sent
        :param decode: There for testing purposes
        :param lax: Accept things you normally shouldn't
        :return: A 2-tuple consisting of an identity description and the 
            real relay-state
        """
        
        if not outstanding:
            outstanding = {}
        
        if decode:
            decoded_xml = base64.b64decode(xml_response)
        else:
            decoded_xml = xml_response
        
        # own copy
        xmlstr = decoded_xml[:]
        log and log.info("verify correct signature")
        response = correctly_signed_response(decoded_xml, 
                        self.config["xmlsec_binary"], log=log)
        if not response:
            if log:
                log.error("Response was not correctly signed")
                log.info(decoded_xml)
            return None
        else:
            log and log.error("Response was correctly signed or nor signed")
            
        log and log.info("response: %s" % (response,))
        try:
            session_info = self.do_response(response, 
                                                requestor, 
                                                outstanding=outstanding, 
                                                xmlstr=xmlstr, 
                                                log=log, context=context,
                                                lax=lax)
            session_info["issuer"] = response.issuer.text
            session_info["session_id"] = response.in_response_to
        except AttributeError, exc:
            if log:
                log.error("AttributeError: %s" % (exc,))
            else:
                print >> sys.stderr, "AttributeError: %s" % (exc,)
            return None
        except Exception, exc:
            if log:
                log.error("Exception: %s" % (exc,))
            else:
                print >> sys.stderr, "Exception: %s" % (exc,)
            return None
                                    
        session_info["ava"]["__userid"] = session_info["name_id"]
        return session_info
          
    def _verify_condition(self, assertion, requestor, log, lax=False, 
                            slack=0):
        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert assertion.conditions
        condition = assertion.conditions
        log and log.info("condition: %s" % condition)

        try:
            slack = self.config["accept_time_diff"]
        except KeyError:
            slack = 0

        not_on_or_after = _use_on_or_after(condition, slack)
        _use_before(condition, slack)
        
        if not for_me(condition, requestor):
            if not LAX and not lax:
                raise Exception("Not for me!!!")
        
        return not_on_or_after
        
    def _websso(self, assertion, _outstanding, _requestor, _log=None):
        # the assertion MUST contain one AuthNStatement
        assert len(assertion.authn_statement) == 1
        # authn_statement = assertion.authn_statement[0]
        # check authn_statement.session_index
        
        
    def _assertion(self, assertion, outstanding, requestor, log, context, 
                    lax):
        if log:
            log.info("assertion context: %s" % (context,))
            log.info("assertion keys: %s" % (assertion.keyswv()))
            log.info("outstanding: %s" % (outstanding))
        
        if context == "AuthNReq":
            self._websso(assertion, outstanding, requestor, log)

        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert assertion.conditions
        log and log.info("verify_condition")
        not_on_or_after = self._verify_condition(assertion, requestor, log, 
                                                lax)

        # The assertion can contain zero or one attributeStatements
        assert len(assertion.attribute_statement) <= 1
        if assertion.attribute_statement:
            ava = get_attribute_values(assertion.attribute_statement[0])
        else:
            ava = {}

        log and log.info("AVA: %s" % (ava,))

        # The assertion must contain a Subject
        assert assertion.subject
        subject = assertion.subject
        for subject_confirmation in subject.subject_confirmation:
            data = subject_confirmation.subject_confirmation_data
            if data.in_response_to in outstanding:
                came_from = outstanding[data.in_response_to]
                del outstanding[data.in_response_to]
            elif LAX:
                came_from = ""
            else:
                print data.in_response_to, outstanding.keys()
                raise Exception(
                    "Combination of session id and requestURI I don't recall")
        
        # The subject must contain a name_id
        assert subject.name_id
        name_id = subject.name_id.text.strip()
        
        return {"ava":ava, "name_id":name_id, "came_from":came_from,
                 "not_on_or_after":not_on_or_after}

    def _encrypted_assertion(self, xmlstr, outstanding, requestor, 
            log=None, context=""):
        log and log.debug("Decrypt message")        
        decrypt_xml = decrypt(xmlstr, self.config["key_file"],
                                self.config["xmlsec_binary"], log=log)
        log and log.debug("Decryption successfull")
        
        response = samlp.response_from_string(decrypt_xml)
        log and log.debug("Parsed decrypted assertion successfull")
        
        enc = response.encrypted_assertion[0].extension_elements[0]            
        assertion = extension_element_to_element(
                        enc, 
                        saml.ELEMENT_FROM_STRING,
                        namespace=saml.NAMESPACE)
        log and log.info("Decrypted Assertion: %s" % assertion)
        return self._assertion(assertion, outstanding, requestor, log,
                                context)
        
    def do_response(self, response, requestor, outstanding=None, 
                        xmlstr="", log=None, context="", lax=False):
        """
        Parse a response, verify that it is a response for me and
        expected by me and that it is correct.

        :param response: The response as a structure
        :param requestor: The host (me) that asked for a AuthN response
        :param outstanding: A dictionary with session ids as keys and request 
            URIs as values.
        :param lax: Accept things you normally shouldn't
        :result: A 2-tuple with attribute value assertions as a dictionary 
            as one part and the NameID as the other.
        """

        if not outstanding:
            outstanding = {}

        if response.status:
            status = response.status
            if status.status_code.value != samlp.STATUS_SUCCESS:
                log and log.info("Not successfull operation: %s" % status)
                raise Exception(
                    "Not successfull according to: %s" % \
                    status.status_code.value)

        # MUST contain *one* assertion
        try:
            assert len(response.assertion) == 1 or \
                    len(response.encrypted_assertion) == 1
        except AssertionError:
            raise Exception("No assertion part")

        if response.assertion:         
            log and log.info("***Unencrypted response***")
            return self._assertion(response.assertion[0], outstanding, 
                                    requestor, log, context, lax)
        else:
            log and log.info("***Encrypted response***")
            return self._encrypted_assertion(xmlstr, outstanding, 
                                                requestor, log, context)

    def create_attribute_query(self, session_id, subject_id, issuer, 
            destination, attribute=None, sp_name_qualifier=None, 
            name_qualifier=None, nameformat=None, sign=False):
        """ Constructs an AttributeQuery 
        
        :param subject_id: The identifier of the subject
        :param destination: To whom the query should be sent
        :param attribute: A dictionary of attributes and values that is 
            asked for. The key are one of 4 variants:
            3-tuple of name_format,name and friendly_name,
            2-tuple of name_format and name,
            1-tuple with name or 
            just the name as a string.
        :param sp_name_qualifier: The unique identifier of the 
            service provider or affiliation of providers for whom the 
            identifier was generated.
        :param name_qualifier: The unique identifier of the identity 
            provider that generated the identifier.
        :return: An AttributeQuery instance
        """

    
        subject = kd_subject(
                    name_id = kd_name_id(subject_id, format=nameformat,
                                sp_name_qualifier=sp_name_qualifier,
                                name_qualifier=name_qualifier),
                    )
        
        prequery = {
            "id": session_id,
            "version": VERSION,
            "issue_instant": instant(),
            "destination": destination,
            "issuer": issuer,
            "subject":subject,
        }
        
        if sign:
            prequery["signature"] = pre_signature_part(prequery["id"])
        
        if attribute:
            prequery["attribute"] = do_attributes(attribute)
            
        request = make_instance(samlp.AttributeQuery, prequery)
        if sign:
            signed_req = sign_assertion_using_xmlsec("%s" % request, 
                                    self.config["xmlsec_binary"], 
                                    key_file=self.config["key_file"])
            return samlp.attribute_query_from_string(signed_req)

        else:
            return request

            
    def attribute_query(self, subject_id, issuer, destination, 
                attribute=None, sp_name_qualifier=None, name_qualifier=None, 
                format=None, log=None):
        """ Does a attribute request from an attribute authority

        :param subject_id: The identifier of the subject
        :param destination: To whom the query should be sent
        :param attribute: A dictionary of attributes and values that is asked for
        :param sp_name_qualifier: The unique identifier of the 
            service provider or affiliation of providers for whom the 
            identifier was generated.
        :param name_qualifier: The unique identifier of the identity 
            provider that generated the identifier.
        :return: The attributes returned
        """
        
        session_id = sid()
        request = self.create_attribute_query(session_id, subject_id, 
                    issuer, destination, attribute, sp_name_qualifier, 
                    name_qualifier, nameformat=format)
        
        log and log.info("Request, created: %s" % request)
        
        soapclient = SOAPClient(destination, self.config["key_file"], 
                                self.config["cert_file"])
        log and log.info("SOAP client initiated")
        try:
            response = soapclient.send(request)
        except Exception, exc:
            log and log.info("SoapClient exception: %s" % (exc,))
            return None

        log and log.info("SOAP request sent and got response: %s" % response)
        if response:
            log and log.info("Verifying response")
            session_info = self.verify_response(response, 
                                                issuer,
                                                outstanding={session_id:""}, 
                                                log=log, decode=False,
                                                context="AttrReq")
            log and log.info("session: %s" % session_info)
            return session_info
        else:
            log and log.info("No response")
            return None
        
    def make_logout_request(self, session_id, destination, issuer,
                reason=None, not_on_or_after=None):
        """ Constructs a LogoutRequest

        :param subject_id: The identifier of the subject
        :param reason: An indication of the reason for the logout, in the 
            form of a URI reference.
        :param not_on_or_after: The time at which the request expires, 
            after which the recipient may discard the message.
        :return: An AttributeQuery instance
        """

        prel = {
            "id": sid(),
            "version": VERSION,
            "issue_instant": instant(),
            "destination": destination,
            "issuer": issuer,
            "session_index": session_id,
        }
    
        if reason:
            prel["reason"] = reason
            
        if not_on_or_after:
            prel["not_on_or_after"] = not_on_or_after
            
        return make_instance(samlp.LogoutRequest, prel)
        
    def logout(self, session_id, destination,
                    issuer, reason="", not_on_or_after=None):        
        return self.make_logout_request(session_id, destination,
                    issuer, reason, not_on_or_after)
        
    
# ----------------------------------------------------------------------

def for_me(condition, myself ):
    for restriction in condition.audience_restriction:
        audience = restriction.audience
        if audience.text.strip() == myself:
            return True

def get_attribute_values(attribute_statement):
    """ Get the attributes and the attribute values 
    
    :param response: The AttributeStatement.
    :return: A dictionary containing attributes and values
    """
    
    result = {}
    for attribute in attribute_statement.attribute:
        # Check name_format ??
        try:
            name = attribute.friendly_name.strip()
        except AttributeError:
            name = attribute.name.strip()
        result[name] = []
        for value in attribute.attribute_value:
            result[name].append(value.text.strip())
    return result

ROW = """<tr><td>%s</td><td>%s</td></tr>"""

def _print_statement(statem):
    """ Print a statement as a HTML table """
    txt = ["""<table border="1">"""]
    for key, val in statem.__dict__.items():
        if key.startswith("_"):
            continue
        else:
            if isinstance(val, basestring):
                txt.append(ROW % (key, val))
            elif isinstance(val, list):
                for value in val:
                    if isinstance(val, basestring):
                        txt.append(ROW % (key, val))
                    elif isinstance(value, saml2.SamlBase):
                        txt.append(ROW % (key, _print_statement(value)))
            elif isinstance(val, saml2.SamlBase):
                txt.append(ROW % (key, _print_statement(val)))
            else:
                txt.append(ROW % (key, val))
                
    txt.append("</table>")
    return "\n".join(txt)

def _print_statements(states):
    """ Print a list statement as HTML tables """
    txt = []
    for stat in states:
        txt.append(_print_statement(stat))
    return "\n".join(txt)

def print_response(resp):
    print _print_statement(resp)
    print resp.to_string()
    