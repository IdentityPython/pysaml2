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
import re
from saml2.time_util import str_to_time, add_duration, instant
from saml2.utils import sid, deflate_and_base64_encode

from saml2 import samlp, saml, extension_element_to_element
from saml2.sigver import correctly_signed_response, decrypt
from saml2.soap import SOAPClient

DEFAULT_BINDING = saml2.BINDING_HTTP_REDIRECT

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""

LAX = True
    
class Saml2Client:
    
    def __init__(self, environ, session=None, service_url=None, metadata=None,
                    xmlsec_binary=None, key_file=None, cert_file=None):
        self.session = session or {}
        self.environ = environ
        self.metadata = metadata
        self.xmlsec_binary = xmlsec_binary
        self.key_file = key_file
        self.cert_file = cert_file

    def _init_request(self, request, destination):
        #request.id = sid()
        request.version = "2.0"
        request.issue_instant = instant()
        request.destination = destination
        return request        

    def create_authn_request(self, query_id, destination, service_url,
                                spentityid, my_name, sp_name_qualifier=None):
        """ Creates an Authenication Request
        
        :param query_id: Query identifier
        :param destination: Where to send the request
        :param service_url: The page to where the response MUST be sent.
        :param spentityid: My official name
        :param my_name: Who I am
        :param sp_name_qualifier: The domain in which the name should be
            valid
        
        :return: An authentication request
        """
        
        authn_request = self._init_request(samlp.AuthnRequest(query_id),
                                            destination)

        authn_request.assertion_consumer_service_url = service_url
        authn_request.protocol_binding = saml2.BINDING_HTTP_POST
        authn_request.provider_name = my_name

        name_id_policy = samlp.NameIDPolicy()
        name_id_policy.allow_create = 'true'
        if sp_name_qualifier:
            name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
            name_id_policy.sp_name_qualifier = sp_name_qualifier
        else:
            name_id_policy.format = saml.NAMEID_FORMAT_TRANSIENT


        authn_request.name_id_policy = name_id_policy
        authn_request.issuer = saml.Issuer(text=spentityid)
        
        return authn_request
                   
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
                (identity, came_from) = self.verify_response(
                                            saml_response, requestor, 
                                            outstanding, log, 
                                            context="AuthNReq")
            #relay_state = post["RelayState"].value
            return (identity, came_from)
        else:
            return None
            
    def authenticate(self, spentityid, location="", service_url="", 
                        my_name="", relay_state="",
                        binding=saml2.BINDING_HTTP_REDIRECT, log=None):
        """ Either verifies an authentication Response or if none is present
        send an authentication request.
        
        :param spentityid: The SP EntityID
        :param binding: How the authentication request should be sent to the 
            IdP
        :param location: Where the IdP is.
        :param service_url: The service URL
        :param my_name: The providers name
        :param relay_state: To where the user should be returned after 
            successfull log in.
        :return: AuthnRequest reponse
        """
        
        if log:
            log.info("spentityid: %s" % spentityid)
            log.info("location: %s" % location)
            log.info("service_url: %s" % service_url)
            log.info("my_name: %s" % my_name)
        sid = sid()
        authen_req = "%s" % self.create_authn_request(sid, location, 
                                service_url, spentityid, my_name)
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
        return (sid, response)
            
    def verify_response(self, xml_response, requestor, outstanding=None, 
                log=None, decode=True, context=""):
        """ Verify a response
        
        :param xml_response: The response as a XML string
        :param requestor: The hostname of the machine
        :param outstanding: A collection of outstanding authentication requests
        :param log: Where logging information should be sent
        :param decode: There for testing purposes
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
        response = correctly_signed_response(decoded_xml, self.xmlsec_binary,
                        log=log)
        if not response:
            log and log.error("Response was not correctly signed")
            print "Response was not correctly signed"
            return ({}, "")
        else:
            log and log.error("Response was correctly signed or nor signed")
            
        log and log.info("response: %s" % (response,))
        try:
            (ava, name_id, came_from) = self.do_response(response, 
                                                requestor, 
                                                outstanding=outstanding, 
                                                xmlstr=xmlstr, 
                                                log=log, context=context)
        except AttributeError, exc:
            log and log.error("AttributeError: %s" % (exc,))
            return ({}, "")
        except Exception, exc:
            log and log.error("Exception: %s" % (exc,))
            return ({}, "")
                                    
        # should return userid and attribute value assertions
        ava["__userid"] = name_id
        return (ava, came_from)
  
    def _verify_condition(self, assertion, requestor):
            # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert assertion.conditions
        condition = assertion.conditions
        now = time.gmtime()        
        not_on_or_after = str_to_time(condition.not_on_or_after)        
        if not_on_or_after < now:
            # To old ignore
            if not LAX:
                raise Exception("To old can't use it")

        not_before = str_to_time(condition.not_before)        
        if not_before > now:
            # Can't use it yet
            if not LAX:
                raise Exception("Can't use it yet")

        if not for_me(condition, requestor):
            if not LAX:
                raise Exception("Not for me!!!")

    def _websso(self, assertion, outstanding, requestor, log):
        # the assertion MUST contain one AuthNStatement
        assert len(assertion.authn_statement) == 1
        # authn_statement = assertion.authn_statement[0]
        # check authn_statement.session_index
        
        
    def _assertion(self, assertion, outstanding, requestor, log, context):
        """ """        
        if context == "AuthNReq":
            self._websso(assertion, outstanding, requestor, log)

        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert assertion.conditions
        self._verify_condition(assertion, requestor)

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
                raise Exception(
                    "Combination of session id and requestURI I don't recall")
        
        # The subject must contain a name_id
        assert subject.name_id
        name_id = subject.name_id.text.strip()
        
        return (ava, name_id, came_from)

    def _encrypted_assertion(self, xmlstr, outstanding, requestor, 
            log=None, context=""):
        log and log.debug("Decrypt message")        
        decrypt_xml = decrypt(xmlstr, self.key_file, self.xmlsec_binary, 
                                log=log)
        log and log.debug("Decryption successfull")
        
        response = samlp.response_from_string(decrypt_xml)
        log and log.debug("Parsed decrypted assertion successfull")
        
        ee = response.encrypted_assertion[0].extension_elements[0]            
        assertion = extension_element_to_element(
                        ee, 
                        saml.ELEMENT_FROM_STRING,
                        namespace=saml.NAMESPACE)
        log and log.info("Decrypted Assertion: %s" % assertion)
        return self._assertion(assertion, outstanding, requestor, log,
                                context)
        
    def do_response(self, response, requestor, outstanding=None, 
                        xmlstr="", log=None, context=""):
        """
        Parse a response, verify that it is a response for me and
        expected by me and that it is correct.

        :param response: The response as a structure
        :param requestor: The host (me) that asked for a AuthN response
        :param outstanding: A dictionary with session ids as keys and request 
            URIs as values.
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
                
        if response.in_response_to:
            if response.in_response_to in outstanding:
                came_from = outstanding[response.in_response_to]
            elif LAX:
                came_from = ""
            else:
                log and log.info("Session id I don't recall using")
                raise Exception("Session id I don't recall using")

        # MUST contain *one* assertion
        try:
            assert len(response.assertion) == 1 or \
                    len(response.encrypted_assertion) == 1
        except AssertionError:
            raise Exception("No assertion part")

        if response.assertion:         
            log and log.info("***Unencrypted response***")
            return self._assertion(response.assertion[0], outstanding, 
                                    requestor, log, context)
        else:
            log and log.info("***Encrypted response***")
            return self._encrypted_assertion(xmlstr, outstanding, 
                                                requestor, log, context)

    def create_attribute_request(self, sid, subject_id, issuer, destination, 
            attribute=None, sp_name_qualifier=None, name_qualifier=None,
            format=None):
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
        
        attr_query = self._init_request(samlp.AttributeQuery(sid), 
                                        destination)
        
        subject = saml.Subject()
        name_id = saml.NameID()
        if format:
            name_id.format = format
        else:
            name_id.format = saml.NAMEID_FORMAT_PERSISTENT
        if name_qualifier:
            name_id.name_qualifier = name_qualifier
        if sp_name_qualifier:
            name_id.sp_name_qualifier = sp_name_qualifier
        name_id.text = subject_id
        subject.name_id = name_id
        
        attr_query.subject = subject
        attr_query.issuer = saml.Issuer(text=issuer)

        if attribute:
            attrs = []
            for attr_tup, values in attribute.items():
                format = friendly = ""
                if isinstance(attr_tup, tuple):
                    if len(attr_tup) == 3:
                        (format,name,friendly) = attr_tup
                    elif len(attr_tup) == 2:
                        (format,name) = attr_tup
                    elif len(attr_tup) == 1:
                        (name) = attr_tup
                elif isinstance(attr_tup, basestring):
                    name = attr_tup
                sattr = saml.Attribute()
                sattr.name = name
                if format:
                    sattr.name_format = format
                if friendly:
                    sattr.friendly_name = friendly

                if values:
                    aval = [saml.AttributeValue(text=val) for val in values]
                    sattr.attribute_value = aval
                attrs.append(sattr)
                    
            attr_query.attribute = attrs
        
        return attr_query
    
    def attribute_request(self, subject_id, issuer, destination, 
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
        
        sid = sid()
        request = self.create_attribute_request(sid, subject_id, issuer,
                    destination, attribute, sp_name_qualifier, name_qualifier,
                    format=format)
        
        log and log.info("Request, created: %s" % request)
        
        soapclient = SOAPClient(destination, self.key_file, self.cert_file)
        log and log.info("SOAP client initiated")
        try:
            response = soapclient.send(request)
        except Exception, e:
            log and log.info("SoapClient exception: %s" % (e,))
            return None

        log and log.info("SOAP request sent and got response: %s" % response)
        if response:
            log and log.info("Verifying response")
            (identity, came_from) = self.verify_response(response, 
                                                issuer,
                                                outstanding={sid:""}, 
                                                log=log, decode=False,
                                                context="AttrReq")
            log and log.info("identity: %s" % identity)
            return identity
        else:
            log and log.info("No response")
            return None
        
    def make_logout_request(self, subject_id, reason=None, 
                not_on_or_after=None):
        """ Constructs an LogoutRequest

        :param subject_id: The identifier of the subject
        :param reason: An indication of the reason for the logout, in the 
            form of a URI reference.
        :param not_on_or_after: The time at which the request expires, 
            after which the recipient may discard the message.
        :return: An AttributeQuery instance
        """

        logout_req = self._init_request(samlp.LogoutRequest())
        logout_req.session_index = sid()
        logout_req.base_id = saml.BaseID(text=subject_id)
        if reason:
            logout_req.reason = reason
        if not_on_or_after:
            logout_req.not_on_or_after = not_on_or_after
            
        return logout_req
        
    def logout(self, subject_id, reason=None, not_on_or_after=None):
        logout_req = self.make_logout_request(subject_id, reason,
                        not_on_or_after)
        

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
    
