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

import saml2
import time
import base64

from saml2.time_util import instant, not_on_or_after
from saml2.s_utils import signature
from saml2.s_utils import sid
from saml2.s_utils import do_attributes, factory
from saml2.s_utils import decode_base64_and_inflate

from saml2 import samlp, saml, class_name
from saml2 import VERSION
from saml2.sigver import pre_signature_part
from saml2.sigver import security_context, signed_instance_factory
from saml2.soap import SOAPClient
from saml2.binding import send_using_soap, http_redirect_message
from saml2.binding import http_post_message
from saml2.population import Population
from saml2.virtual_org import VirtualOrg

from saml2.response import authn_response
from saml2.response import response_factory
from saml2.response import LogoutResponse
from saml2.response import AuthnResponse

from saml2 import BINDING_HTTP_REDIRECT, BINDING_SOAP, BINDING_HTTP_POST

SSO_BINDING = saml2.BINDING_HTTP_REDIRECT

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""

LAX = False

class IdpUnspecified(Exception):
    pass

class VerifyError(Exception):
    pass

class LogoutError(Exception):
    pass
        
class Saml2Client(object):
    """ The basic pySAML2 service provider class """
    
    def __init__(self, config=None, debug=0, vorg=None, 
                identity_cache=None, state_cache=None):
        """
        :param config: A saml2.config.Config instance
        """
        self.vorg = None
        self.users = Population(identity_cache)

        # for server state storage
        if not state_cache:
            self.state = {} # in memory storage
        else:
            self.state = state_cache
        
        self.sec = None
        if config:
            self.config = config
            if "metadata" in config:
                self.metadata = config["metadata"]
                if vorg:
                    self.vorg = VirtualOrg(self.metadata, vorg, 
                                            self.users.cache, 
                                            log=None, vorg_conf=None)
            self.sec = security_context(config)
    
        if not debug:
            self.debug = self.config.debug()
        else:
            self.debug = debug
    
    def relay_state(self, session_id):
        vals = [session_id, str(int(time.time()))]
        vals.append(signature(self.config["secret"], vals))
        return "|".join(vals)

    def _init_request(self, request, destination):
        #request.id = sid()
        request.version = VERSION
        request.issue_instant = instant()
        request.destination = destination
        return request
    
    def idp_entry(self, name=None, location=None, provider_id=None):
        res = samlp.IDPEntry()
        if name:
            res.name = name
        if location:
            res.loc = location
        if provider_id:
            res.provider_id = provider_id

        return res
    
    def scoping_from_metadata(self, entityid, location=None):
        name = self.metadata.name(entityid)
        idp_ent = self.idp_entry(name, location)
        return samlp.Scoping(idp_list=samlp.IDPList(idp_entry=[idp_ent]))
    
    def response(self, post, entity_id, outstanding, log=None):
        """ Deal with an AuthnResponse or LogoutResponse
        
        :param post: The reply as a dictionary
        :param entity_id: The Entity ID for this SP
        :param outstanding: A dictionary with session IDs as keys and
            the original web request from the user before redirection
            as values.
        :param log: where loggin should go.
        :return: An response.AuthnResponse or response.LogoutResponse instance
        """
        # If the request contains a samlResponse, try to validate it
        try:
            saml_response = post['SAMLResponse']
        except KeyError:
            return None
        
        reply_addr = self._service_url()
        
        resp = None
        if saml_response:
            resp = response_factory(saml_response, self.config, entity_id, 
                                    reply_addr, outstanding, log, 
                                    debug=self.debug)

            
            if self.debug:
                log and log.info(resp)
            resp = resp.verify()
            if isinstance(resp, AuthnResponse):
                self.users.add_information_about_person(resp.session_info())
            elif isinstance(resp, LogoutResponse):
                self.handle_logout_response(resp)
                    
        return resp
    
    def authn_request(self, query_id, destination, service_url, spentityid,
                        my_name, vorg="", scoping=None, log=None, sign=False,
                        binding=saml2.BINDING_HTTP_POST):
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
        request = samlp.AuthnRequest(
            id= query_id,
            version= VERSION,
            issue_instant= instant(),
            destination= destination,
            assertion_consumer_service_url= service_url,
            protocol_binding= binding,
            provider_name= my_name
        )
        
        if scoping:
            request.scoping = scoping
        
        # Profile stuff, should be configurable
        name_id_policy = samlp.NameIDPolicy(allow_create="true", 
                                        format=saml.NAMEID_FORMAT_TRANSIENT)
        
        if vorg:
            try:
                name_id_policy.sp_name_qualifier = vorg
                name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
            except KeyError:
                pass
        
        if sign:
            request.signature = pre_signature_part(request.id,
                                                    self.sec.my_cert, 1)
            to_sign = [(class_name(request), request.id)]
        else:
            to_sign = []
        
        request.name_id_policy = name_id_policy
        request.issuer = factory(saml.Issuer, text=spentityid )
        
        if log:
            log.info("REQUEST: %s" % request)
        
        return "%s" % signed_instance_factory(request, self.sec, to_sign)
    
    def issuer(self):
        """ Return an Issuer instance """
        return saml.Issuer(text=self.config["entityid"], 
                                format=saml.NAMEID_FORMAT_ENTITY)        
    
    def _spentityid(self, spentityid=None):
        if self.config:
            return self.config["entityid"]
        else:
            return spentityid

    def _sso_location(self, location=None):
        if not location :
            # get the idp location from the configuration alternative the 
            # metadata. If there is more than one IdP in the configuration 
            # raise exception
            urls = self.config.idps()
            if len(urls) > 1:
                raise IdpUnspecified("Too many IdPs to choose from: %s" % urls)
            return urls[0]["single_sign_on_service"][BINDING_HTTP_REDIRECT]
        else:
            return location
        
    def _service_url(self, url=None):
        if not url:
            return self.config.endpoint("sp", "assertion_consumer_service")[0]

    def _my_name(self, name=None):
        if not name:
            return self.config.name()
        else:
            return name
        
    def authenticate(self, spentityid=None, location="", service_url="",
                        my_name="", relay_state="",
                        binding=saml2.BINDING_HTTP_REDIRECT, log=None,
                        vorg="", scoping=None, sign=False):
        """ Sends an authentication request.
        
        :param spentityid: The SP EntityID
        :param location: Where the IdP is.
        :param service_url: The SP's service URL
        :param my_name: The providers name
        :param relay_state: To where the user should be returned after
            successfull log in.
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param vorg: The entity_id of the virtual organization I'm a member of
        :param scoping: For which IdPs this query are aimed.
        :param sign: Whether the request should be signed or not.
        :return: AuthnRequest response
        """
        
        spentityid = self._spentityid(spentityid)
        location = self._sso_location(location)
        service_url = self._service_url(service_url)
        my_name = self._my_name(my_name)
                            
        if log:
            log.info("spentityid: %s" % spentityid)
            log.info("location: %s" % location)
            log.info("service_url: %s" % service_url)
            log.info("my_name: %s" % my_name)
            
        session_id = sid()
        authen_req = self.authn_request(session_id, location,
                                service_url, spentityid, my_name, vorg,
                                scoping, log, sign)
        log and log.info("AuthNReq: %s" % authen_req)
        
        if binding == saml2.BINDING_HTTP_POST:
            # No valid ticket; Send a form to the client
            # THIS IS NOT TO BE USED RIGHT NOW
            (head, response) = http_post_message(authen_req, location, 
                                                    relay_state)
        elif binding == saml2.BINDING_HTTP_REDIRECT:
            (head, _body) = http_redirect_message(authen_req, location, 
                                                relay_state)
            response = head[0]
        else:
            raise Exception("Unkown binding type: %s" % binding)
        return (session_id, response)

    
    def create_attribute_query(self, session_id, subject_id, destination,
            issuer=None, attribute=None, sp_name_qualifier=None,
            name_qualifier=None, nameid_format=None, sign=False):
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
        :param nameid_format: The format of the name ID
        :param sign: Whether the query should be signed or not.
        :return: An AttributeQuery instance
        """
    
        
        subject = saml.Subject(
                    name_id = saml.NameID(
                                text=subject_id, 
                                format=nameid_format,
                                sp_name_qualifier=sp_name_qualifier,
                                name_qualifier=name_qualifier),
                    )
                    
        query = samlp.AttributeQuery(
            id=session_id,
            version=VERSION,
            issue_instant=instant(),
            destination=destination,
            issuer=issuer,
            subject=subject,
        )
        
        if sign:
            query.signature = pre_signature_part(query.id, self.sec.my_cert, 1)
        
        if attribute:
            query.attribute = do_attributes(attribute)
        
        if sign:
            signed_query = self.sec.sign_assertion_using_xmlsec("%s" % query)
            return samlp.attribute_query_from_string(signed_query)
        else:
            return query
            
    
    def attribute_query(self, subject_id, destination, issuer=None,
                attribute=None, sp_name_qualifier=None, name_qualifier=None,
                nameid_format=None, log=None):
        """ Does a attribute request from an attribute authority
        
        :param subject_id: The identifier of the subject
        :param destination: To whom the query should be sent
        :param issuer: Who is sending this query
        :param attribute: A dictionary of attributes and values that is asked for
        :param sp_name_qualifier: The unique identifier of the
            service provider or affiliation of providers for whom the
            identifier was generated.
        :param name_qualifier: The unique identifier of the identity
            provider that generated the identifier.
        :param nameid_format: The format of the name ID
        :return: The attributes returned
        """
        
        session_id = sid()
        if not issuer:
            issuer = self.issuer()
        
        request = self.create_attribute_query(session_id, subject_id,
                    destination, issuer, attribute, sp_name_qualifier,
                    name_qualifier, nameid_format=nameid_format)
        
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
            
            aresp = authn_response(self.config, "", issuer, 
                                    outstanding_queries={session_id:""}, 
                                    log=log)
            session_info = aresp.loads(response).verify().session_info()

            if session_info:
                self.users.add_information_about_person(session_info)
            
            log and log.info("session: %s" % session_info)
            return session_info
        else:
            log and log.info("No response")
            return None
    
    def logout_requests(self, subject_id, destination, entity_id, 
                            reason=None, expire=None, _log=None):
        """ Constructs a LogoutRequest
        
        :param subject_id: The identifier of the subject
        :param destination: 
        :param reason: An indication of the reason for the logout, in the
            form of a URI reference.
        :param expire: The time at which the request expires,
            after which the recipient may discard the message.
        :return: A LogoutRequest instance
        """
            
        session_id = sid()
        # create NameID from subject_id
        name_id = saml.NameID(
            text = self.users.get_entityid(subject_id, entity_id))

        request = samlp.LogoutRequest(
            id=session_id,
            version=VERSION,
            issue_instant=instant(),
            destination=destination,
            issuer=self.issuer(),
            name_id = name_id
        )
        
    
        if reason:
            request.reason = reason
    
        if expire:
            request.not_on_or_after = expire
                        
        return request
    
    def global_logout(self, subject_id, reason="", expire=None,
                          sign=False, log=None, return_to="/"):
        """ More or less a layer of indirection :-/
        Bootstrapping the whole thing by finding all the IdPs that should
        be notified.
        
        :param subject_id: The identifier of the subject that wants to be
            logged out.
        :param reason: Why the subject wants to log out
        :param expire: The latest the log out should happen.
        :param sign: Whether the request should be signed or not.
            This also depends on what binding is used.
        :param log: A logging function
        :param return_to: Where to send the user after she has been
            logged out.
        :return: Depends on which binding is used:
            If the HTTP redirect binding then a HTTP redirect,
            if SOAP binding has been used the just the result of that
            conversation. 
        """
            
        log and log.info("logout request for: %s" % subject_id)

        # find out which IdPs/AAs I should notify
        entity_ids = self.users.issuers_of_info(subject_id)

        return self._logout(subject_id, entity_ids, reason, expire, 
                            sign, log, return_to)
        
    def _logout(self, subject_id, entity_ids, reason, expire, 
                sign, log=None, return_to="/"):
        
        # check time
        if not_on_or_after(expire) == False: # I've run out of time
            # Do the local logout anyway
            self.local_logout(subject_id)
            return (0, "504 Gateway Timeout", [], [])
            
        # for all where I can use the SOAP binding, do those first
        not_done = entity_ids[:]
        session_id = 0

        for entity_id in entity_ids:
            response = False
            rstate = None
            for binding in [BINDING_SOAP, BINDING_HTTP_POST, 
                            BINDING_HTTP_REDIRECT]:
                destination = self.config.logout_service(entity_id, binding)
                if not destination:
                    continue

                log and log.info("destination to provider: %s" % destination)
                request = self.logout_requests(subject_id, destination, 
                                                entity_id, reason, expire, log)
                
                to_sign = []
                if sign and binding != BINDING_HTTP_REDIRECT:
                    request.signature = pre_signature_part(request.id,
                                                    self.sec.my_cert, 1)
                    to_sign = [(class_name(request), request.id)]
        
                if log:
                    log.info("REQUEST: %s" % request)

                request = signed_instance_factory(request, self.sec, to_sign)
        
                if binding == BINDING_SOAP:
                    response = send_using_soap(request, destination, 
                                                self.config["key_file"],
                                                self.config["cert_file"], 
                                                log=log)
                    if response:
                        log and log.info("Verifying response")
                        response = self.logout_response(response, log)

                    if response:
                        not_done.remove(entity_id)
                        log and log.info("OK response from %s" % destination)
                    else:
                        log and log.info(
                                    "NOT OK response from %s" % destination)

                else:
                    session_id = request.id
                    rstate = self.relay_state(session_id)

                    self.state[session_id] = {"entity_id": entity_id,
                                                "operation": "SLO",
                                                "entity_ids": entity_ids,
                                                "subject_id": subject_id,
                                                "reason": reason,
                                                "not_on_of_after": expire,
                                                "sign": sign,
                                                "return_to": return_to}
                    

                    if binding == BINDING_HTTP_POST:
                        (head, body) = http_post_message(request, 
                                                            destination, 
                                                            rstate)
                        code = "200 OK"
                    else:
                        (head, body) = http_redirect_message(request, 
                                                            destination, 
                                                            rstate)
                        code = "302 Found"
            
                    return (session_id, code, head, body)
        
        if not_done != []:
            # upstream should try later
            raise LogoutError("%s" % (entity_ids,))
        
        return (0, "", [], response)

    def local_logout(self, subject_id):
        # Remove the user from the cache, equals local logout
        self.users.remove_person(subject_id)
        return True

    def handle_logout_response(self, response):
        """ handles a Logout response """
        self.log and self.log.info("state: %s" % (self.state,))
        status = self.state[response.in_response_to]
        self.log and self.log.info("status: %s" % (status,))
        issuer = response.issuer()
        self.log and self.log.info("issuer: %s" % issuer)
        del self.state[response.in_response_to]
        if status["entity_ids"] == [issuer]: # done
            self.local_logout(status["subject_id"])
            return (0, "200 Ok", [("Content-type","text/html")], [])
        else:
            status["entity_ids"].remove(issuer)
            return self._logout(status["subject_id"], 
                                status["entity_ids"], 
                                status["reason"], 
                                status["not_on_or_after"], 
                                status["sign"], 
                                log, )
        
    def logout_response(self, xmlstr, log=None, binding=BINDING_SOAP):
        """ Deal with a LogoutResponse

        :param xmlstr: The response as a xml string
        :param subject_id: the id of the user that initiated the logout
        :param log: logging function
        :param binding: What type of binding this message came through.
        :return: None if the reply doesn't contain a valid SAML LogoutResponse,
            otherwise the reponse if the logout was successful and None if it 
            was not.
        """
        
        response = None

        if xmlstr:
            try:
                return_addr = self.config.endpoint("sp", 
                                                    "single_logout_service",
                                                    binding=binding)[0]
            except Exception:
                log and log.info("Not supposed to handle this!")
                return None
            
            response = LogoutResponse(self.sec, return_addr, debug=True, 
                                        log=log)

            if binding == BINDING_HTTP_REDIRECT:
                xmlstr = decode_base64_and_inflate(xmlstr)
            elif binding == BINDING_HTTP_POST:
                xmlstr = base64.b64decode(xmlstr)

            if self.debug and log:
                log.info("XMLSTR: %s" % xmlstr)

            response = response.loads(xmlstr, False)

            if response:
                response = response.verify()
                
            if not response:
                return None
            
            if self.debug and log:
                log.info(response)
                
            return self.handle_logout_response(response)

        return response
        
    def add_vo_information_about_user(self, subject_id):
        """ Add information to the knowledge I have about the user """
        try:
            (ava, _) = self.users.get_identity(subject_id)
        except KeyError:
            pass

        # is this a Virtual Organization situation
        if self.vorg:
            if self.vorg.do_aggregation(subject_id):
                # Get the extended identity
                ava = self.users.get_identity(subject_id)[0]
        return ava
        
    def is_session_valid(session_id):
        return True
        
# ----------------------------------------------------------------------

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
