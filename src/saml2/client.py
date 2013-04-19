#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2009-2011 Umeå University
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
import urllib
from urlparse import urlparse
try:
    from urlparse import parse_qs
except ImportError:
    # Compatibility with Python <= 2.5
    from cgi import parse_qs

from saml2.time_util import instant, not_on_or_after
from saml2.s_utils import signature
from saml2.s_utils import sid
from saml2.s_utils import do_attributes
from saml2.s_utils import decode_base64_and_inflate
#from saml2.s_utils import deflate_and_base64_encode

from saml2 import samlp, saml, class_name
from saml2 import VERSION
from saml2.sigver import pre_signature_part
from saml2.sigver import security_context, signed_instance_factory
from saml2.soap import SOAPClient
from saml2.binding import send_using_soap, http_redirect_message
from saml2.binding import http_post_message
from saml2.population import Population
from saml2.virtual_org import VirtualOrg
from saml2.config import config_factory

#from saml2.response import authn_response
from saml2.response import response_factory
from saml2.response import LogoutResponse
from saml2.response import AuthnResponse
from saml2.response import attribute_response

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_PAOS

SSO_BINDING = saml2.BINDING_HTTP_REDIRECT

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""

LAX = False
IDPDISC_POLICY = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single"

class IdpUnspecified(Exception):
    pass

class VerifyError(Exception):
    pass

class LogoutError(Exception):
    pass
        
class Saml2Client(object):
    """ The basic pySAML2 service provider class """
    
    def __init__(self, config=None,
                identity_cache=None, state_cache=None, 
                virtual_organization=None, config_file="", logger=None):
        """
        :param config: A saml2.config.Config instance
        :param identity_cache: Where the class should store identity information
        :param state_cache: Where the class should keep state information
        :param virtual_organization: Which if any virtual organization this
            SP belongs to
        """

        self.users = Population(identity_cache)

        # for server state storage
        if state_cache is None:
            self.state = {} # in memory storage
        else:
            self.state = state_cache

        if config:
            self.config = config
        elif config_file:
            self.config = config_factory("sp", config_file)
        else:
            raise Exception("Missing configuration")

        self.metadata = self.config.metadata

        if logger is None:
            self.logger = self.config.setup_logger()
        else:
            self.logger = logger

        # we copy the config.debug variable in an internal
        # field for convenience and because we may need to
        # change it during the tests
        self.debug = self.config.debug

        self.sec = security_context(self.config, log=self.logger,
                                    debug=self.debug)

        if virtual_organization:
            self.vorg = VirtualOrg(self, virtual_organization)
        else:
            self.vorg = None

        if "allow_unsolicited" in self.config:
            self.allow_unsolicited = self.config.allow_unsolicited
        else:
            self.allow_unsolicited = False

        if getattr(self.config, 'authn_requests_signed', 'false') == 'true':
            self.authn_requests_signed_default = True
        else:
            self.authn_requests_signed_default = False

        if getattr(self.config, 'logout_requests_signed', 'false') == 'true':
            self.logout_requests_signed_default = True
        else:
            self.logout_requests_signed_default = False

    #
    # Private methods
    #

    def _relay_state(self, session_id):
        vals = [session_id, str(int(time.time()))]
        if self.config.secret is None:
            vals.append(signature("", vals))
        else:
            vals.append(signature(self.config.secret, vals))
        return "|".join(vals)

    def _issuer(self, entityid=None):
        """ Return an Issuer instance """
        if entityid:
            if isinstance(entityid, saml.Issuer):
                return entityid
            else:
                return saml.Issuer(text=entityid,
                                    format=saml.NAMEID_FORMAT_ENTITY)
        else:
            return saml.Issuer(text=self.config.entityid,
                                format=saml.NAMEID_FORMAT_ENTITY)

    def _sso_location(self, entityid=None, binding=BINDING_HTTP_REDIRECT):
        if entityid:
            # verify that it's in the metadata
            try:
                return self.config.single_sign_on_services(entityid, binding)[0]
            except IndexError:
                if self.logger:
                    self.logger.info("_sso_location: %s, %s" % (entityid,
                                                                binding))
                return IdpUnspecified("No IdP to send to given the premises")

        # get the idp location from the configuration alternative the
        # metadata. If there is more than one IdP in the configuration
        # raise exception
        eids = self.config.idps()
        if len(eids) > 1:
            raise IdpUnspecified("Too many IdPs to choose from: %s" % eids)
        try:
            loc = self.config.single_sign_on_services(eids.keys()[0],
                                                        binding)[0]
            return loc
        except IndexError:
            return IdpUnspecified("No IdP to send to given the premises")

    def _my_name(self):
        return self.config.name

    #
    # Public API
    #

    def service_url(self, binding=BINDING_HTTP_POST):
        _res = self.config.endpoint("assertion_consumer_service", binding)
        if _res:
            return _res[0]
        else:
            return None

    def response(self, post, outstanding, log=None, decode=True,
                 asynchop=True):
        """ Deal with an AuthnResponse or LogoutResponse
        
        :param post: The reply as a dictionary
        :param outstanding: A dictionary with session IDs as keys and
            the original web request from the user before redirection
            as values.
        :param log: where loggin should go.
        :param decode: Whether the response is Base64 encoded or not
        :param asynchop: Whether the response was return over a asynchronous
            connection. SOAP for instance is synchronous
        :return: An response.AuthnResponse or response.LogoutResponse instance
        """
        # If the request contains a samlResponse, try to validate it
        try:
            saml_response = post['SAMLResponse']
        except KeyError:
            return None

        try:
            _ = self.config.entityid
        except KeyError:
            raise Exception("Missing entity_id specification")

        if log is None:
            log = self.logger
            
        reply_addr = self.service_url()
        
        resp = None
        if saml_response:
            try:
                resp = response_factory(saml_response, self.config,
                                        reply_addr, outstanding, log, 
                                        debug=self.debug, decode=decode,
                                        asynchop=asynchop, 
                                        allow_unsolicited=self.allow_unsolicited)
            except Exception, exc:
                if log:
                    log.error("%s" % exc)
                return None

            if log:
                log.debug(">> %s", resp)

            resp = resp.verify()
            if resp is None:
                log.error("Response could not be verified")
                return

            if isinstance(resp, AuthnResponse):
                self.users.add_information_about_person(resp.session_info())
                if log:
                    log.info("--- ADDED person info ----")
            elif isinstance(resp, LogoutResponse):
                self.handle_logout_response(resp, log)
            elif log:
                log.error("Response type not supported: %s" % saml2.class_name(resp))
        return resp
    
    def authn_request(self, query_id, destination, service_url, spentityid,
                        my_name="", vorg="", scoping=None, log=None, sign=None,
                        binding=saml2.BINDING_HTTP_POST,
                        nameid_format=saml.NAMEID_FORMAT_TRANSIENT):
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
        :param binding: The protocol to use for the Response !!
        :return: <samlp:AuthnRequest> instance
        """
        request = samlp.AuthnRequest(
            id= query_id,
            version= VERSION,
            issue_instant= instant(),
            assertion_consumer_service_url= service_url,
            protocol_binding= binding
        )

        if destination:
            request.destination = destination
        if my_name:
            request.provider_name = my_name
        if scoping:
            request.scoping = scoping
        
        # Profile stuff, should be configurable
        if nameid_format == saml.NAMEID_FORMAT_TRANSIENT:
            name_id_policy = samlp.NameIDPolicy(allow_create="true",
                                                format=nameid_format)
        else:
            name_id_policy = samlp.NameIDPolicy(format=nameid_format)

        if vorg:
            try:
                name_id_policy.sp_name_qualifier = vorg
                name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
            except KeyError:
                pass

        if sign is None:
            sign = self.authn_requests_signed_default
        
        if sign:
            request.signature = pre_signature_part(request.id,
                                                    self.sec.my_cert, 1)
            to_sign = [(class_name(request), request.id)]
        else:
            to_sign = []
        
        request.name_id_policy = name_id_policy
        request.issuer = self._issuer(spentityid)

        if log is None:
            log = self.logger

        if log:
            log.info("REQUEST: %s" % request)
        
        return signed_instance_factory(request, self.sec, to_sign)

    def authn(self, location, session_id, vorg="", scoping=None, log=None,
                sign=None, binding=saml2.BINDING_HTTP_POST,
                service_url_binding=None):
        """
        Construct a Authentication Request

        :param location: The URL of the destination
        :param session_id: The ID of the session
        :param vorg: The virtual organization if any that is involved
        :param scoping: How the request should be scoped, default == Not
        :param log: A log function to use for logging
        :param sign: If the request should be signed
        :param binding: The binding to use, default = HTTP POST
        :return: An AuthnRequest instance
        """
        spentityid = self.config.entityid
        if service_url_binding is None:
            service_url = self.service_url(binding)
        else:
            service_url = self.service_url(service_url_binding)

        if binding == BINDING_PAOS:
            my_name = None
            location = None
        else:
            my_name = self._my_name()


        if log is None:
            log = self.logger

        if log:
            log.info("spentityid: %s" % spentityid)
            log.info("service_url: %s" % service_url)
            log.info("my_name: %s" % my_name)

        return self.authn_request(session_id, location, service_url,
                                  spentityid, my_name, vorg, scoping, log,
                                  sign, binding=binding)

    def authenticate(self, entityid=None, relay_state="",
                     binding=saml2.BINDING_HTTP_REDIRECT,
                     log=None, vorg="", scoping=None, sign=None):
        """ Makes an authentication request.

        :param entityid: The entity ID of the IdP to send the request to
        :param relay_state: To where the user should be returned after
            successfull log in.
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param vorg: The entity_id of the virtual organization I'm a member of
        :param scoping: For which IdPs this query are aimed.
        :param sign: Whether the request should be signed or not.
        :return: AuthnRequest response
        """

        location = self._sso_location(entityid)
        session_id = sid()

        _req_str = "%s" % self.authn(location, session_id, vorg, scoping, log,
                                       sign)

        if log:
            log.info("AuthNReq: %s" % _req_str)

        if binding == saml2.BINDING_HTTP_POST:
            # No valid ticket; Send a form to the client
            # THIS IS NOT TO BE USED RIGHT NOW
            if log:
                log.info("HTTP POST")
            (head, response) = http_post_message(_req_str, location,
                                                    relay_state)
        elif binding == saml2.BINDING_HTTP_REDIRECT:
            if log:
                log.info("HTTP REDIRECT")
            (head, _body) = http_redirect_message(_req_str, location,
                                                    relay_state)
            response = head[0]
        else:
            raise Exception("Unkown binding type: %s" % binding)
        return session_id, response

    
    def create_attribute_query(self, session_id, subject_id, destination,
            issuer_id=None, attribute=None, sp_name_qualifier=None,
            name_qualifier=None, nameid_format=None, sign=False):
        """ Constructs an AttributeQuery
        
        :param session_id: The identifier of the session
        :param subject_id: The identifier of the subject
        :param destination: To whom the query should be sent
        :param issuer_id: Identifier of the issuer
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
            issuer=self._issuer(issuer_id),
            subject=subject,
        )
        
        if sign:
            query.signature = pre_signature_part(query.id, self.sec.my_cert, 1)
        
        if attribute:
            query.attribute = do_attributes(attribute)
        
        if sign:
            signed_query = self.sec.sign_attribute_query_using_xmlsec(
                                                                "%s" % query)
            return samlp.attribute_query_from_string(signed_query)
        else:
            return query
            
    
    def attribute_query(self, subject_id, destination, issuer_id=None,
                attribute=None, sp_name_qualifier=None, name_qualifier=None,
                nameid_format=None, log=None, real_id=None):
        """ Does a attribute request to an attribute authority, this is
        by default done over SOAP. Other bindings could be used but not
        supported right now.
        
        :param subject_id: The identifier of the subject
        :param destination: To whom the query should be sent
        :param issuer_id: Who is sending this query
        :param attribute: A dictionary of attributes and values that is asked for
        :param sp_name_qualifier: The unique identifier of the
            service provider or affiliation of providers for whom the
            identifier was generated.
        :param name_qualifier: The unique identifier of the identity
            provider that generated the identifier.
        :param nameid_format: The format of the name ID
        :param log: Function to use for logging
        :param real_id: The identifier which is the key to this entity in the
            identity database
        :return: The attributes returned
        """

        if log is None:
            log = self.logger

        session_id = sid()
        issuer = self._issuer(issuer_id)
        
        request = self.create_attribute_query(session_id, subject_id,
                    destination, issuer, attribute, sp_name_qualifier,
                    name_qualifier, nameid_format=nameid_format)
        
        if log:
            log.info("Request, created: %s" % request)
        
        soapclient = SOAPClient(destination, self.config.key_file,
                                self.config.cert_file,
                                ca_certs=self.config.ca_certs)
        if log:
            log.info("SOAP client initiated")

        try:
            response = soapclient.send(request)
        except Exception, exc:
            if log:
                log.info("SoapClient exception: %s" % (exc,))
            return None
        
        if log:
            log.info("SOAP request sent and got response: %s" % response)
#            fil = open("response.xml", "w")
#            fil.write(response)
#            fil.close()
            
        if response:
            if log:
                log.info("Verifying response")
            
            try:
                # synchronous operation
                aresp = attribute_response(self.config, issuer, log=log)
            except Exception, exc:
                if log:
                    log.error("%s", (exc,))
                return None
                
            _resp = aresp.loads(response, False, soapclient.response).verify()
            if _resp is None:
                if log:
                    log.error("Didn't like the response")
                return None
            
            session_info = _resp.session_info()

            if session_info:
                if real_id is not None:
                    session_info["name_id"] = real_id
                self.users.add_information_about_person(session_info)
            
            if log:
                log.info("session: %s" % session_info)
            return session_info
        else:
            if log:
                log.info("No response")
            return None
    
    def construct_logout_request(self, subject_id, destination,
                                    issuer_entity_id, reason=None, expire=None):
        """ Constructs a LogoutRequest
        
        :param subject_id: The identifier of the subject
        :param destination:
        :param issuer_entity_id: The entity ID of the IdP the request is
            target at.
        :param reason: An indication of the reason for the logout, in the
            form of a URI reference.
        :param expire: The time at which the request expires,
            after which the recipient may discard the message.
        :return: A LogoutRequest instance
        """
            
        session_id = sid()
        # create NameID from subject_id
        name_id = saml.NameID(
            text = self.users.get_entityid(subject_id, issuer_entity_id,
                                           False))

        request = samlp.LogoutRequest(
            id=session_id,
            version=VERSION,
            issue_instant=instant(),
            destination=destination,
            issuer=self._issuer(),
            name_id = name_id
        )
    
        if reason:
            request.reason = reason
    
        if expire:
            request.not_on_or_after = expire
                        
        return request
    
    def global_logout(self, subject_id, reason="", expire=None,
                          sign=None, log=None, return_to="/"):
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

        if log is None:
            log = self.logger

        if log:
            log.info("logout request for: %s" % subject_id)

        # find out which IdPs/AAs I should notify
        entity_ids = self.users.issuers_of_info(subject_id)

        return self._logout(subject_id, entity_ids, reason, expire, 
                            sign, log, return_to)
        
    def _logout(self, subject_id, entity_ids, reason, expire, 
                sign=None, log=None, return_to="/"):
        
        # check time
        if not not_on_or_after(expire): # I've run out of time
            # Do the local logout anyway
            self.local_logout(subject_id)
            return 0, "504 Gateway Timeout", [], []
            
        # for all where I can use the SOAP binding, do those first
        not_done = entity_ids[:]
        response = False
        if log is None:
            log = self.logger

        for entity_id in entity_ids:
            response = False

            for binding in [BINDING_SOAP, BINDING_HTTP_POST,
                            BINDING_HTTP_REDIRECT]:
                destinations = self.config.single_logout_services(entity_id,
                                                                binding)
                if not destinations:
                    continue

                destination = destinations[0]
                
                if log:
                    log.info("destination to provider: %s" % destination)
                request = self.construct_logout_request(subject_id, destination,
                                                    entity_id, reason, expire)
                
                to_sign = []
                #if sign and binding != BINDING_HTTP_REDIRECT:

                if sign is None:
                    sign = self.logout_requests_signed_default

                if sign:
                    request.signature = pre_signature_part(request.id,
                                                    self.sec.my_cert, 1)
                    to_sign = [(class_name(request), request.id)]
        
                if log:
                    log.info("REQUEST: %s" % request)

                request = signed_instance_factory(request, self.sec, to_sign)
        
                if binding == BINDING_SOAP:
                    response = send_using_soap(request, destination, 
                                                self.config.key_file,
                                                self.config.cert_file,
                                                log=log,
                                                ca_certs=self.config.ca_certs)
                    if response:
                        if log:
                            log.info("Verifying response")
                        response = self.logout_response(response, log)

                    if response:
                        not_done.remove(entity_id)
                        if log:
                            log.info("OK response from %s" % destination)
                    else:
                        if log:
                            log.info(
                                    "NOT OK response from %s" % destination)

                else:
                    session_id = request.id
                    rstate = self._relay_state(session_id)

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
            
                    return session_id, code, head, body
        
        if not_done:
            # upstream should try later
            raise LogoutError("%s" % (entity_ids,))
        
        return 0, "", [], response

    def local_logout(self, subject_id):
        """ Remove the user from the cache, equals local logout 
        
        :param subject_id: The identifier of the subject
        """
        self.users.remove_person(subject_id)
        return True

    def handle_logout_response(self, response, log):
        """ handles a Logout response 
        
        :param response: A response.Response instance
        :param log: A logging function
        :return: 4-tuple of (session_id of the last sent logout request,
            response message, response headers and message)
        """
        if log is None:
            log = self.logger

        if log:
            log.info("state: %s" % (self.state,))
        status = self.state[response.in_response_to]
        if log:
            log.info("status: %s" % (status,))
        issuer = response.issuer()
        if log:
            log.info("issuer: %s" % issuer)
        del self.state[response.in_response_to]
        if status["entity_ids"] == [issuer]: # done
            self.local_logout(status["subject_id"])
            return 0, "200 Ok", [("Content-type","text/html")], []
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
        :param log: logging function
        :param binding: What type of binding this message came through.
        :return: None if the reply doesn't contain a valid SAML LogoutResponse,
            otherwise the reponse if the logout was successful and None if it 
            was not.
        """
        
        response = None
        if log is None:
            log = self.logger

        if xmlstr:
            try:
                # expected return address
                return_addr = self.config.endpoint("single_logout_service",
                                                   binding=binding)[0]
            except Exception:
                if log:
                    log.info("Not supposed to handle this!")
                return None
            
            try:
                response = LogoutResponse(self.sec, return_addr, debug=self.debug,
                                            log=log)
            except Exception, exc:
                if log:
                    log.info("%s" % exc)
                return None
                
            if binding == BINDING_HTTP_REDIRECT:
                xmlstr = decode_base64_and_inflate(xmlstr)
            elif binding == BINDING_HTTP_POST:
                xmlstr = base64.b64decode(xmlstr)

            if log:
                log.debug("XMLSTR: %s" % xmlstr)

            response = response.loads(xmlstr, False)

            if response:
                response = response.verify()
                
            if not response:
                return None
            
            if log:
                log.debug(response)
                
            return self.handle_logout_response(response, log)

        return response

    def http_redirect_logout_request(self, get, subject_id, log=None):
        """ Deal with a LogoutRequest received through HTTP redirect

        :param get: The request as a dictionary 
        :param subject_id: the id of the current logged user
        :return: a tuple with a list of header tuples (presently only location)
            and a status which will be True in case of success or False 
            otherwise.
        """
        headers = []
        success = False
        if log is None:
            log = self.logger

        try:
            saml_request = get['SAMLRequest']
        except KeyError:
            return None

        if saml_request:
            xml = decode_base64_and_inflate(saml_request)

            request = samlp.logout_request_from_string(xml)
            if log:
                log.debug(request)

            if request.name_id.text == subject_id:
                status = samlp.STATUS_SUCCESS
                success = self.local_logout(subject_id)
            else:
                status = samlp.STATUS_REQUEST_DENIED

            response, destination = self .make_logout_response(
                                                        request.issuer.text,
                                                        request.id,
                                                        status)

            if log:
                log.info("RESPONSE: {0:>s}".format(response))

            if 'RelayState' in get:
                rstate = get['RelayState']
            else:
                rstate = ""
                
            (headers, _body) = http_redirect_message(str(response), 
                                                    destination, 
                                                    rstate, 'SAMLResponse')

        return headers, success

    def logout_request(self, request, subject_id, log=None, 
                            binding=BINDING_HTTP_REDIRECT):
        """ Deal with a LogoutRequest 

        :param request: The request. The format depends on which binding is
            used.
        :param subject_id: the id of the current logged user
        :return: What is returned also depends on which binding is used.
        """
        if log is None:
            log = self.logger

        if binding == BINDING_HTTP_REDIRECT:
            return self.http_redirect_logout_request(request, subject_id, log)
        
    def make_logout_response(self, idp_entity_id, request_id,
                             status_code, binding=BINDING_HTTP_REDIRECT):
        """ Constructs a LogoutResponse

        :param idp_entity_id: The entityid of the IdP that want to do the
            logout
        :param request_id: The Id of the request we are replying to
        :param status_code: The status code of the response
        :param binding: The type of binding that will be used for the response
        :return: A LogoutResponse instance
        """

        destination = self.config.single_logout_services(idp_entity_id, binding)[0]

        status = samlp.Status(
            status_code=samlp.StatusCode(value=status_code))

        response = samlp.LogoutResponse(
            id=sid(),
            version=VERSION,
            issue_instant=instant(),
            destination=destination,
            issuer=self._issuer(),
            in_response_to=request_id,
            status=status,
            )

        return response, destination

    def add_vo_information_about_user(self, subject_id):
        """ Add information to the knowledge I have about the user. This is
        for Virtual organizations.
        
        :param subject_id: The subject identifier 
        :return: A possibly extended knowledge.
        """

        ava = {}
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

    #noinspection PyUnusedLocal
    def is_session_valid(self, _session_id):
        """ Place holder. Supposed to check if the session is still valid.
        """
        return True

    def authz_decision_query_using_assertion(self, entityid, assertion,
                                            action=None,
                                            resource=None, subject=None,
                                            binding=saml2.BINDING_HTTP_REDIRECT,
                                            log=None, sign=False):
        """ Makes an authz decision query.

        :param entityid: The entity ID of the IdP to send the request to
        :param assertion:
        :param action:
        :param resource:
        :param subject:
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param sign: Whether the request should be signed or not.
        :return: AuthzDecisionQuery instance
        """

        if action:
            if isinstance(action, basestring):
                _action = [saml.Action(text=action)]
            else:
                _action = [saml.Action(text=a) for a in action]
        else:
            _action = None
            
        return self.authz_decision_query(entityid,
                                         _action,
                                         saml.Evidence(assertion=assertion),
                                         resource, subject,
                                         binding, log, sign)

    #noinspection PyUnusedLocal
    def authz_decision_query(self, entityid, action,
                                evidence=None, resource=None, subject=None,
                                binding=saml2.BINDING_HTTP_REDIRECT,
                                log=None, sign=None):
        """ Creates an authz decision query.

        :param entityid: The entity ID of the IdP to send the request to
        :param action: The action you want to perform (has to be at least one)
        :param evidence: Why you should be able to perform the action
        :param resource: The resource you want to perform the action on
        :param subject: Who wants to do the thing
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param sign: Whether the request should be signed or not.
        :return: AuthzDecisionQuery instance
        """

        spentityid = self._issuer()
        service_url = self.service_url()
        my_name = self._my_name()

        if log is None:
            log = self.logger

        if log:
            log.info("spentityid: %s" % spentityid)
            log.info("service_url: %s" % service_url)
            log.info("my_name: %s" % my_name)


#        authen_req = self.authn_request(session_id, location,
#                                service_url, spentityid, my_name, vorg,
#                                scoping, log, sign)
        
        request = samlp.AuthzDecisionQuery(action, evidence, resource,
                                           subject=subject,
                                           issuer=spentityid,
                                           id=sid(),
                                           issue_instant=instant(),
                                           version=VERSION,
                                           destination=entityid)

        return request


    #noinspection PyUnusedLocal
    def authz_decision_query_response(self, response, log=None):
        """ Verify that the response is OK """
        pass

    #noinspection PyUnusedLocal
    def do_authz_decision_query(self, entityid, assertion=None,
                                log=None, sign=False):

        authz_decision_query = self.authz_decision_query(entityid, assertion)

        for destination in self.config.authz_services(entityid):
            to_sign = []
            if sign :
                authz_decision_query.signature = pre_signature_part(
                                                        authz_decision_query.id,
                                                        self.sec.my_cert, 1)
                to_sign.append((class_name(authz_decision_query),
                                authz_decision_query.id))

                authz_decision_query = signed_instance_factory(authz_decision_query,
                                                               self.sec, to_sign)

            response = send_using_soap(authz_decision_query, destination,
                                        self.config.key_file,
                                        self.config.cert_file,
                                        log=log,
                                        ca_certs=self.config.ca_certs)
            if response:
                if log:
                    log.info("Verifying response")
                response = self.authz_decision_query_response(response, log)

            if response:
                #not_done.remove(entity_id)
                if log:
                    log.info("OK response from %s" % destination)
                return response
            else:
                if log:
                    log.info("NOT OK response from %s" % destination)

        return None

    def request_to_discovery_service(self, disc_url, return_url="",
                                     policy="", returnIDParam="",
                                     is_passive=False ):
        """
        Created the HTTP redirect URL needed to send the user to the
        discovery service.

        :param disc_url: The URL of the discovery service
        :param return_url: The discovery service MUST redirect the user agent
            to this location in response to this request
        :param policy: A parameter name used to indicate the desired behavior
            controlling the processing of the discovery service
        :param returnIDParam: A parameter name used to return the unique
            identifier of the selected identity provider to the original
            requester.
        :param is_passive: A boolean value of "true" or "false" that controls
            whether the discovery service is allowed to visibly interact with
            the user agent.
        :return: A URL
        """
        pdir = {"entityID": self.config.entityid}
        if return_url:
            pdir["return"] = return_url
        if policy and policy != IDPDISC_POLICY:
            pdir["policy"] = policy
        if returnIDParam:
            pdir["returnIDParam"] = returnIDParam
        if is_passive:
            pdir["is_passive"] = "true"

        params = urllib.urlencode(pdir)
        return "%s?%s" % (disc_url, params)

    def get_idp_from_discovery_service(self, query="", url="", returnIDParam=""):
        """
        Deal with the reponse url from a Discovery Service

        :param url: the url the user was redirected back to
        :param returnIDParam: This is where the identifier of the IdP is
            place if it was specified in the query otherwise in 'entityID'
        :return: The IdP identifier or "" if none was given
        """

        if url:
            part = urlparse(url)
            qsd = parse_qs(part[4])
        elif query:
            qsd = parse_qs(query)
        else:
            qsd = {}
            
        if returnIDParam:
            try:
                return qsd[returnIDParam][0]
            except KeyError:
                return ""
        else:
            try:
                return qsd["entityID"][0]
            except KeyError:
                return ""
