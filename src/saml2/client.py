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
from saml2.saml import AssertionIDRef

try:
    from urlparse import parse_qs
except ImportError:
    # Compatibility with Python <= 2.5
    from cgi import parse_qs

from saml2.time_util import not_on_or_after
from saml2.s_utils import decode_base64_and_inflate

from saml2 import samlp, saml, class_name
from saml2.sigver import pre_signature_part
from saml2.sigver import signed_instance_factory
from saml2.binding import send_using_soap
from saml2.binding import http_redirect_message
from saml2.binding import http_post_message
from saml2.client_base import Base, LogoutError

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST

import logging
logger = logging.getLogger(__name__)

class Saml2Client(Base):
    """ The basic pySAML2 service provider class """

    def do_authenticate(self, entityid=None, relay_state="",
                     binding=saml2.BINDING_HTTP_REDIRECT, vorg="",
                     scoping=None, consent=None, extensions=None, sign=None):
        """ Makes an authentication request.

        :param entityid: The entity ID of the IdP to send the request to
        :param relay_state: To where the user should be returned after
            successfull log in.
        :param binding: Which binding to use for sending the request
        :param vorg: The entity_id of the virtual organization I'm a member of
        :param scoping: For which IdPs this query are aimed.
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param sign: Whether the request should be signed or not.
        :return: AuthnRequest response
        """

        location = self._sso_location(entityid, binding)

        session_id, _req_str = "%s" % self.create_authn_request(location, vorg,
                                                                scoping,
                                                                consent,
                                                                extensions,
                                                                sign)

        logger.info("AuthNReq: %s" % _req_str)

        if binding == saml2.BINDING_HTTP_POST:
            # No valid ticket; Send a form to the client
            # THIS IS NOT TO BE USED RIGHT NOW
            logger.info("HTTP POST")
            (head, response) = http_post_message(_req_str, location,
                                                 relay_state)
        elif binding == saml2.BINDING_HTTP_REDIRECT:
            logger.info("HTTP REDIRECT")
            (head, _body) = http_redirect_message(_req_str, location,
                                                  relay_state)
            response = head[0]
        else:
            raise Exception("Unknown binding type: %s" % binding)

        return session_id, response

    def global_logout(self, subject_id, reason="", expire=None, sign=None,
                      return_to="/"):
        """ More or less a layer of indirection :-/
        Bootstrapping the whole thing by finding all the IdPs that should
        be notified.
        
        :param subject_id: The identifier of the subject that wants to be
            logged out.
        :param reason: Why the subject wants to log out
        :param expire: The latest the log out should happen.
        :param sign: Whether the request should be signed or not.
            This also depends on what binding is used.
        :param return_to: Where to send the user after she has been
            logged out.
        :return: Depends on which binding is used:
            If the HTTP redirect binding then a HTTP redirect,
            if SOAP binding has been used the just the result of that
            conversation. 
        """

        logger.info("logout request for: %s" % subject_id)

        # find out which IdPs/AAs I should notify
        entity_ids = self.users.issuers_of_info(subject_id)

        return self.do_logout(subject_id, entity_ids, reason, expire,
                            sign, return_to)
        
    def do_logout(self, subject_id, entity_ids, reason, expire,
                sign=None, return_to="/"):
        
        # check time
        if not not_on_or_after(expire): # I've run out of time
            # Do the local logout anyway
            self.local_logout(subject_id)
            return 0, "504 Gateway Timeout", [], []
            
        # for all where I can use the SOAP binding, do those first
        not_done = entity_ids[:]
        response = False

        for entity_id in entity_ids:
            response = False

            for binding in [BINDING_SOAP, BINDING_HTTP_POST,
                            BINDING_HTTP_REDIRECT]:
                destinations = self.config.single_logout_services(entity_id,
                                                                  binding)
                if not destinations:
                    continue

                destination = destinations[0]

                logger.info("destination to provider: %s" % destination)
                request = self.create_logout_request(subject_id, destination,
                                                     entity_id, reason, expire)
                
                to_sign = []
                #if sign and binding != BINDING_HTTP_REDIRECT:

                if sign is None:
                    sign = self.logout_requests_signed_default

                if sign:
                    request.signature = pre_signature_part(request.id,
                                                    self.sec.my_cert, 1)
                    to_sign = [(class_name(request), request.id)]

                logger.info("REQUEST: %s" % request)

                request = signed_instance_factory(request, self.sec, to_sign)
        
                if binding == BINDING_SOAP:
                    response = send_using_soap(request, destination, 
                                                self.config.key_file,
                                                self.config.cert_file,
                                                ca_certs=self.config.ca_certs)
                    if response:
                        logger.info("Verifying response")
                        response = self.logout_response(response)

                    if response:
                        not_done.remove(entity_id)
                        logger.info("OK response from %s" % destination)
                    else:
                        logger.info(
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

    def handle_logout_response(self, response):
        """ handles a Logout response 
        
        :param response: A response.Response instance
        :return: 4-tuple of (session_id of the last sent logout request,
            response message, response headers and message)
        """

        logger.info("state: %s" % (self.state,))
        status = self.state[response.in_response_to]
        logger.info("status: %s" % (status,))
        issuer = response.issuer()
        logger.info("issuer: %s" % issuer)
        del self.state[response.in_response_to]
        if status["entity_ids"] == [issuer]: # done
            self.local_logout(status["subject_id"])
            return 0, "200 Ok", [("Content-type","text/html")], []
        else:
            status["entity_ids"].remove(issuer)
            return self.do_logout(status["subject_id"], status["entity_ids"],
                                  status["reason"], status["not_on_or_after"],
                                  status["sign"])

    def do_http_redirect_logout(self, get, subject_id):
        """ Deal with a LogoutRequest received through HTTP redirect

        :param get: The request as a dictionary 
        :param subject_id: the id of the current logged user
        :return: a tuple with a list of header tuples (presently only location)
            and a status which will be True in case of success or False 
            otherwise.
        """
        headers = []
        success = False

        try:
            saml_request = get['SAMLRequest']
        except KeyError:
            return None

        if saml_request:
            xml = decode_base64_and_inflate(saml_request)

            request = samlp.logout_request_from_string(xml)
            logger.debug(request)

            if request.name_id.text == subject_id:
                status = samlp.STATUS_SUCCESS
                success = self.local_logout(subject_id)
            else:
                status = samlp.STATUS_REQUEST_DENIED

            destination, (id, response) = self.create_logout_response(
                                                            request.issuer.text,
                                                            request.id,
                                                            status)

            logger.info("RESPONSE: {0:>s}".format(response))

            if 'RelayState' in get:
                rstate = get['RelayState']
            else:
                rstate = ""
                
            (headers, _body) = http_redirect_message(str(response), 
                                                     destination,
                                                     rstate, 'SAMLResponse')

        return headers, success

    def handle_logout_request(self, request, subject_id,
                              binding=BINDING_HTTP_REDIRECT):
        """ Deal with a LogoutRequest 

        :param request: The request. The format depends on which binding is
            used.
        :param subject_id: the id of the current logged user
        :return: What is returned also depends on which binding is used.
        """

        if binding == BINDING_HTTP_REDIRECT:
            return self.do_http_redirect_logout(request, subject_id)

    # MUST use SOAP for
    # AssertionIDRequest, SubjectQuery,
    # AuthnQuery, AttributeQuery, or AuthzDecisionQuery

    def _soap_query_response(self, destination, query_type, **kwargs):
        _create_func = getattr(self, "create_%s" % query_type)
        _response_func = getattr(self, "%s_response" % query_type)

        id, query = _create_func(destination, **kwargs)

        response = send_using_soap(query, destination,
                                   self.config.key_file,
                                   self.config.cert_file,
                                   ca_certs=self.config.ca_certs)

        if response:
            logger.info("Verifying response")
            if "response_args" in kwargs:
                response = _response_func(response, **kwargs["response_args"])
            else:
                response = _response_func(response)

        if response:
            #not_done.remove(entity_id)
            logger.info("OK response from %s" % destination)
            return response
        else:
            logger.info("NOT OK response from %s" % destination)

        return None

    #noinspection PyUnusedLocal
    def do_authz_decision_query(self, entity_id, action,
                                subject_id, nameid_format,
                                evidence=None, resource=None,
                                sp_name_qualifier=None,
                                name_qualifier=None,
                                consent=None, extensions=None, sign=False):

        subject = saml.Subject(
            name_id = saml.NameID(text=subject_id,
                                  format=nameid_format,
                                  sp_name_qualifier=sp_name_qualifier,
                                  name_qualifier=name_qualifier))

        for destination in self.config.authz_service_endpoints(entity_id,
                                                               BINDING_SOAP):
            resp = self._soap_query_response(destination,
                                             "authz_decision_query",
                                             action=action, evidence=evidence,
                                             resource=resource, subject=subject)
            if resp:
                return resp

        return None

    def do_assertion_id_request(self, assertion_ids, entity_id,
                                consent=None, extensions=None, sign=False):

        destination = self.metadata.assertion_id_request_service(entity_id,
                                                                 BINDING_SOAP)[0]

        if isinstance(assertion_ids, basestring):
            assertion_ids = [assertion_ids]

        _id_refs = [AssertionIDRef(_id) for _id in assertion_ids]

        return self._soap_query_response(destination, "assertion_id_request",
                                         assertion_id_refs=_id_refs,
                                         consent=consent, extensions=extensions,
                                         sign=sign)


    def do_authn_query(self, entity_id,
                       consent=None, extensions=None, sign=False):

        destination = self.metadata.authn_request_service(entity_id,
                                                          BINDING_SOAP)[0]

        return self._soap_query_response(destination, "authn_query",
                                         consent=consent, extensions=extensions,
                                         sign=sign)

    def do_attribute_query(self, subject_id, entityid,
                           attribute=None, sp_name_qualifier=None,
                           name_qualifier=None, nameid_format=None,
                           real_id=None, consent=None, extensions=None,
                           sign=False):
        """ Does a attribute request to an attribute authority, this is
        by default done over SOAP. Other bindings could be used but not
        supported right now.

        :param subject_id: The identifier of the subject
        :param entityid: To whom the query should be sent
        :param attribute: A dictionary of attributes and values that is asked for
        :param sp_name_qualifier: The unique identifier of the
            service provider or affiliation of providers for whom the
            identifier was generated.
        :param name_qualifier: The unique identifier of the identity
            provider that generated the identifier.
        :param nameid_format: The format of the name ID
        :param real_id: The identifier which is the key to this entity in the
            identity database
        :return: The attributes returned
        """

        location = self._sso_location(entityid, BINDING_SOAP)

        response_args = {"real_id": real_id}

        return self._soap_query_response(location, "attribute_query",
                                         consent=consent, extensions=extensions,
                                         sign=sign, subject_id=subject_id,
                                         attribute=attribute,
                                         sp_name_qualifier=sp_name_qualifier,
                                         name_qualifier=name_qualifier,
                                         nameid_format=nameid_format,
                                         response_args=response_args)

#        if response:
#            logger.info("Verifying response")
#
#            try:
#                # synchronous operation
#                aresp = attribute_response(self.config, self.config.entityid)
#            except Exception, exc:
#                logger.error("%s", (exc,))
#                return None
#
#            _resp = aresp.loads(response, False, soapclient.response).verify()
#            if _resp is None:
#                logger.error("Didn't like the response")
#                return None
#
#            session_info = _resp.session_info()
#
#            if session_info:
#                if real_id is not None:
#                    session_info["name_id"] = real_id
#                self.users.add_information_about_person(session_info)
#
#            logger.info("session: %s" % session_info)
#            return session_info
#        else:
#            logger.info("No response")
#            return None
