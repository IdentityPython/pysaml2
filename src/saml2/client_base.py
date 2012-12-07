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
from saml2.saml import AssertionIDRef, NAMEID_FORMAT_TRANSIENT
from saml2.samlp import AuthnQuery
from saml2.samlp import LogoutRequest
from saml2.samlp import AssertionIDRequest
from saml2.samlp import NameIDMappingRequest
from saml2.samlp import AttributeQuery
from saml2.samlp import AuthzDecisionQuery
from saml2.samlp import AuthnRequest

import saml2
import time
import base64
try:
    from urlparse import parse_qs
except ImportError:
    # Compatibility with Python <= 2.5
    from cgi import parse_qs

from saml2.time_util import instant
from saml2.s_utils import signature, rndstr
from saml2.s_utils import sid
from saml2.s_utils import do_attributes
from saml2.s_utils import decode_base64_and_inflate

from saml2 import samlp, saml, class_name
from saml2 import VERSION
from saml2.sigver import pre_signature_part
from saml2.sigver import security_context, signed_instance_factory
from saml2.population import Population
from saml2.virtual_org import VirtualOrg
from saml2.config import config_factory

from saml2.response import response_factory, attribute_response
from saml2.response import LogoutResponse
from saml2.response import AuthnResponse

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_PAOS
import logging

logger = logging.getLogger(__name__)

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

class Base(object):
    """ The basic pySAML2 service provider class """

    def __init__(self, config=None, identity_cache=None, state_cache=None,
                 virtual_organization="",config_file=""):
        """
        :param config: A saml2.config.Config instance
        :param identity_cache: Where the class should store identity information
        :param state_cache: Where the class should keep state information
        :param virtual_organization: A specific virtual organization
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

        if self.config.vorg:
            for vo in self.config.vorg.values():
                vo.sp = self

        self.metadata = self.config.metadata
        self.config.setup_logger()

        # we copy the config.debug variable in an internal
        # field for convenience and because we may need to
        # change it during the tests
        self.debug = self.config.debug

        self.sec = security_context(self.config)

        if virtual_organization:
            if isinstance(virtual_organization, basestring):
                self.vorg = self.config.vorg[virtual_organization]
            elif isinstance(virtual_organization, VirtualOrg):
                self.vorg = virtual_organization
        else:
            self.vorg = {}

        for foo in ["allow_unsolicited", "authn_requests_signed",
                   "logout_requests_signed"]:
            if self.config.getattr("sp", foo) == 'true':
                setattr(self, foo, True)
            else:
                setattr(self, foo, False)

        # extra randomness
        self.seed = rndstr(32)
        self.logout_requests_signed_default = True
        self.allow_unsolicited = self.config.getattr("allow_unsolicited", "sp")

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
                logger.info("_sso_location: %s, %s" % (entityid,
                                                       binding))
                raise IdpUnspecified("No IdP to send to given the premises")

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
            raise IdpUnspecified("No IdP to send to given the premises")

    def _my_name(self):
        return self.config.name

    #
    # Public API
    #

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

    def service_url(self, binding=BINDING_HTTP_POST):
        _res = self.config.endpoint("assertion_consumer_service", binding, "sp")
        if _res:
            return _res[0]
        else:
            return None

    def _message(self, request_cls, destination=None, id=0,
                 consent=None, extensions=None, sign=False, **kwargs):
        """
        Some parameters appear in all requests so simplify by doing
        it in one place

        :param request_cls: The specific request type
        :param destination: The recipient
        :param id: A message identifier
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param kwargs: Key word arguments specific to one request type
        :return: An instance of the request_cls
        """
        if not id:
            id = sid(self.seed)

        req = request_cls(id=id, version=VERSION, issue_instant=instant(),
                          issuer=self._issuer(), **kwargs)

        if destination:
            req.destination = destination

        if consent:
            req.consent = consent

        if extensions:
            req.extensions = extensions

        if sign:
            req.signature = pre_signature_part(req.id, self.sec.my_cert, 1)
            to_sign = [(class_name(req), req.id)]
        else:
            to_sign = []

        logger.info("REQUEST: %s" % req)

        return signed_instance_factory(req, self.sec, to_sign)

    def create_authn_request(self, destination, vorg="", scoping=None,
                             binding=saml2.BINDING_HTTP_POST,
                             nameid_format=NAMEID_FORMAT_TRANSIENT,
                             service_url_binding=None,
                             id=0, consent=None, extensions=None, sign=None,
                             allow_create=False):
        """ Creates an authentication request.
        
        :param destination: Where the request should be sent.
        :param vorg: The virtual organization the service belongs to.
        :param scoping: The scope of the request
        :param binding: The protocol to use for the Response !!
        :param nameid_format: Format of the NameID
        :param service_url_binding: Where the reply should be sent dependent
            on reply binding.
        :param id: The identifier for this request
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param sign: Whether the request should be signed or not.
        :param allow_create: If the identity provider is allowed, in the course
            of fulfilling the request, to create a new identifier to represent
            the principal.
        :return: <samlp:AuthnRequest> instance
        """

        if service_url_binding is None:
            service_url = self.service_url(binding)
        else:
            service_url = self.service_url(service_url_binding)

        if binding == BINDING_PAOS:
            my_name = None
            location = None
        else:
            my_name = self._my_name()

        if allow_create:
            allow_create="true"
        else:
            allow_create="false"

        # Profile stuff, should be configurable
        if nameid_format is None or nameid_format == NAMEID_FORMAT_TRANSIENT:
            name_id_policy = samlp.NameIDPolicy(allow_create=allow_create,
                                                format=NAMEID_FORMAT_TRANSIENT)
        else:
            name_id_policy = samlp.NameIDPolicy(allow_create=allow_create,
                                                format=nameid_format)

        if vorg:
            try:
                name_id_policy.sp_name_qualifier = vorg
                name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
            except KeyError:
                pass

        return self._message(AuthnRequest, destination, id, consent,
                             extensions, sign,
                             assertion_consumer_service_url=service_url,
                             protocol_binding=binding,
                             name_id_policy=name_id_policy,
                             provider_name=my_name,
                             scoping=scoping)


    def create_attribute_query(self, destination, subject_id,
                               attribute=None, sp_name_qualifier=None,
                               name_qualifier=None, nameid_format=None,
                               id=0, consent=None, extensions=None, sign=False,
                               **kwargs):
        """ Constructs an AttributeQuery
        
        :param destination: To whom the query should be sent
        :param subject_id: The identifier of the subject
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
        :param id: The identifier of the session
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param sign: Whether the query should be signed or not.
        :return: An AttributeQuery instance
        """


        subject = saml.Subject(
            name_id = saml.NameID(text=subject_id,
                                  format=nameid_format,
                                  sp_name_qualifier=sp_name_qualifier,
                                  name_qualifier=name_qualifier))

        if attribute:
            attribute = do_attributes(attribute)

        return self._message(AttributeQuery, destination, id, consent,
                             extensions, sign, subject=subject,
                             attribute=attribute)


    def create_logout_request(self, destination, subject_id, issuer_entity_id,
                              reason=None, expire=None,
                              id=0, consent=None, extensions=None, sign=False):
        """ Constructs a LogoutRequest
        
        :param destination: Destination of the request
        :param subject_id: The identifier of the subject
        :param issuer_entity_id: The entity ID of the IdP the request is
            target at.
        :param reason: An indication of the reason for the logout, in the
            form of a URI reference.
        :param expire: The time at which the request expires,
            after which the recipient may discard the message.
        :param id: Request identifier
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param sign: Whether the query should be signed or not.
        :return: A LogoutRequest instance
        """

        name_id = saml.NameID(
            text = self.users.get_entityid(subject_id, issuer_entity_id,
                                           False))

        return self._message(LogoutRequest, destination, id,
                             consent, extensions, sign, name_id = name_id,
                             reason=reason, not_on_or_after=expire)

    def create_logout_response(self, idp_entity_id, request_id,
                             status_code, binding=BINDING_HTTP_REDIRECT):
        """ Constructs a LogoutResponse

        :param idp_entity_id: The entityid of the IdP that want to do the
            logout
        :param request_id: The Id of the request we are replying to
        :param status_code: The status code of the response
        :param binding: The type of binding that will be used for the response
        :return: A LogoutResponse instance
        """

        destination = self.config.single_logout_services(idp_entity_id,
                                                         binding)[0]

        status = samlp.Status(
            status_code=samlp.StatusCode(value=status_code))

        return destination, self._message(LogoutResponse, destination,
                                          in_response_to=request_id,
                                          status=status)

    # MUST use SOAP for
    # AssertionIDRequest, SubjectQuery,
    # AuthnQuery, AttributeQuery, or AuthzDecisionQuery

    def create_authz_decision_query(self, destination, action,
                                    evidence=None, resource=None, subject=None,
                                    id=0, consent=None, extensions=None,
                                    sign=None):
        """ Creates an authz decision query.

        :param destination: The IdP endpoint
        :param action: The action you want to perform (has to be at least one)
        :param evidence: Why you should be able to perform the action
        :param resource: The resource you want to perform the action on
        :param subject: Who wants to do the thing
        :param id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
        :param sign: Whether the request should be signed or not.
        :return: AuthzDecisionQuery instance
        """

        return self._message(AuthzDecisionQuery, destination, id, consent,
                             extensions, sign, action=action, evidence=evidence,
                             resource=resource, subject=subject)

    def create_authz_decision_query_using_assertion(self, destination, assertion,
                                                    action=None, resource=None,
                                                    subject=None, id=0,
                                                    consent=None,
                                                    extensions=None,
                                                    sign=False):
        """ Makes an authz decision query.

        :param destination: The IdP endpoint to send the request to
        :param assertion: An Assertion instance
        :param action: The action you want to perform (has to be at least one)
        :param resource: The resource you want to perform the action on
        :param subject: Who wants to do the thing
        :param id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
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

        return self.create_authz_decision_query(destination,
                                                _action,
                                                saml.Evidence(assertion=assertion),
                                                resource, subject,
                                                id=id,
                                                consent=consent,
                                                extensions=extensions,
                                                sign=sign)

    def create_assertion_id_request(self, assertion_id_refs, destination=None,
                                    id=0, consent=None, extensions=None,
                                    sign=False):
        """

        :param assertion_id_refs:
        :param destination: The IdP endpoint to send the request to
        :param id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
        :param sign: Whether the request should be signed or not.
        :return: AssertionIDRequest instance
        """
        id_refs = [AssertionIDRef(text=s) for s in assertion_id_refs]

        return self._message(AssertionIDRequest, destination, id, consent,
                             extensions, sign, assertion_id_refs=id_refs )


    def create_authn_query(self, subject, destination=None,
                           authn_context=None, session_index="",
                           id=0, consent=None, extensions=None, sign=False):
        """

        :param subject:
        :param destination: The IdP endpoint to send the request to
        :param authn_context:
        :param session_index:
        :param id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
        :param sign: Whether the request should be signed or not.
        :return:
        """
        return self._message(AuthnQuery, destination, id, consent, extensions,
                             sign, subject=subject, session_index=session_index,
                             requested_auth_context=authn_context)

    def create_nameid_mapping_request(self, nameid_policy,
                                      nameid=None, baseid=None,
                                      encryptedid=None, destination=None,
                                      id=0, consent=None, extensions=None,
                                      sign=False):
        """

        :param nameid_policy:
        :param nameid:
        :param baseid:
        :param encryptedid:
        :param destination:
        :param id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
        :param sign: Whether the request should be signed or not.
        :return:
        """

        # One of them must be present
        assert nameid or baseid or encryptedid

        if nameid:
            return self._message(NameIDMappingRequest, destination, id, consent,
                                 extensions, sign, nameid_policy=nameid_policy,
                                 nameid=nameid)
        elif baseid:
            return self._message(NameIDMappingRequest, destination, id, consent,
                                 extensions, sign, nameid_policy=nameid_policy,
                                 baseid=baseid)
        else:
            return self._message(NameIDMappingRequest, destination, id, consent,
                                 extensions, sign, nameid_policy=nameid_policy,
                                 encryptedid=encryptedid)

    def create_manage_nameid_request(self):
        pass

    # ======== response handling ===========

    def _response(self, post, outstanding, decode=True, asynchop=True):
        """ Deal with an AuthnResponse or LogoutResponse

        :param post: The reply as a dictionary
        :param outstanding: A dictionary with session IDs as keys and
            the original web request from the user before redirection
            as values.
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

        reply_addr = self.service_url()

        resp = None
        if saml_response:
            try:
                resp = response_factory(saml_response, self.config,
                                        reply_addr, outstanding, decode=decode,
                                        asynchop=asynchop,
                                        allow_unsolicited=self.allow_unsolicited)
            except Exception, exc:
                logger.error("%s" % exc)
                return None
            logger.debug(">> %s", resp)

            resp = resp.verify()
            if isinstance(resp, AuthnResponse):
                self.users.add_information_about_person(resp.session_info())
                logger.info("--- ADDED person info ----")
            else:
                logger.error("Response type not supported: %s" % (
                    saml2.class_name(resp),))
        return resp

    def authn_request_response(self, post, outstanding, decode=True,
                               asynchop=True):
        return self._response(post, outstanding, decode, asynchop)

    def logout_response(self, xmlstr, binding=BINDING_SOAP):
        """ Deal with a LogoutResponse

        :param xmlstr: The response as a xml string
        :param binding: What type of binding this message came through.
        :return: None if the reply doesn't contain a valid SAML LogoutResponse,
            otherwise the reponse if the logout was successful and None if it
            was not.
        """

        response = None

        if xmlstr:
            try:
                # expected return address
                return_addr = self.config.endpoint("single_logout_service",
                                                   binding=binding)[0]
            except Exception:
                logger.info("Not supposed to handle this!")
                return None

            try:
                response = LogoutResponse(self.sec, return_addr)
            except Exception, exc:
                logger.info("%s" % exc)
                return None

            if binding == BINDING_HTTP_REDIRECT:
                xmlstr = decode_base64_and_inflate(xmlstr)
            elif binding == BINDING_HTTP_POST:
                xmlstr = base64.b64decode(xmlstr)

            logger.debug("XMLSTR: %s" % xmlstr)

            response = response.loads(xmlstr, False)

            if response:
                response = response.verify()

            if not response:
                return None

            logger.debug(response)

        return response

    #noinspection PyUnusedLocal
    def authz_decision_query_response(self, response):
        """ Verify that the response is OK
        """
        resp = samlp.response_from_string(response)
        return resp

    def assertion_id_request_response(self, response):
        """ Verify that the response is OK
        """
        resp = samlp.response_from_string(response)
        return resp

    def authn_query_response(self, response):
        """ Verify that the response is OK
        """
        resp = samlp.response_from_string(response)
        return resp

    def attribute_query_response(self, response, **kwargs):
        try:
            # synchronous operation
            aresp = attribute_response(self.config, self.config.entityid)
        except Exception, exc:
            logger.error("%s", (exc,))
            return None

        _resp = aresp.loads(response, False, response).verify()
        if _resp is None:
            logger.error("Didn't like the response")
            return None

        session_info = _resp.session_info()

        if session_info:
            if "real_id" in kwargs:
                session_info["name_id"] = kwargs["real_id"]
            self.users.add_information_about_person(session_info)

        logger.info("session: %s" % session_info)
        return session_info
