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
from urllib import urlencode
from urlparse import urlparse

from saml2.entity import Entity

from saml2.mdstore import destinations
from saml2.profile import paos, ecp
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.samlp import AuthnQuery
from saml2.samlp import NameIDMappingRequest
from saml2.samlp import AttributeQuery
from saml2.samlp import AuthzDecisionQuery
from saml2.samlp import AuthnRequest

import saml2
import time
from saml2.soap import make_soap_enveloped_saml_thingy

try:
    from urlparse import parse_qs
except ImportError:
    # Compatibility with Python <= 2.5
    from cgi import parse_qs

from saml2.s_utils import signature, UnravelError
from saml2.s_utils import do_attributes

from saml2 import samlp, BINDING_SOAP, SAMLError
from saml2 import saml
from saml2 import soap
from saml2.population import Population

from saml2.response import AttributeResponse, StatusError
from saml2.response import AuthzResponse
from saml2.response import AssertionIDResponse
from saml2.response import AuthnQueryResponse
from saml2.response import NameIDMappingResponse
from saml2.response import AuthnResponse

from saml2 import BINDING_HTTP_REDIRECT
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

ECP_SERVICE = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
ACTOR = "http://schemas.xmlsoap.org/soap/actor/next"
MIME_PAOS = "application/vnd.paos+xml"


class IdpUnspecified(SAMLError):
    pass


class VerifyError(SAMLError):
    pass


class LogoutError(SAMLError):
    pass


class NoServiceDefined(SAMLError):
    pass


class Base(Entity):
    """ The basic pySAML2 service provider class """

    def __init__(self, config=None, identity_cache=None, state_cache=None,
                 virtual_organization="", config_file=""):
        """
        :param config: A saml2.config.Config instance
        :param identity_cache: Where the class should store identity information
        :param state_cache: Where the class should keep state information
        :param virtual_organization: A specific virtual organization
        """

        Entity.__init__(self, "sp", config, config_file, virtual_organization)

        self.users = Population(identity_cache)

        # for server state storage
        if state_cache is None:
            self.state = {}  # in memory storage
        else:
            self.state = state_cache

        for foo in ["allow_unsolicited", "authn_requests_signed",
                    "logout_requests_signed"]:
            if self.config.getattr(foo, "sp") == 'true':
                setattr(self, foo, True)
            else:
                setattr(self, foo, False)

        # extra randomness
        self.allow_unsolicited = self.config.getattr("allow_unsolicited", "sp")

        self.artifact2response = {}
        self.logout_requests_signed = False

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

    def _sso_location(self, entityid=None, binding=BINDING_HTTP_REDIRECT):
        if entityid:
            # verify that it's in the metadata
            srvs = self.metadata.single_sign_on_service(entityid, binding)
            if srvs:
                return destinations(srvs)[0]
            else:
                logger.info("_sso_location: %s, %s" % (entityid, binding))
                raise IdpUnspecified("No IdP to send to given the premises")

        # get the idp location from the metadata. If there is more than one
        # IdP in the configuration raise exception
        eids = self.metadata.with_descriptor("idpsso")
        if len(eids) > 1:
            raise IdpUnspecified("Too many IdPs to choose from: %s" % eids)

        try:
            srvs = self.metadata.single_sign_on_service(eids.keys()[0], binding)
            return destinations(srvs)[0]
        except IndexError:
            raise IdpUnspecified("No IdP to send to given the premises")

    def _my_name(self):
        return self.config.name

    #
    # Public API
    #

    def add_vo_information_about_user(self, name_id):
        """ Add information to the knowledge I have about the user. This is
        for Virtual organizations.

        :param name_id: The subject identifier
        :return: A possibly extended knowledge.
        """

        ava = {}
        try:
            (ava, _) = self.users.get_identity(name_id)
        except KeyError:
            pass

        # is this a Virtual Organization situation
        if self.vorg:
            if self.vorg.do_aggregation(name_id):
                # Get the extended identity
                ava = self.users.get_identity(name_id)[0]
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

    def create_authn_request(self, destination, vorg="", scoping=None,
                             binding=saml2.BINDING_HTTP_POST,
                             nameid_format=NAMEID_FORMAT_TRANSIENT,
                             service_url_binding=None, message_id=0,
                             consent=None, extensions=None, sign=None,
                             allow_create=False, sign_prepare=False, **kwargs):
        """ Creates an authentication request.
        
        :param destination: Where the request should be sent.
        :param vorg: The virtual organization the service belongs to.
        :param scoping: The scope of the request
        :param binding: The protocol to use for the Response !!
        :param nameid_format: Format of the NameID
        :param service_url_binding: Where the reply should be sent dependent
            on reply binding.
        :param message_id: The identifier for this request
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param sign: Whether the request should be signed or not.
        :param sign_prepare: Whether the signature should be prepared or not.
        :param allow_create: If the identity provider is allowed, in the course
            of fulfilling the request, to create a new identifier to represent
            the principal.
        :param kwargs: Extra key word arguments
        :return: <samlp:AuthnRequest> instance
        """

        args = {}
        try:
            args["assertion_consumer_service_url"] = kwargs[
                "assertion_consumer_service_url"]
            del kwargs["assertion_consumer_service_url"]
        except KeyError:
            try:
                args["attribute_consuming_service_index"] = str(kwargs[
                    "attribute_consuming_service_index"])
                del kwargs["attribute_consuming_service_index"]
            except KeyError:
                if service_url_binding is None:
                    service_url = self.service_url(binding)
                else:
                    service_url = self.service_url(service_url_binding)
                args["assertion_consumer_service_url"] = service_url

        try:
            args["provider_name"] = kwargs["provider_name"]
        except KeyError:
            if binding == BINDING_PAOS:
                pass
            else:
                args["provider_name"] = self._my_name()

        try:
            args["name_id_policy"] = kwargs["name_id_policy"]
            del kwargs["name_id_policy"]
        except KeyError:
            if allow_create:
                allow_create = "true"
            else:
                allow_create = "false"

            # Profile stuff, should be configurable
            if nameid_format is None:
                name_id_policy = samlp.NameIDPolicy(
                    allow_create=allow_create, format=NAMEID_FORMAT_TRANSIENT)
            elif nameid_format == "":
                name_id_policy = None
            else:
                name_id_policy = samlp.NameIDPolicy(allow_create=allow_create,
                                                    format=nameid_format)

            if name_id_policy and vorg:
                try:
                    name_id_policy.sp_name_qualifier = vorg
                    name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
                except KeyError:
                    pass
            args["name_id_policy"] = name_id_policy

        if kwargs:
            _args, extensions = self._filter_args(AuthnRequest(), extensions,
                                                  **kwargs)
            args.update(_args)

        try:
            del args["id"]
        except KeyError:
            pass

        return self._message(AuthnRequest, destination, message_id, consent,
                             extensions, sign, sign_prepare,
                             protocol_binding=binding,
                             scoping=scoping, **args)

    def create_attribute_query(self, destination, name_id=None,
                               attribute=None, message_id=0, consent=None,
                               extensions=None, sign=False, sign_prepare=False,
                               **kwargs):
        """ Constructs an AttributeQuery
        
        :param destination: To whom the query should be sent
        :param name_id: The identifier of the subject
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
        :param format: The format of the name ID
        :param message_id: The identifier of the session
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param sign: Whether the query should be signed or not.
        :param sign_prepare: Whether the Signature element should be added.
        :return: An AttributeQuery instance
        """

        if name_id is None:
            if "subject_id" in kwargs:
                name_id = saml.NameID(text=kwargs["subject_id"])
                for key in ["sp_name_qualifier", "name_qualifier",
                            "format"]:
                    try:
                        setattr(name_id, key, kwargs[key])
                    except KeyError:
                        pass
            else:
                raise AttributeError("Missing required parameter")
        elif isinstance(name_id, basestring):
            name_id = saml.NameID(text=name_id)
            for key in ["sp_name_qualifier", "name_qualifier", "format"]:
                try:
                    setattr(name_id, key, kwargs[key])
                except KeyError:
                    pass

        subject = saml.Subject(name_id=name_id)

        if attribute:
            attribute = do_attributes(attribute)

        return self._message(AttributeQuery, destination, message_id, consent,
                             extensions, sign, sign_prepare, subject=subject,
                             attribute=attribute)

    # MUST use SOAP for
    # AssertionIDRequest, SubjectQuery,
    # AuthnQuery, AttributeQuery, or AuthzDecisionQuery
    def create_authz_decision_query(self, destination, action,
                                    evidence=None, resource=None, subject=None,
                                    message_id=0, consent=None, extensions=None,
                                    sign=None, **kwargs):
        """ Creates an authz decision query.

        :param destination: The IdP endpoint
        :param action: The action you want to perform (has to be at least one)
        :param evidence: Why you should be able to perform the action
        :param resource: The resource you want to perform the action on
        :param subject: Who wants to do the thing
        :param message_id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
        :param sign: Whether the request should be signed or not.
        :return: AuthzDecisionQuery instance
        """

        return self._message(AuthzDecisionQuery, destination, message_id,
                             consent, extensions, sign, action=action,
                             evidence=evidence, resource=resource,
                             subject=subject)

    def create_authz_decision_query_using_assertion(self, destination,
                                                    assertion, action=None,
                                                    resource=None,
                                                    subject=None, message_id=0,
                                                    consent=None,
                                                    extensions=None,
                                                    sign=False):
        """ Makes an authz decision query based on a previously received
        Assertion.

        :param destination: The IdP endpoint to send the request to
        :param assertion: An Assertion instance
        :param action: The action you want to perform (has to be at least one)
        :param resource: The resource you want to perform the action on
        :param subject: Who wants to do the thing
        :param message_id: Message identifier
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

        return self.create_authz_decision_query(
            destination, _action, saml.Evidence(assertion=assertion),
            resource, subject, message_id=message_id, consent=consent,
            extensions=extensions, sign=sign)

    def create_assertion_id_request(self, assertion_id_refs, **kwargs):
        """

        :param assertion_id_refs:
        :return: One ID ref
        """
#        id_refs = [AssertionIDRef(text=s) for s in assertion_id_refs]
#
#        return self._message(AssertionIDRequest, destination, id, consent,
#                             extensions, sign, assertion_id_ref=id_refs )

        if isinstance(assertion_id_refs, basestring):
            return assertion_id_refs
        else:
            return assertion_id_refs[0]

    def create_authn_query(self, subject, destination=None, authn_context=None,
                           session_index="", message_id=0, consent=None,
                           extensions=None, sign=False):
        """

        :param subject: The subject its all about as a <Subject> instance
        :param destination: The IdP endpoint to send the request to
        :param authn_context: list of <RequestedAuthnContext> instances
        :param session_index: a specified session index
        :param message_id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
        :param sign: Whether the request should be signed or not.
        :return:
        """
        return self._message(AuthnQuery, destination, message_id, consent, extensions,
                             sign, subject=subject, session_index=session_index,
                             requested_authn_context=authn_context)

    def create_name_id_mapping_request(self, name_id_policy,
                                       name_id=None, base_id=None,
                                       encrypted_id=None, destination=None,
                                       message_id=0, consent=None, extensions=None,
                                       sign=False):
        """

        :param name_id_policy:
        :param name_id:
        :param base_id:
        :param encrypted_id:
        :param destination:
        :param message_id: Message identifier
        :param consent: If the principal gave her consent to this request
        :param extensions: Possible request extensions
        :param sign: Whether the request should be signed or not.
        :return:
        """

        # One of them must be present
        assert name_id or base_id or encrypted_id

        if name_id:
            return self._message(NameIDMappingRequest, destination, message_id,
                                 consent, extensions, sign,
                                 name_id_policy=name_id_policy, name_id=name_id)
        elif base_id:
            return self._message(NameIDMappingRequest, destination, message_id,
                                 consent, extensions, sign,
                                 name_id_policy=name_id_policy, base_id=base_id)
        else:
            return self._message(NameIDMappingRequest, destination, message_id,
                                 consent, extensions, sign,
                                 name_id_policy=name_id_policy,
                                 encrypted_id=encrypted_id)

    # ======== response handling ===========

    def parse_authn_request_response(self, xmlstr, binding, outstanding=None):
        """ Deal with an AuthnResponse

        :param xmlstr: The reply as a xml string
        :param binding: Which binding that was used for the transport
        :param outstanding: A dictionary with session IDs as keys and
            the original web request from the user before redirection
            as values.
        :return: An response.AuthnResponse or None
        """

        try:
            _ = self.config.entityid
        except KeyError:
            raise SAMLError("Missing entity_id specification")

        resp = None
        if xmlstr:
            kwargs = {
                "outstanding_queries": outstanding,
                "allow_unsolicited": self.allow_unsolicited,
                "return_addr": self.service_url(),
                "entity_id": self.config.entityid,
                "attribute_converters": self.config.attribute_converters,
                "allow_unknown_attributes": self.config.allow_unknown_attributes,
            }
            try:
                resp = self._parse_response(xmlstr, AuthnResponse,
                                            "assertion_consumer_service",
                                            binding, **kwargs)
            except StatusError, err:
                logger.error("SAML status error: %s" % err)
                raise
            except UnravelError:
                return None
            except Exception, exc:
                logger.error("%s" % exc)
                raise

            #logger.debug(">> %s", resp)

            if resp is None:
                return None
            elif isinstance(resp, AuthnResponse):
                #self.users.add_information_about_person(resp.session_info())
                #logger.info("--- ADDED person info ----")
                pass
            else:
                logger.error("Response type not supported: %s" % (
                    saml2.class_name(resp),))
        return resp

    # ------------------------------------------------------------------------
    # SubjectQuery, AuthnQuery, RequestedAuthnContext, AttributeQuery,
    # AuthzDecisionQuery all get Response as response

    def parse_authz_decision_query_response(self, response,
                                            binding=BINDING_SOAP):
        """ Verify that the response is OK
        """
        kwargs = {"entity_id": self.config.entityid,
                  "attribute_converters": self.config.attribute_converters}

        return self._parse_response(response, AuthzResponse, "", binding,
                                    **kwargs)

    def parse_authn_query_response(self, response, binding=BINDING_SOAP):
        """ Verify that the response is OK
        """
        kwargs = {"entity_id": self.config.entityid,
                  "attribute_converters": self.config.attribute_converters}

        return self._parse_response(response, AuthnQueryResponse, "", binding,
                                    **kwargs)

    def parse_assertion_id_request_response(self, response, binding):
        """ Verify that the response is OK
        """
        kwargs = {"entity_id": self.config.entityid,
                  "attribute_converters": self.config.attribute_converters}

        res = self._parse_response(response, AssertionIDResponse, "", binding,
                                   **kwargs)
        return res

    # ------------------------------------------------------------------------

    def parse_attribute_query_response(self, response, binding):
        kwargs = {"entity_id": self.config.entityid,
                  "attribute_converters": self.config.attribute_converters}

        return self._parse_response(response, AttributeResponse,
                                    "attribute_consuming_service", binding,
                                    **kwargs)

    def parse_name_id_mapping_request_response(self, txt, binding=BINDING_SOAP):
        """

        :param txt: SOAP enveloped SAML message
        :param binding: Just a placeholder, it's always BINDING_SOAP
        :return: parsed and verified <NameIDMappingResponse> instance
        """

        return self._parse_response(txt, NameIDMappingResponse, "", binding)

    # ------------------- ECP ------------------------------------------------

    def create_ecp_authn_request(self, entityid=None, relay_state="",
                                 sign=False, **kwargs):
        """ Makes an authentication request.

        :param entityid: The entity ID of the IdP to send the request to
        :param relay_state: A token that can be used by the SP to know
            where to continue the conversation with the client
        :param sign: Whether the request should be signed or not.
        :return: SOAP message with the AuthnRequest
        """

        # ----------------------------------------
        # <paos:Request>
        # ----------------------------------------
        my_url = self.service_url(BINDING_PAOS)

        # must_understand and act according to the standard
        #
        paos_request = paos.Request(must_understand="1", actor=ACTOR,
                                    response_consumer_url=my_url,
                                    service=ECP_SERVICE)

        # ----------------------------------------
        # <ecp:RelayState>
        # ----------------------------------------

        relay_state = ecp.RelayState(actor=ACTOR, must_understand="1",
                                     text=relay_state)

        # ----------------------------------------
        # <samlp:AuthnRequest>
        # ----------------------------------------

        try:
            authn_req = kwargs["authn_req"]
        except KeyError:
            try:
                _binding = kwargs["binding"]
            except KeyError:
                _binding = BINDING_SOAP
                kwargs["binding"] = _binding

            logger.debug("entityid: %s, binding: %s" % (entityid, _binding))

            # The IDP publishes support for ECP by using the SOAP binding on
            # SingleSignOnService
            _, location = self.pick_binding("single_sign_on_service",
                                            [_binding], entity_id=entityid)
            authn_req = self.create_authn_request(
                location, service_url_binding=BINDING_PAOS, **kwargs)

        # ----------------------------------------
        # The SOAP envelope
        # ----------------------------------------

        soap_envelope = make_soap_enveloped_saml_thingy(authn_req,
                                                        [paos_request,
                                                         relay_state])

        return authn_req.id, "%s" % soap_envelope

    def parse_ecp_authn_response(self, txt, outstanding=None):
        rdict = soap.class_instances_from_soap_enveloped_saml_thingies(txt,
                                                                       [paos,
                                                                        ecp,
                                                                        samlp])

        _relay_state = None
        for item in rdict["header"]:
            if item.c_tag == "RelayState" and\
                    item.c_namespace == ecp.NAMESPACE:
                _relay_state = item

        response = self.parse_authn_request_response(rdict["body"],
                                                     BINDING_PAOS, outstanding)

        return response, _relay_state

    def can_handle_ecp_response(self, response):
        try:
            accept = response.headers["accept"]
        except KeyError:
            try:
                accept = response.headers["Accept"]
            except KeyError:
                return False

        if MIME_PAOS in accept:
            return True
        else:
            return False

    # ----------------------------------------------------------------------
    # IDP discovery
    # ----------------------------------------------------------------------

    def create_discovery_service_request(self, url, entity_id, **kwargs):
        """
        Created the HTTP redirect URL needed to send the user to the
        discovery service.

        :param url: The URL of the discovery service
        :param entity_id: The unique identifier of the service provider
        :param return: The discovery service MUST redirect the user agent
            to this location in response to this request
        :param policy: A parameter name used to indicate the desired behavior
            controlling the processing of the discovery service
        :param returnIDParam: A parameter name used to return the unique
            identifier of the selected identity provider to the original
            requester.
        :param isPassive: A boolean value True/False that controls
            whether the discovery service is allowed to visibly interact with
            the user agent.
        :return: A URL
        """
        args = {"entityID": entity_id}
        for key in ["policy", "returnIDParam"]:
            try:
                args[key] = kwargs[key]
            except KeyError:
                pass

        try:
            args["return"] = kwargs["return_url"]
        except KeyError:
            try:
                args["return"] = kwargs["return"]
            except KeyError:
                pass

        if "isPassive" in kwargs:
            if kwargs["isPassive"]:
                args["isPassive"] = "true"
            else:
                args["isPassive"] = "false"

        params = urlencode(args)
        return "%s?%s" % (url, params)

    def parse_discovery_service_response(self, url="", query="",
                                         returnIDParam="entityID"):
        """
        Deal with the response url from a Discovery Service

        :param url: the url the user was redirected back to or
        :param query: just the query part of the URL.
        :param returnIDParam: This is where the identifier of the IdP is
            place if it was specified in the query. Default is 'entityID'
        :return: The IdP identifier or "" if none was given
        """

        if url:
            part = urlparse(url)
            qsd = parse_qs(part[4])
        elif query:
            qsd = parse_qs(query)
        else:
            qsd = {}

        try:
            return qsd[returnIDParam][0]
        except KeyError:
            return ""
