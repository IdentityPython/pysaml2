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

"""Contains classes and functions that a SAML2.0 Identity provider (IdP) 
or attribute authority (AA) may use to conclude its tasks.
"""
import logging

import shelve
import sys
import memcache
from saml2.httpbase import HTTPBase
from saml2.mdstore import destinations

from saml2 import saml, BINDING_HTTP_POST
from saml2 import class_name
from saml2 import soap
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_PAOS

from saml2.request import AuthnRequest
from saml2.request import AttributeQuery
from saml2.request import LogoutRequest

from saml2.s_utils import sid
from saml2.s_utils import MissingValue
from saml2.s_utils import success_status_factory
from saml2.s_utils import OtherError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import error_status_factory

from saml2.time_util import instant

from saml2.sigver import security_context
from saml2.sigver import signed_instance_factory
from saml2.sigver import pre_signature_part
from saml2.sigver import response_factory, logoutresponse_factory

from saml2.config import config_factory

from saml2.assertion import Assertion, Policy, restriction_from_attribute_spec, filter_attribute_value_assertions

logger = logging.getLogger(__name__)

class UnknownVO(Exception):
    pass
    
class Identifier(object):
    """ A class that handles identifiers of objects """
    def __init__(self, db, voconf=None):
        if isinstance(db, basestring):
            self.map = shelve.open(db, writeback=True)
        else:
            self.map = db
        self.voconf = voconf

    def _store(self, typ, entity_id, local, remote):
        self.map["|".join([typ, entity_id, "f", local])] = remote
        self.map["|".join([typ, entity_id, "b", remote])] = local
    
    def _get_remote(self, typ, entity_id, local):
        return self.map["|".join([typ, entity_id, "f", local])]

    def _get_local(self, typ, entity_id, remote):
        return self.map["|".join([typ, entity_id, "b", remote])]
        
    def persistent(self, entity_id, subject_id):
        """ Keeps the link between a permanent identifier and a 
        temporary/pseudo-temporary identifier for a subject
        
        The store supports look-up both ways: from a permanent local
        identifier to a identifier used talking to a SP and from an
        identifier given back by an SP to the local permanent.
        
        :param entity_id: SP entity ID or VO entity ID
        :param subject_id: The local permanent identifier of the subject
        :return: An arbitrary identifier for the subject unique to the
            service/group of services/VO with a given entity_id
        """
        try:
            return self._get_remote("persistent", entity_id, subject_id)
        except KeyError:
            temp_id = "xyz"
            while True:
                temp_id = sid()
                try:
                    self._get_local("persistent", entity_id, temp_id)
                except KeyError:
                    break
            self._store("persistent", entity_id, subject_id, temp_id)
            self.map.sync()
            
            return temp_id

    def _get_vo_identifier(self, sp_name_qualifier, identity):
        try:
            vo = self.voconf[sp_name_qualifier]
            try:
                subj_id = identity[vo.common_identifier]
            except KeyError:
                raise MissingValue("Common identifier")
        except (KeyError, TypeError):
            raise UnknownVO("%s" % sp_name_qualifier)

        nameid_format = vo.nameid_format
        if not nameid_format:
            nameid_format = saml.NAMEID_FORMAT_PERSISTENT

        return saml.NameID(format=nameid_format,
                            sp_name_qualifier=sp_name_qualifier,
                            text=subj_id)
    
    def persistent_nameid(self, sp_name_qualifier, userid):
        """ Get or create a persistent identifier for this object to be used
        when communicating with servers using a specific SPNameQualifier
        
        :param sp_name_qualifier: An identifier for a 'context'
        :param userid: The local permanent identifier of the object 
        :return: A persistent random identifier.
        """
        subj_id = self.persistent(sp_name_qualifier, userid)
        return saml.NameID(format=saml.NAMEID_FORMAT_PERSISTENT,
                            sp_name_qualifier=sp_name_qualifier,
                            text=subj_id)

    def transient_nameid(self, sp_entity_id, userid):
        """ Returns a random one-time identifier. One-time means it is
        kept around as long as the session is active.
        
        :param sp_entity_id: A qualifier to bind the created identifier to
        :param userid: The local persistent identifier for the subject.
        :return: The created identifier,
        """
        temp_id = sid()
        while True:
            try:
                _ = self._get_local("transient", sp_entity_id, temp_id)
                temp_id = sid()
            except KeyError:
                break
        self._store("transient", sp_entity_id, userid, temp_id)
        self.map.sync()

        return saml.NameID(format=saml.NAMEID_FORMAT_TRANSIENT,
                            sp_name_qualifier=sp_entity_id,
                            text=temp_id)

    def email_nameid(self, sp_name_qualifier, userid):
        return saml.NameID(format=saml.NAMEID_FORMAT_EMAILADDRESS,
                       sp_name_qualifier=sp_name_qualifier,
                       text=userid)

    def construct_nameid(self, local_policy, userid, sp_entity_id,
                        identity=None, name_id_policy=None, sp_nid=None):
        """ Returns a name_id for the object. How the name_id is 
        constructed depends on the context.
        
        :param local_policy: The policy the server is configured to follow
        :param userid: The local permanent identifier of the object
        :param sp_entity_id: The 'user' of the name_id
        :param identity: Attribute/value pairs describing the object
        :param name_id_policy: The policy the server on the other side wants
            us to follow.
        :param sp_nid: Name ID Formats from the SPs metadata
        :return: NameID instance precursor
        """
        if name_id_policy and name_id_policy.sp_name_qualifier:
            try:
                return self._get_vo_identifier(name_id_policy.sp_name_qualifier,
                                               identity)
            except Exception, exc:
                print >> sys.stderr, "%s:%s" % (exc.__class__.__name__, exc)

        if name_id_policy:
            nameid_format = name_id_policy.format
        elif sp_nid:
            nameid_format = sp_nid[0]
        elif local_policy:
            nameid_format = local_policy.get_nameid_format(sp_entity_id)
        else:
            raise Exception("Unknown NameID format")

        if nameid_format == saml.NAMEID_FORMAT_PERSISTENT:
            return self.persistent_nameid(sp_entity_id, userid)
        elif nameid_format == saml.NAMEID_FORMAT_TRANSIENT:
            return self.transient_nameid(sp_entity_id, userid)
        elif nameid_format == saml.NAMEID_FORMAT_EMAILADDRESS:
            return self.email_nameid(sp_entity_id, userid)

    def local_name(self, entity_id, remote_id):
        """ Get the local persistent name that has the specified remote ID.
        
        :param entity_id: The identifier of the entity that got the remote id
        :param remote_id: The identifier that was exported
        :return: Local identifier
        """
        try:
            return self._get_local("persistent", entity_id, remote_id)
        except KeyError:
            try:
                return self._get_local("transient", entity_id, remote_id)
            except KeyError:
                return None
        
class Server(HTTPBase):
    """ A class that does things that IdPs or AAs do """
    def __init__(self, config_file="", config=None, _cache="", stype="idp"):

        self.ident = None
        if config_file:
            self.load_config(config_file, stype)
        elif config:
            self.conf = config
        else:
            raise Exception("Missing configuration")

        HTTPBase.__init__(self, self.conf.verify_ssl_cert,
                          self.conf.ca_certs, self.conf.key_file,
                          self.conf.cert_file)

        self.conf.setup_logger()
            
        self.metadata = self.conf.metadata
        self.sec = security_context(self.conf)
        self._cache = _cache

        # if cache:
        #     if isinstance(cache, basestring):
        #         self.cache = Cache(cache)
        #     else:
        #         self.cache = cache
        # else:
        #     self.cache = Cache()
        
    def load_config(self, config_file, stype="idp"):
        """ Load the server configuration 
        
        :param config_file: The name of the configuration file
        :param stype: The type of Server ("idp"/"aa")
        """
        self.conf = config_factory(stype, config_file)
        if stype == "aa":
            return
        
        try:
            # subject information is stored in a database
            # default database is a shelve database which is OK in some setups
            dbspec = self.conf.getattr("subject_data", "idp")
            idb = None
            if isinstance(dbspec, basestring):
                idb = shelve.open(dbspec, writeback=True)
            else: # database spec is a a 2-tuple (type, address)
                print >> sys.stderr, "DBSPEC: %s" % dbspec
                (typ, addr) = dbspec
                if typ == "shelve":
                    idb = shelve.open(addr, writeback=True)
                elif typ == "memcached":
                    idb = memcache.Client(addr)
                elif typ == "dict": # in-memory dictionary
                    idb = addr
                    
            if idb is not None:
                self.ident = Identifier(idb, self.conf.virtual_organization)
            else:
                raise Exception("Couldn't open identity database: %s" %
                                (dbspec,))
        except AttributeError:
            self.ident = None

    def close_shelve_db(self):
        """Close the shelve db to prevent file system locking issues"""
        if self.ident:
            self.ident.map.close()

    def issuer(self, entityid=None):
        """ Return an Issuer precursor """
        if entityid:
            return saml.Issuer(text=entityid,
                                format=saml.NAMEID_FORMAT_ENTITY)
        else:
            return saml.Issuer(text=self.conf.entityid,
                                format=saml.NAMEID_FORMAT_ENTITY)
        
    def parse_authn_request(self, enc_request, binding=BINDING_HTTP_REDIRECT):
        """Parse a Authentication Request
        
        :param enc_request: The request in its transport format
        :param binding: Which binding that was used to transport the message
            to this entity.
        :return: A dictionary with keys:
            consumer_url - as gotten from the SPs entity_id and the metadata
            id - the id of the request
            sp_entity_id - the entity id of the SP
            request - The verified request
        """
        
        response = {}
        _log_info = logger.info
        _log_debug = logger.debug

        # The addresses I should receive messages like this on
        receiver_addresses = self.conf.endpoint("single_sign_on_service",
                                                 binding)
        _log_info("receiver addresses: %s" % receiver_addresses)
        _log_info("Binding: %s" % binding)


        try:
            timeslack = self.conf.accepted_time_diff
            if not timeslack:
                timeslack = 0
        except AttributeError:
            timeslack = 0

        authn_request = AuthnRequest(self.sec,
                                     self.conf.attribute_converters,
                                     receiver_addresses, timeslack=timeslack)

        if binding == BINDING_SOAP or binding == BINDING_PAOS:
            # not base64 decoding and unzipping
            authn_request.debug=True
            authn_request = authn_request.loads(enc_request, binding)
        else:
            authn_request = authn_request.loads(enc_request, binding)

        _log_debug("Loaded authn_request")

        if authn_request:
            authn_request = authn_request.verify()

        _log_debug("Verified authn_request")

        if not authn_request:
            return None
            
        response["id"] = authn_request.message.id # put in in_reply_to

        sp_entity_id = authn_request.message.issuer.text
        # try to find return address in metadata
        # What's the binding ? ProtocolBinding
        if authn_request.message.protocol_binding == BINDING_HTTP_REDIRECT:
            _binding = BINDING_HTTP_POST
        else:
            _binding = authn_request.message.protocol_binding

        try:
            srvs = self.metadata.assertion_consumer_service(sp_entity_id,
                                                           binding=_binding)
            consumer_url = destinations(srvs)[0]
        except (KeyError, IndexError):
            _log_info("Failed to find consumer URL for %s" % sp_entity_id)
            _log_info("Binding: %s" % _binding)
            _log_info("entities: %s" % self.metadata.keys())
            raise UnknownPrincipal(sp_entity_id)

        if not consumer_url: # what to do ?
            _log_info("Couldn't find a consumer URL binding=%s entity_id=%s" % (
                                        _binding,sp_entity_id))
            raise UnsupportedBinding(sp_entity_id)

        response["sp_entity_id"] = sp_entity_id
        response["binding"] = _binding

        if authn_request.message.assertion_consumer_service_url:
            return_destination = \
                        authn_request.message.assertion_consumer_service_url
        
            if consumer_url != return_destination:
                # serious error on someones behalf
                _log_info("%s != %s" % (consumer_url, return_destination))
                raise OtherError("ConsumerURL and return destination mismatch")
        
        response["consumer_url"] = consumer_url
        response["request"] = authn_request.message

        return response
                        
    def wants(self, sp_entity_id, index=None):
        """ Returns what attributes the SP requires and which are optional
        if any such demands are registered in the Metadata.
        
        :param sp_entity_id: The entity id of the SP
        :param index: which of the attribute consumer services its all about
        :return: 2-tuple, list of required and list of optional attributes
        """
        return self.metadata.attribute_requirement(sp_entity_id, index)
        
    def parse_attribute_query(self, xml_string, binding):
        """ Parse an attribute query
        
        :param xml_string: The Attribute Query as an XML string
        :param binding: Which binding that was used for the request
        :return: 3-Tuple containing:
            subject - identifier of the subject
            attribute - which attributes that the requestor wants back
            query - the whole query
        """
        receiver_addresses = self.conf.endpoint("attribute_service")
        attribute_query = AttributeQuery( self.sec, receiver_addresses)

        attribute_query = attribute_query.loads(xml_string, binding)
        attribute_query = attribute_query.verify()

        logger.info("KEYS: %s" % attribute_query.message.keys())
        # Subject is described in the a saml.Subject instance
        subject = attribute_query.subject_id()
        attribute = attribute_query.attribute()

        return subject, attribute, attribute_query.message
            
    # ------------------------------------------------------------------------

    def _response(self, in_response_to, consumer_url=None, status=None,
                  issuer=None, sign=False, to_sign=None,
                  **kwargs):
        """ Create a Response that adhers to the ??? profile.
        
        :param in_response_to: The session identifier of the request
        :param consumer_url: The URL which should receive the response
        :param status: The status of the response
        :param issuer: The issuer of the response
        :param sign: Whether the response should be signed or not
        :param to_sign: What other parts to sign
        :param kwargs: Extra key word arguments
        :return: A Response instance
        """

        if not status: 
            status = success_status_factory()

        _issuer = self.issuer(issuer)

        response = response_factory(
            issuer=_issuer,
            in_response_to = in_response_to,
            status = status,
            )

        if consumer_url:
            response.destination = consumer_url

        for key, val in kwargs.items():
            setattr(response, key, val)

        if sign:
            try:
                to_sign.append((class_name(response), response.id))
            except AttributeError:
                to_sign = [(class_name(response), response.id)]


        return signed_instance_factory(response, self.sec, to_sign)

    # ------------------------------------------------------------------------
    
    def _authn_response(self, in_response_to, consumer_url,
                        sp_entity_id, identity=None, name_id=None,
                        status=None, authn=None,
                        authn_decl=None, issuer=None, policy=None,
                        sign_assertion=False, sign_response=False):
        """ Create a response. A layer of indirection.
        
        :param in_response_to: The session identifier of the request
        :param consumer_url: The URL which should receive the response
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param authn: A 2-tuple denoting the authn class and the authn
            authority.
        :param authn_decl:
        :param issuer: The issuer of the response
        :param sign_assertion: Whether the assertion should be signed or not
        :param sign_response: Whether the response should be signed or not
        :return: A response instance
        """

        to_sign = []
        args = {}
        if identity:
            _issuer = self.issuer(issuer)
            ast = Assertion(identity)
            if policy is None:
                policy = Policy()
            try:
                ast.apply_policy(sp_entity_id, policy, self.metadata)
            except MissingValue, exc:
                return self.create_error_response(in_response_to, consumer_url,
                                                  exc, sign_response)

            if authn: # expected to be a 2-tuple class+authority
                (authn_class, authn_authn) = authn
                assertion = ast.construct(sp_entity_id, in_response_to,
                                          consumer_url, name_id,
                                          self.conf.attribute_converters,
                                          policy, issuer=_issuer,
                                          authn_class=authn_class,
                                          authn_auth=authn_authn)
            elif authn_decl:
                assertion = ast.construct(sp_entity_id, in_response_to,
                                          consumer_url, name_id,
                                          self.conf.attribute_converters,
                                          policy, issuer=_issuer,
                                          authn_decl=authn_decl)
            else:
                assertion = ast.construct(sp_entity_id, in_response_to,
                                          consumer_url, name_id,
                                          self.conf.attribute_converters,
                                          policy, issuer=_issuer)

            if sign_assertion:
                assertion.signature = pre_signature_part(assertion.id,
                                                         self.sec.my_cert, 1)
                # Just the assertion or the response and the assertion ?
                to_sign = [(class_name(assertion), assertion.id)]

            # Store which assertion that has been sent to which SP about which
            # subject.

            # self.cache.set(assertion.subject.name_id.text,
            #                 sp_entity_id, {"ava": identity, "authn": authn},
            #                 assertion.conditions.not_on_or_after)

            args["assertion"] = assertion

        return self._response(in_response_to, consumer_url, status, issuer,
                              sign_response, to_sign, **args)
                        
    # ------------------------------------------------------------------------
    
    def create_error_response(self, in_response_to, destination, info,
                              sign=False, issuer=None):
        """ Create a error response.
        
        :param in_response_to: The identifier of the message this is a response
            to.
        :param destination: The intended recipient of this message
        :param info: Either an Exception instance or a 2-tuple consisting of
            error code and descriptive text
        :param sign: Whether the response should be signed or not
        :param issuer: The issuer of the response
        :return: A response instance
        """
        status = error_status_factory(info)

        return self._response(in_response_to, destination, status, issuer,
                              sign)

    # ------------------------------------------------------------------------
    #noinspection PyUnusedLocal
    def create_aa_response(self, in_response_to, consumer_url, sp_entity_id,
                           identity=None, userid="", name_id=None, status=None,
                           issuer=None, sign_assertion=False,
                           sign_response=False, attributes=None):
        """ Create an attribute assertion response.
        
        :param in_response_to: The session identifier of the request
        :param consumer_url: The URL which should receive the response
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param userid: A identifier of the user
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param issuer: The issuer of the response
        :param sign_assertion: Whether the assertion should be signed or not
        :param sign_response: Whether the whole response should be signed
        :return: A response instance
        """
        if not name_id and userid:
            try:
                name_id = self.ident.construct_nameid(self.conf.policy, userid,
                                                      sp_entity_id, identity)
                logger.warning("Unspecified NameID format")
            except Exception:
                pass

        to_sign = []
        args = {}
        if identity:
            _issuer = self.issuer(issuer)
            ast = Assertion(identity)
            policy = self.conf.getattr("policy", "aa")
            if policy:
                ast.apply_policy(sp_entity_id, policy)
            else:
                policy = Policy()

            if attributes:
                restr = restriction_from_attribute_spec(attributes)
                ast = filter_attribute_value_assertions(ast)

            assertion = ast.construct(sp_entity_id, in_response_to,
                                      consumer_url, name_id,
                                      self.conf.attribute_converters,
                                      policy, issuer=_issuer)

            if sign_assertion:
                assertion.signature = pre_signature_part(assertion.id,
                                                         self.sec.my_cert, 1)
                # Just the assertion or the response and the assertion ?
                to_sign = [(class_name(assertion), assertion.id)]


            args["assertion"] = assertion

        return self._response(in_response_to, consumer_url, status, issuer,
                              sign_response, to_sign, **args)

    # ------------------------------------------------------------------------

    def create_authn_response(self, identity, in_response_to, destination,
                              sp_entity_id, name_id_policy=None, userid=None,
                              name_id=None, authn=None, authn_decl=None,
                              issuer=None, sign_response=False,
                              sign_assertion=False):
        """ Constructs an AuthenticationResponse

        :param identity: Information about an user
        :param in_response_to: The identifier of the authentication request
            this response is an answer to.
        :param destination: Where the response should be sent
        :param sp_entity_id: The entity identifier of the Service Provider
        :param name_id_policy: How the NameID should be constructed
        :param userid: The subject identifier
        :param authn: Information about the authentication
        :param authn_decl:
        :param issuer: Issuer of the response
        :param sign_assertion: Whether the assertion should be signed or not.
        :param sign_response: Whether the response should be signed or not.
        :return: A response instance
        """

        policy = self.conf.getattr("policy", "idp")

        if not name_id:
            try:
                nid_formats = []
                for _sp in self.metadata[sp_entity_id]["spsso_descriptor"]:
                    if "name_id_format" in _sp:
                        nid_formats.extend([n.text for n in _sp["name_id_format"]])

                name_id = self.ident.construct_nameid(policy, userid,
                                                      sp_entity_id, identity,
                                                      name_id_policy,
                                                      nid_formats)
            except IOError, exc:
                response = self.create_error_response(in_response_to,
                                                      destination,
                                                      sp_entity_id,
                                                      exc, name_id)
                return ("%s" % response).split("\n")
        
        try:
            return self._authn_response(in_response_to, # in_response_to
                                        destination,    # consumer_url
                                        sp_entity_id,   # sp_entity_id
                                        identity,       # identity as dictionary
                                        name_id,
                                        authn=authn,    # Information about the
                                                        #   authentication
                                        authn_decl=authn_decl,
                                        issuer=issuer,
                                        policy=policy,
                                        sign_assertion=sign_assertion,
                                        sign_response=sign_response)

        except MissingValue, exc:
            return self.create_error_response(in_response_to, destination,
                                                  sp_entity_id, exc, name_id)
        


    def parse_logout_request(self, text, binding=BINDING_SOAP):
        """Parse a Logout Request
        
        :param text: The request in its transport format, if the binding is 
            HTTP-Redirect or HTTP-Post the text *must* be the value of the 
            SAMLRequest attribute.
        :return: A validated LogoutRequest instance or None if validation 
            failed.
        """
        
        try:
            slo = self.conf.endpoint("single_logout_service", binding, "idp")
        except IndexError:
            logger.info("enpoints: %s" % self.conf.getattr("endpoints", "idp"))
            logger.info("binding wanted: %s" % (binding,))
            raise

        if not slo:
            raise Exception("No single_logout_server for that binding")

        logger.info("Endpoint: %s" % slo)
        req = LogoutRequest(self.sec, slo)
        if binding == BINDING_SOAP:
            lreq = soap.parse_soap_enveloped_saml_logout_request(text)
            try:
                req = req.loads(lreq, binding)
            except Exception:
                return None
        else:
            try:
                req = req.loads(text, binding)
            except Exception, exc:
                logger.error("%s" % (exc,))
                return None

        req = req.verify()
        
        if not req: # Not a valid request
            # return a error message with status code element set to
            # urn:oasis:names:tc:SAML:2.0:status:Requester
            return None
        else:
            return req


    def create_logout_response(self, request, binding, status=None,
                               sign=False, issuer=None):
        """ Create a LogoutResponse. What is returned depends on which binding
        is used.
        
        :param request: The request this is a response to
        :param binding: Which binding the request came in over
        :param status: The return status of the response operation
        :param issuer: The issuer of the message
        :return: A logout message.
        """
        mid = sid()

        if not status:
            status = success_status_factory()

        # response and packaging differs depending on binding
        response = ""
        if binding in [BINDING_SOAP, BINDING_HTTP_POST]:
            response = logoutresponse_factory(sign=sign, id = mid,
                                              in_response_to = request.id,
                                              status = status)
        elif binding == BINDING_HTTP_REDIRECT:
            sp_entity_id = request.issuer.text.strip()
            srvs = self.metadata.single_logout_service(sp_entity_id, "spsso")
            if not srvs:
                raise Exception("Nowhere to send the response")

            destination = destinations(srvs)[0]

            _issuer = self.issuer(issuer)
            response = logoutresponse_factory(sign=sign, id = mid,
                                              in_response_to = request.id,
                                              status = status,
                                              issuer = _issuer,
                                              destination = destination,
                                              sp_entity_id = sp_entity_id,
                                              instant=instant())
        if sign:
            to_sign = [(class_name(response), mid)]
            response = signed_instance_factory(response, self.sec, to_sign)

        logger.info("Response: %s" % (response,))

        return response

    def parse_authz_decision_query(self, xml_string, binding):
        """ Parse an attribute query

        :param xml_string: The Authz decision Query as an XML string
        :return: 3-Tuple containing:
            subject - identifier of the subject
            attribute - which attributes that the requestor wants back
            query - the whole query
        """
        receiver_addresses = self.conf.endpoint("attribute_service", "idp")
        attribute_query = AttributeQuery( self.sec, receiver_addresses)

        attribute_query = attribute_query.loads(xml_string, binding)
        attribute_query = attribute_query.verify()

        # Subject name is a BaseID,NameID or EncryptedID instance
        subject = attribute_query.subject_id()
        attribute = attribute_query.attribute()

        return subject, attribute, attribute_query.message
