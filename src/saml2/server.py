#!/usr/bin/python
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

import shelve
import sys
import memcache

from saml2 import saml
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

from saml2.binding import http_soap_message
from saml2.binding import http_redirect_message
from saml2.binding import http_post_message

from saml2.sigver import security_context
from saml2.sigver import signed_instance_factory
from saml2.sigver import pre_signature_part
from saml2.sigver import response_factory, logoutresponse_factory

from saml2.config import config_factory

from saml2.assertion import Assertion, Policy

class UnknownVO(Exception):
    pass
    
class Identifier(object):
    """ A class that handles identifiers of objects """
    def __init__(self, db, voconf=None, debug=0, log=None):
        if isinstance(db, basestring):
            self.map = shelve.open(db, writeback=True)
        else:
            self.map = db
        self.voconf = voconf
        self.debug = debug
        self.log = log
        
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

    def _get_vo_identifier(self, sp_name_qualifier, userid, identity):
        try:
            vo_conf = self.voconf[sp_name_qualifier]
            if "common_identifier" in vo_conf:
                try:
                    subj_id = identity[vo_conf["common_identifier"]]
                except KeyError:
                    raise MissingValue("Common identifier")
            else:
                return self.persistent_nameid(sp_name_qualifier, userid)
        except (KeyError, TypeError):
            raise UnknownVO("%s" % sp_name_qualifier)

        try:
            nameid_format = vo_conf["nameid_format"]
        except KeyError:
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
                                                userid, identity)
            except Exception:
                pass

        if sp_nid:
            nameid_format = sp_nid[0]
        else:
            nameid_format = local_policy.get_nameid_format(sp_entity_id)

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
        
class Server(object):
    """ A class that does things that IdPs or AAs do """
    def __init__(self, config_file="", config=None, _cache="",
                    log=None, debug=0, stype="idp"):

        self.log = log
        self.debug = debug
        self.ident = None
        if config_file:
            self.load_config(config_file, stype)
        elif config:
            self.conf = config
        else:
            raise Exception("Missing configuration")

        if self.log is None:
            self.log = self.conf.setup_logger()
            
        self.metadata = self.conf.metadata
        self.sec = security_context(self.conf, log)
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
            dbspec = self.conf.subject_data
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
                self.ident = Identifier(idb, self.conf.virtual_organization,
                                        self.debug, self.log)
            else:
                raise Exception("Couldn't open identity database: %s" %
                                (dbspec,))
        except AttributeError:
            self.ident = None
    
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
        if self.log:
            _log_info = self.log.info
        else:
            _log_info = None

        # The addresses I should receive messages like this on
        receiver_addresses = self.conf.endpoint("single_sign_on_service",
                                                 binding)
        if self.debug and self.log:
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
                                     receiver_addresses, log=self.log,
                                     timeslack=timeslack)

        if binding == BINDING_SOAP or binding == BINDING_PAOS:
            # not base64 decoding and unzipping
            authn_request.debug=True
            _log_info("Don't decode")
            authn_request = authn_request.loads(enc_request, decode=False)
        else:
            authn_request = authn_request.loads(enc_request)

        if self.debug and self.log:
            _log_info("Loaded authn_request")

        if authn_request:
            authn_request = authn_request.verify()

        if self.debug and self.log:
            _log_info("Verified authn_request")

        if not authn_request:
            return None
            
        response["id"] = authn_request.message.id # put in in_reply_to

        sp_entity_id = authn_request.message.issuer.text
        # try to find return address in metadata
        try:
            # What's the binding ? ProtocolBinding
            _binding = authn_request.message.protocol_binding
            consumer_url = self.metadata.consumer_url(sp_entity_id,
                                                      binding=_binding)
        except KeyError:
            if self.log:
                _log_info("Failed to find consumer URL for %s" % sp_entity_id)
                _log_info("entities: %s" % self.metadata.entity.keys())
            raise UnknownPrincipal(sp_entity_id)
            
        if not consumer_url: # what to do ?
            if self.log:
                _log_info("Couldn't find a consumer URL binding=%s" % _binding)
            raise UnsupportedBinding(sp_entity_id)

        response["sp_entity_id"] = sp_entity_id

        if authn_request.message.assertion_consumer_service_url:
            return_destination = \
                        authn_request.message.assertion_consumer_service_url
        
            if consumer_url != return_destination:
                # serious error on someones behalf
                if self.log:
                    _log_info("%s != %s" % (consumer_url, return_destination))
                else:
                    print >> sys.stderr, \
                                "%s != %s" % (consumer_url, return_destination)
                raise OtherError("ConsumerURL and return destination mismatch")
        
        response["consumer_url"] = consumer_url
        response["request"] = authn_request.message

        return response
                        
    def wants(self, sp_entity_id):
        """ Returns what attributes the SP requiers and which are optional
        if any such demands are registered in the Metadata.
        
        :param sp_entity_id: The entity id of the SP
        :return: 2-tuple, list of required and list of optional attributes
        """
        return self.metadata.requests(sp_entity_id)
        
    def parse_attribute_query(self, xml_string, decode=True):
        """ Parse an attribute query
        
        :param xml_string: The Attribute Query as an XML string
        :param decode: Whether the xmlstring is base64encoded and zipped
        :return: 3-Tuple containing:
            subject - identifier of the subject
            attribute - which attributes that the requestor wants back
            query - the whole query
        """
        receiver_addresses = self.conf.endpoint("attribute_service")
        attribute_query = AttributeQuery( self.sec, receiver_addresses)

        attribute_query = attribute_query.loads(xml_string, decode=decode)
        attribute_query = attribute_query.verify()

        self.log.info("KEYS: %s" % attribute_query.message.keys())
        # Subject is described in the a saml.Subject instance
        subject = attribute_query.subject_id()
        attribute = attribute_query.attribute()

        return subject, attribute, attribute_query.message
            
    # ------------------------------------------------------------------------

    def _response(self, in_response_to, consumer_url=None, sp_entity_id=None, 
                    identity=None, name_id=None, status=None, sign=False,
                    policy=Policy(), authn=None, authn_decl=None, issuer=None):
        """ Create a Response that adhers to the ??? profile.
        
        :param in_response_to: The session identifier of the request
        :param consumer_url: The URL which should receive the response
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param sign: Whether the assertion should be signed or not 
        :param policy: The attribute release policy for this instance
        :param authn: A 2-tuple denoting the authn class and the authn
            authority
        :param authn_decl:
        :param issuer: The issuer of the response
        :return: A Response instance
        """
                
        to_sign = []

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

        if identity:            
            ast = Assertion(identity)
            try:
                ast.apply_policy(sp_entity_id, policy, self.metadata)
            except MissingValue, exc:
                return self.error_response(in_response_to, consumer_url, 
                                               sp_entity_id, exc, name_id)

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
            
            if sign:
                assertion.signature = pre_signature_part(assertion.id,
                                                        self.sec.my_cert, 1)
                # Just the assertion or the response and the assertion ?
                to_sign = [(class_name(assertion), assertion.id)]

            # Store which assertion that has been sent to which SP about which
            # subject.
            
            # self.cache.set(assertion.subject.name_id.text, 
            #                 sp_entity_id, {"ava": identity, "authn": authn}, 
            #                 assertion.conditions.not_on_or_after)
            
            response.assertion = assertion
                
        return signed_instance_factory(response, self.sec, to_sign)

    # ------------------------------------------------------------------------
    
    def do_response(self, in_response_to, consumer_url,
                        sp_entity_id, identity=None, name_id=None, 
                        status=None, sign=False, authn=None, authn_decl=None,
                        issuer=None):
        """ Create a response. A layer of indirection.
        
        :param in_response_to: The session identifier of the request
        :param consumer_url: The URL which should receive the response
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param sign: Whether the assertion should be signed or not 
        :param authn: A 2-tuple denoting the authn class and the authn
            authority.
        :param authn_decl:
        :param issuer: The issuer of the response
        :return: A Response instance.
        """

        policy = self.conf.policy

        return self._response(in_response_to, consumer_url,
                        sp_entity_id, identity, name_id, 
                        status, sign, policy, authn, authn_decl, issuer)
                        
    # ------------------------------------------------------------------------
    
    def error_response(self, in_response_to, destination, spid, info, 
                        name_id=None, sign=False, issuer=None):
        """ Create a error response.
        
        :param in_response_to: The identifier of the message this is a response
            to.
            :param destination: The intended recipient of this message
        :param spid: The entitiy ID of the SP that will get this.
        :param info: Either an Exception instance or a 2-tuple consisting of
            error code and descriptive text
        :param name_id:
        :param sign: Whether the message should be signed or not
        :param issuer: The issuer of the response
        :return: A Response instance
        """
        status = error_status_factory(info)
            
        return self._response(
                        in_response_to, # in_response_to
                        destination,    # consumer_url
                        spid,           # sp_entity_id
                        name_id=name_id,
                        status=status,
                        sign=sign,
                        issuer=issuer
                        )

    # ------------------------------------------------------------------------
    #noinspection PyUnusedLocal
    def do_aa_response(self, in_response_to, consumer_url, sp_entity_id, 
                        identity=None, userid="", name_id=None, status=None, 
                        sign=False, _name_id_policy=None, issuer=None):
        """ Create an attribute assertion response.
        
        :param in_response_to: The session identifier of the request
        :param consumer_url: The URL which should receive the response
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param userid: A identifier of the user
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param sign: Whether the assertion should be signed or not 
        :param _name_id_policy: Policy for NameID creation.
        :param issuer: The issuer of the response
        :return: A Response instance.
        """
#        name_id = self.ident.construct_nameid(self.conf.policy, userid,
#                                            sp_entity_id, identity)
        
        return self._response(in_response_to, consumer_url,
                        sp_entity_id, identity, name_id, 
                        status, sign, policy=self.conf.policy, issuer=issuer)

    # ------------------------------------------------------------------------

    def authn_response(self, identity, in_response_to, destination,
                        sp_entity_id, name_id_policy, userid, sign=False, 
                        authn=None, sign_response=False, authn_decl=None,
                        issuer=None, instance=False):
        """ Constructs an AuthenticationResponse

        :param identity: Information about an user
        :param in_response_to: The identifier of the authentication request
            this response is an answer to.
        :param destination: Where the response should be sent
        :param sp_entity_id: The entity identifier of the Service Provider
        :param name_id_policy: ...
        :param userid: The subject identifier
        :param sign: Whether the assertion should be signed or not. This is
            different from signing the response as such.
        :param authn: Information about the authentication
        :param sign_response: The response can be signed separately from the 
            assertions.
        :param authn_decl:
        :param issuer: Issuer of the response
        :param instance: Whether to return the instance or a string
            representation
        :return: A XML string representing an authentication response
        """

        name_id = None
        try:
            nid_formats = []
            for _sp in self.metadata.entity[sp_entity_id]["sp_sso"]:
                nid_formats.extend([n.text for n in _sp.name_id_format])

            policy = self.conf.policy
            name_id = self.ident.construct_nameid(policy, userid, sp_entity_id,
                                                    identity, name_id_policy,
                                                    nid_formats)
        except IOError, exc:
            response = self.error_response(in_response_to, destination, 
                                            sp_entity_id, exc, name_id)
            return ("%s" % response).split("\n")
        
        try:
            response = self.do_response(
                            in_response_to, # in_response_to
                            destination,    # consumer_url
                            sp_entity_id,   # sp_entity_id
                            identity,       # identity as dictionary
                            name_id,
                            sign=sign,      # If the assertion should be signed
                            authn=authn,    # Information about the 
                                            #   authentication
                            authn_decl=authn_decl,
                            issuer=issuer
                        )
        except MissingValue, exc:
            response = self.error_response(in_response_to, destination, 
                                        sp_entity_id, exc, name_id)
        

        if sign_response:
            try:
                response.signature = pre_signature_part(response.id,
                                                        self.sec.my_cert, 2)
        
                return self.sec.sign_statement_using_xmlsec(response,
                                                        class_name(response),
                                                        nodeid=response.id)
            except Exception, exc:
                response = self.error_response(in_response_to, destination, 
                                                sp_entity_id, exc, name_id)
                if instance:
                    return response
                else:
                    return ("%s" % response).split("\n")
        else:
            if instance:
                return response
            else:
                return ("%s" % response).split("\n")

    def parse_logout_request(self, text, binding=BINDING_SOAP):
        """Parse a Logout Request
        
        :param text: The request in its transport format, if the binding is 
            HTTP-Redirect or HTTP-Post the text *must* be the value of the 
            SAMLRequest attribute.
        :return: A validated LogoutRequest instance or None if validation 
            failed.
        """
        
        try:
            slo = self.conf.endpoint("single_logout_service", binding)
        except IndexError:
            if self.log:
                self.log.info("enpoints: %s" % (self.conf.endpoints,))
                self.log.info("binding wanted: %s" % (binding,))
            raise

        if not slo:
            raise Exception("No single_logout_server for that binding")
        
        if self.log:
            self.log.info("Endpoint: %s" % slo)
        req = LogoutRequest(self.sec, slo)
        if binding == BINDING_SOAP:
            lreq = soap.parse_soap_enveloped_saml_logout_request(text)
            try:
                req = req.loads(lreq, False) # Got it over SOAP so no base64+zip
            except Exception:
                return None
        else:
            try:
                req = req.loads(text)
            except Exception, exc:
                self.log.error("%s" % (exc,))
                return None

        req = req.verify()
        
        if not req: # Not a valid request
            # return a error message with status code element set to
            # urn:oasis:names:tc:SAML:2.0:status:Requester
            return None
        else:
            return req


    def logout_response(self, request, bindings, status=None,
                            sign=False, issuer=None):
        """ Create a LogoutResponse. What is returned depends on which binding
        is used.
        
        :param request: The request this is a response to
        :param bindings: Which bindings that can be used to send the response
        :param status: The return status of the response operation
        :param issuer: The issuer of the message
        :return: A 3-tuple consisting of HTTP return code, HTTP headers and 
            possibly a message.
        """
        sp_entity_id = request.issuer.text.strip()
        
        binding = None
        destinations = []
        for binding in bindings:
            destinations = self.conf.single_logout_services(sp_entity_id,
                                                           binding)
            if destinations:
                break
                

        if not destinations:
            if self.log:
                self.log.error("Not way to return a response !!!")
            return ("412 Precondition Failed",
                    [("Content-type", "text/html")],
                    ["No return way defined"])
        
        # Pick the first
        destination = destinations[0]
        
        if self.log:
            self.log.info("Logout Destination: %s, binding: %s" % (destination,
                                                                    binding))
        if not status: 
            status = success_status_factory()

        mid = sid()
        rcode = "200 OK"
        
        # response and packaging differs depending on binding
        
        if binding == BINDING_SOAP:
            response = logoutresponse_factory(
                                sign=sign,
                                id = mid,
                                in_response_to = request.id,
                                status = status,
                                )
            if sign:
                to_sign = [(class_name(response), mid)]
                response = signed_instance_factory(response, self.sec, to_sign)
                
            (headers, message) = http_soap_message(response)
        else:
            _issuer = self.issuer(issuer)
            response = logoutresponse_factory(
                                sign=sign,
                                id = mid,
                                in_response_to = request.id,
                                status = status,
                                issuer = _issuer,
                                destination = destination,
                                sp_entity_id = sp_entity_id,
                                instant=instant(),
                                )
            if sign:
                to_sign = [(class_name(response), mid)]
                response = signed_instance_factory(response, self.sec, to_sign)
                
            if self.log:
                self.log.info("Response: %s" % (response,))
            if binding == BINDING_HTTP_REDIRECT:
                (headers, message) = http_redirect_message(response, 
                                                            destination, 
                                                            typ="SAMLResponse")
                rcode = "302 Found"
            else:
                (headers, message) = http_post_message(response, destination,
                                                        typ="SAMLResponse")
                
        return rcode, headers, message

    def parse_authz_decision_query(self, xml_string):
        """ Parse an attribute query

        :param xml_string: The Authz decision Query as an XML string
        :return: 3-Tuple containing:
            subject - identifier of the subject
            attribute - which attributes that the requestor wants back
            query - the whole query
        """
        receiver_addresses = self.conf.endpoint("attribute_service")
        attribute_query = AttributeQuery( self.sec, receiver_addresses)

        attribute_query = attribute_query.loads(xml_string)
        attribute_query = attribute_query.verify()

        # Subject name is a BaseID,NameID or EncryptedID instance
        subject = attribute_query.subject_id()
        attribute = attribute_query.attribute()

        return subject, attribute, attribute_query.message
