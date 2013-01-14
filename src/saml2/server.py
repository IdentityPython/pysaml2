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
from saml2.samlp import NameIDMappingResponse
from saml2.entity import Entity

from saml2 import saml
from saml2 import class_name
from saml2 import BINDING_HTTP_REDIRECT

from saml2.request import AuthnRequest
from saml2.request import AssertionIDRequest
from saml2.request import AttributeQuery
from saml2.request import NameIDMappingRequest
from saml2.request import AuthzDecisionQuery
from saml2.request import AuthnQuery

from saml2.s_utils import sid
from saml2.s_utils import MissingValue
from saml2.s_utils import error_status_factory

from saml2.sigver import pre_signature_part

from saml2.assertion import Assertion
from saml2.assertion import Policy
from saml2.assertion import restriction_from_attribute_spec
from saml2.assertion import filter_attribute_value_assertions

logger = logging.getLogger(__name__)

class UnknownVO(Exception):
    pass

def context_match(cfilter, cntx):
    return True

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
        
class Server(Entity):
    """ A class that does things that IdPs or AAs do """
    def __init__(self, config_file="", config=None, _cache="", stype="idp"):
        Entity.__init__(self, stype, config, config_file)
        self.init_config(stype)
        self._cache = _cache
        self.ticket = {}
        self.authn = {}
        self.assertion = {}

    def init_config(self, stype="idp"):
        """ Remaining init of the server configuration 
        
        :param stype: The type of Server ("idp"/"aa")
        """
        if stype == "aa":
            return
        
        try:
            # subject information is stored in a database
            # default database is a shelve database which is OK in some setups
            dbspec = self.config.getattr("subject_data", "idp")
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
                self.ident = Identifier(idb, self.config.virtual_organization)
            else:
                raise Exception("Couldn't open identity database: %s" %
                                (dbspec,))
        except AttributeError:
            self.ident = None

    def close_shelve_db(self):
        """Close the shelve db to prevent file system locking issues"""
        if self.ident:
            self.ident.map.close()

    def wants(self, sp_entity_id, index=None):
        """ Returns what attributes the SP requires and which are optional
        if any such demands are registered in the Metadata.

        :param sp_entity_id: The entity id of the SP
        :param index: which of the attribute consumer services its all about
        :return: 2-tuple, list of required and list of optional attributes
        """
        return self.metadata.attribute_requirement(sp_entity_id, index)

    # -------------------------------------------------------------------------

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

        return self._parse_request(enc_request, AuthnRequest,
                                   "single_sign_on_service", binding)

    def parse_attribute_query(self, xml_string, binding):
        """ Parse an attribute query
        
        :param xml_string: The Attribute Query as an XML string
        :param binding: Which binding that was used for the request
        :return: A query instance
        """

        return self._parse_request(xml_string, AttributeQuery,
                                   "attribute_service", binding)


    def parse_authz_decision_query(self, xml_string, binding):
        """ Parse an attribute query

        :param xml_string: The Authz decision Query as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, AuthzDecisionQuery,
                                   "authz_service", binding)

    def parse_assertion_id_request(self, xml_string, binding):
        """ Parse an assertion id query

        :param xml_string: The AssertionIDRequest as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, AssertionIDRequest,
                                   "assertion_id_request_service", binding)

    def parse_authn_query(self, xml_string, binding):
        """ Parse an authn query

        :param xml_string: The AuthnQuery as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, AuthnQuery,
                                   "authn_query_service", binding)

    def parse_name_id_mapping_request(self, xml_string, binding):
        """ Parse a nameid mapping request

        :param xml_string: The NameIDMappingRequest as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, NameIDMappingRequest,
                                   "manage_name_id_service", binding)

    # ------------------------------------------------------------------------

    def store_assertion(self, assertion, to_sign):
        self.assertion[assertion.id] = (assertion, to_sign)

    def get_assertion(self, id):
        return self.assertion[id]

    def store_authn_statement(self, authn_statement, name_id):
        try:
            self.authn[name_id.text].append(authn_statement)
        except:
            self.authn[name_id.text] = [authn_statement]

    def get_authn_statements(self, subject, session_index=None,
                             requested_context=None):
        result = []
        for statement in self.authn[subject.name_id.text]:
            if session_index:
                if statement.session_index != session_index:
                    continue
            if requested_context:
                if not context_match(requested_context, statement.authn_context):
                    continue
            result.append(statement)

        return result

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
            _issuer = self._issuer(issuer)
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
                                          self.config.attribute_converters,
                                          policy, issuer=_issuer,
                                          authn_class=authn_class,
                                          authn_auth=authn_authn)
                self.store_authn_statement(assertion.authn_statement, name_id)
            elif authn_decl:
                assertion = ast.construct(sp_entity_id, in_response_to,
                                          consumer_url, name_id,
                                          self.config.attribute_converters,
                                          policy, issuer=_issuer,
                                          authn_decl=authn_decl)
                self.store_authn_statement(assertion.authn_statement, name_id)
            else:
                assertion = ast.construct(sp_entity_id, in_response_to,
                                          consumer_url, name_id,
                                          self.config.attribute_converters,
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

            self.store_assertion(assertion, to_sign)

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
                name_id = self.ident.construct_nameid(self.config.policy, userid,
                                                      sp_entity_id, identity)
                logger.warning("Unspecified NameID format")
            except Exception:
                pass

        to_sign = []
        args = {}
        if identity:
            _issuer = self._issuer(issuer)
            ast = Assertion(identity)
            policy = self.config.getattr("policy", "aa")
            if policy:
                ast.apply_policy(sp_entity_id, policy)
            else:
                policy = Policy()

            if attributes:
                restr = restriction_from_attribute_spec(attributes)
                ast = filter_attribute_value_assertions(ast)

            assertion = ast.construct(sp_entity_id, in_response_to,
                                      consumer_url, name_id,
                                      self.config.attribute_converters,
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

        policy = self.config.getattr("policy", "idp")

        if not name_id:
            try:
                nid_formats = []
                for _sp in self.metadata[sp_entity_id]["spsso_descriptor"]:
                    if "name_id_format" in _sp:
                        nid_formats.extend([n["text"] for n in _sp["name_id_format"]])

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

    def create_assertion_id_request_response(self, assertion_id, in_response_to,
                                             issuer=None, sign_response=False,
                                             status=None):
        """

        :param assertion_id:
        :param in_response_to:
        :param issuer:
        :param sign_response:
        :param status:
        :return:
        """
        # Done over SOAP
        args = {}
        to_sign = []

        for aid in assertion_id:
            try:
                (assertion, to_sign) = self.get_assertion(aid)
                to_sign.extend(to_sign)
                try:
                    args["assertion"].append(assertion)
                except KeyError:
                    args["assertion"] = [assertion]
            except KeyError:
                pass

        return self._response(in_response_to, "", status, issuer,
                              sign_response, to_sign, **args)

    def create_name_id_mapping_response(self, name_id=None, encrypted_id=None,
                                        in_response_to=None,
                                        issuer=None, sign_response=False,
                                        status=None):
        """
        protocol for mapping a principal's name identifier into a
        different name identifier for the same principal.
        Done over soap.

        :param name_id:
        :param encrypted_id:
        :param in_response_to:
        :param issuer:
        :param sign_response:
        :param status:
        :return:
        """
        # Done over SOAP

        ms_args = self.message_args()

        _resp = NameIDMappingResponse(name_id, encrypted_id,
                                      in_response_to=in_response_to, **ms_args)

        if sign_response:
            return self.sign(_resp)
        else:
            logger.info("Message: %s" % _resp)
            return _resp

    def create_authn_query_response(self, subject, session_index=None,
                                    requested_context=None, in_response_to=None,
                                    issuer=None, sign_response=False,
                                    status=None):
        """
        A successful <Response> will contain one or more assertions containing
        authentication statements.

        :return:
        """

        margs = self.message_args()
        asserts = []
        for statement in self.get_authn_statements(subject, session_index,
                                                   requested_context):

            asserts.append(saml.Assertion(authn_statement=statement,
                                          subject=subject, **margs))

        if asserts:
            args = {"assertion": asserts}
        else:
            args = {}

        return self._response(in_response_to, "", status, issuer,
                              sign_response, to_sign=[], **args)
