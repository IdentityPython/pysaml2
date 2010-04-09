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

"""Contains classes and functions that a SAML2.0 Identity provider (IdP) 
or attribute authority (AA) may use to conclude its tasks.
"""

import shelve
import sys

from saml2 import saml, samlp, VERSION, make_instance

from saml2.utils import sid, decode_base64_and_inflate
from saml2.utils import response_factory
from saml2.utils import MissingValue, args2dict
from saml2.utils import success_status_factory, assertion_factory
from saml2.utils import OtherError, do_attribute_statement
from saml2.utils import VersionMismatch, UnknownPrincipal, UnsupportedBinding
from saml2.utils import status_from_exception_factory

from saml2.sigver import security_context, signed_instance_factory
from saml2.sigver import pre_signature_part
from saml2.time_util import instant, in_a_while
from saml2.config import Config
from saml2.cache import Cache 
from saml2.assertion import Assertion, Policy   

class UnknownVO(Exception):
    pass
    
class Identifier(object):
    """ A class that handles identifiers of objects """
    def __init__(self, dbname, entityid, voconf=None, debug=0, log=None):
        self.map = shelve.open(dbname,writeback=True)
        self.entityid = entityid
        self.voconf = voconf
        self.debug = debug
        self.log = log
        
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
        if self.debug:
            self.log and self.log.debug("Id map keys: %s" % self.map.keys())
            
        try:
            emap = self.map[entity_id]
        except KeyError:
            emap = self.map[entity_id] = {"forward":{}, "backward":{}}

        try:
            if self.debug:
                self.log.debug("map forward keys: %s" % emap["forward"].keys())
            return emap["forward"][subject_id]
        except KeyError:
            while True:
                temp_id = sid()
                if temp_id not in emap["backward"]:
                    break
            emap["forward"][subject_id] = temp_id
            emap["backward"][temp_id] = subject_id
            self.map[entity_id] = emap
            self.map.sync()
            
            return temp_id

    def _get_vo_identifier(self, sp_name_qualifier, userid, identity):
        try:
            vo_conf = self.voconf(sp_name_qualifier)
            if "common_identifier" in vo_conf:
                try:
                    subj_id = identity[vo_conf["common_identifier"]]
                except KeyError:
                    raise MissingValue("Common identifier")
            else:
                return self.persistent_nameid(sp_name_qualifier, userid)
        except KeyError:
            raise UnknownVO("%s" % sp_name_qualifier)
        
        try:
            format = vo_conf["nameid_format"]
        except KeyError:
            format = saml.NAMEID_FORMAT_PERSISTENT
            
        return args2dict(subj_id, format=format,
                            sp_name_qualifier=sp_name_qualifier)
    
    def persistent_nameid(self, sp_name_qualifier, userid):
        """ Get or create a persistent identifier for this object to be used
        when communicating with servers using a specific SPNameQualifier
        
        :param sp_name_qualifier: An identifier for a 'context'
        :param userid: The local permanent identifier of the object 
        :return: A persistent random identifier.
        """
        subj_id = self.persistent(sp_name_qualifier, userid)
        return args2dict(subj_id, format=saml.NAMEID_FORMAT_PERSISTENT,
                                sp_name_qualifier=sp_name_qualifier)    

    def construct_nameid(self, local_policy, userid, sp_entity_id,
                        identity=None, name_id_policy=None):
        """ Returns a name_id for the object. How the name_id is 
        constructed depends on the context.
        
        :param local_policy: The policy the server is configured to follow
        :param user: The local permanent identifier of the object
        :param sp_entity_id: The 'user' of the name_id
        :param identity: Attribute/value pairs describing the object
        :param name_id_policy: The policy the server on the other side wants
            us to follow.
        :return: NameID instance precursor
        """
        if name_id_policy and name_id_policy.sp_name_qualifier:
            return self._get_vo_identifier(name_id_policy.sp_name_qualifier,
                                            userid, identity)
        else:
            nameid_format = local_policy.get_nameid_format(sp_entity_id)
            if nameid_format == saml.NAMEID_FORMAT_PERSISTENT:
                return self.persistent_nameid(self.entityid, userid)
            elif nameid_format == saml.NAMEID_FORMAT_TRANSIENT:
                return self.temporary_nameid()
                
    def temporary_nameid(self):
        """ Returns a random one-time identifier """
        return args2dict(sid(), format=saml.NAMEID_FORMAT_TRANSIENT)
        
        
class Server(object):
    """ A class that does things that IdPs or AAs do """
    def __init__(self, config_file="", config=None, cache="",
                    log=None, debug=0):

        self.log = log
        self.debug = debug
        if config_file:
            self.load_config(config_file)
        elif config:
            self.conf = config
        
        self.metadata = self.conf["metadata"]
        self.sc = security_context(self.conf, log)
        if cache:
            self.cache = Cache(cache)
        else:
            self.cache = Cache()
        
    def load_config(self, config_file):
        
        self.conf = Config()
        self.conf.load_file(config_file)
        if "subject_data" in self.conf:
            self.id = Identifier(self.conf["subject_data"], 
                                    self.conf["entityid"], self.conf.vo_conf,
                                    self.debug, self.log)
        else:
            self.id = None
    
    def issuer(self):
        """ Return an Issuer precursor """
        return args2dict( self.conf["entityid"], 
                            format=saml.NAMEID_FORMAT_ENTITY)
        
        
    def parse_authn_request(self, enc_request):
        """Parse a Authentication Request
        
        :param enc_request: The request in its transport format
        :return: A dictionary with keys:
            consumer_url - as gotten from the SPs entity_id and the metadata
            id - the id of the request
            sp_entity_id - the entity id of the SP
            request - The verified request
        """
        
        response = {}
        request_xml = decode_base64_and_inflate(enc_request)
        try:
            request = self.sc.correctly_signed_authn_request(request_xml)
            if self.log and self.debug:
                self.log.info("Request was correctly signed")
        except Exception:
            if self.log:
                self.log.error("Request was not correctly signed")
                self.log.info(request_xml)
            raise
                        
        return_destination = request.assertion_consumer_service_url
        # request.destination should be me 
        response["id"] = request.id # put in in_reply_to
        if request.version != VERSION:
            raise VersionMismatch(
                        "can't work with version %s" % request.version)
                        
        sp_entity_id = request.issuer.text
        # used to find return address in metadata
        try:
            consumer_url = self.metadata.consumer_url(sp_entity_id)
        except KeyError:
            self.log and self.log.info(
                    "entities: %s" % self.metadata.entity.keys())
            raise UnknownPrincipal(sp_entity_id)
            
        if not consumer_url: # what to do ?
            raise UnsupportedBinding(sp_entity_id)

        response["sp_entity_id"] = sp_entity_id

        if consumer_url != return_destination:
            # serious error on someones behalf
            if self.log:
                self.log.info("%s != %s" % (consumer_url, return_destination))
            else:
                print >> sys.stderr, \
                            "%s != %s" % (consumer_url, return_destination)
            raise OtherError("ConsumerURL and return destination mismatch")
        
        response["consumer_url"] = consumer_url
        response["request"] = request

        return response
                        
    def wants(self, sp_entity_id):
        """ Returns what attributes this SP requiers and which are optional
        if any such demands are registered in the Metadata.
        
        :param sp_entity_id: The entity id of the SP
        :return: 2-tuple, list of required and list of optional attributes
        """
        return self.metadata.requests(sp_entity_id)
        
    def parse_attribute_query(self, xml_string):
        """ Parse an attribute query
        
        :param xml_string: The Attribute Query as an XML string
        :return: 3-Tuple containing:
            subject - identifier of the subject
            attribute - which attributes that the requestor wants back
            query - the whole query
        """
        query = samlp.attribute_query_from_string(xml_string)
        # Check that it's 
        assert query.version == VERSION
        
        self.log and self.log.info(
            "%s ?= %s" % (query.destination, self.conf.aa_url))
        # Is it for me ?
        assert query.destination == self.conf.aa_url
        
        # verify signature
        
        subject = query.subject.name_id.text
        if query.attribute:
            attribute = query.attribute
        else:
            attribute = None
        return (subject, attribute, query)
            
    # ------------------------------------------------------------------------

    def _response(self, consumer_url, in_response_to, sp_entity_id, 
                    identity=None, name_id=None, status=None, sign=False,
                    policy=Policy()):
        """ Create a Response that adhers to the ??? profile.
        
        :param consumer_url: The URL which should receive the response
        :param in_response_to: The session identifier of the request
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param sign: Whether the assertion should be signed or not 
        :param policy: The attribute release policy for this instance
        :return: A Response instance
        """
                
        if not status:
            status = success_status_factory()
            
        _issuer = self.issuer()
        
        response = response_factory(
            issuer=_issuer,
            in_response_to = in_response_to,
            destination = consumer_url,
            status = status,
            )

        if identity:            
            ast = Assertion(identity)
            try:
                ast.apply_policy(sp_entity_id, policy, self.metadata)
            except MissingValue, exc:
                return self.error_response(consumer_url, in_response_to, 
                                               sp_entity_id, exc, name_id)

            assertion = ast.construct(sp_entity_id, in_response_to, name_id,
                                        self.conf.attribute_converters(), 
                                        policy, issuer=_issuer)
            
            if sign:
                assertion["signature"] = pre_signature_part(assertion["id"],
                                                        self.sc.my_cert, 1)

            # Store which assertion that has been sent to which SP about which
            # subject.
            
            self.cache.set(assertion["subject"]["name_id"]["text"], 
                            sp_entity_id, assertion, 
                            assertion["conditions"]["not_on_or_after"])
            
            response.update({"assertion":assertion})
                
        return signed_instance_factory(samlp.Response, response, self.sc)

    # ------------------------------------------------------------------------
    
    def do_response(self, consumer_url, in_response_to,
                        sp_entity_id, identity=None, name_id=None, 
                        status=None, sign=False ):

        return self._response(consumer_url, in_response_to,
                        sp_entity_id, identity, name_id, 
                        status, sign, self.conf.idp_policy())
                        
    # ------------------------------------------------------------------------
    
    def error_response(self, destination, in_response_to, spid, exc, 
                        name_id=None):
                        
        return self._response(
                        destination,    # consumer_url
                        in_response_to, # in_response_to
                        spid,           # sp_entity_id
                        None,           # identity
                        name_id,
                        status = status_from_exception_factory(exc)
                        )

    # ------------------------------------------------------------------------
    
    def do_aa_response(self, consumer_url, in_response_to, sp_entity_id, 
                        identity=None, userid="", name_id=None, ip_address="", 
                        issuer=None, status=None, sign=False, 
                        name_id_policy=None):

        name_id = self.id.construct_nameid(self.conf.aa_policy(), userid, 
                                            sp_entity_id, identity)
                                            
        return self._response(consumer_url, in_response_to,
                        sp_entity_id, identity, name_id, 
                        status, sign, policy=self.conf.aa_policy())

    # ------------------------------------------------------------------------


    # ------------------------------------------------------------------------

    def authn_response(self, identity, in_response_to, destination, 
                        sp_entity_id, name_id_policy, userid, sign=False):
        """ Constructs an AuthenticationResponse
        
        :param identity: Information about an user
        :param in_response_to: The identifier of the authentication request
            this response is an answer to.
        :param destination: Where the response should be sent
        :param sp_entity_id: The entity identifier of the Service Provider
        :param name_id_policy: ...
        :param userid: The subject identifier
        :return: A XML string representing an authentication response
        """
        
        try:
            name_id = self.id.construct_nameid(self.conf.idp_policy(),
                                  userid, sp_entity_id, identity,
                                  name_id_policy)
        except IOError, exc:
            response = self.error_response(destination, in_response_to, 
                                            sp_entity_id, exc, name_id)
            return ("%s" % response).split("\n")
        
        try:
            response = self.do_response(
                            destination,    # consumer_url
                            in_response_to, # in_response_to
                            sp_entity_id,   # sp_entity_id
                            identity,       # identity as dictionary
                            name_id,
                            sign=sign
                        )
        except MissingValue, exc:
            response = self.error_response(destination, in_response_to, 
                                        sp_entity_id, exc, name_id)
        

        if sign:
            try:
                return self.sc.sign_statement_using_xmlsec(response,
                                                        class_name(response))
            except Exception, exc:
                response = self.error_response(destination, in_response_to, 
                                                sp_entity_id, exc, name_id)
                return ("%s" % response).split("\n")
        else:
            return ("%s" % response).split("\n")
