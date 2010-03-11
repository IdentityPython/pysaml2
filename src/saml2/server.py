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

from saml2 import saml, samlp, VERSION

from saml2.utils import issuer_factory, conditions_factory, audience_restriction_factory
from saml2.utils import sid, decode_base64_and_inflate, make_instance
from saml2.utils import audience_factory, name_id_factory, assertion_factory
from saml2.utils import subject_factory, subject_confirmation_factory, response_factory
from saml2.utils import authn_statement_factory, MissingValue
from saml2.utils import subject_confirmation_data_factory, success_status_factory
from saml2.utils import filter_attribute_value_assertions
from saml2.utils import OtherError, do_attribute_statement
from saml2.utils import VersionMismatch, UnknownPrincipal, UnsupportedBinding
from saml2.utils import filter_on_attributes, status_from_exception_factory

from saml2.sigver import correctly_signed_authn_request
from saml2.sigver import pre_signature_part
from saml2.time_util import instant, in_a_while
from saml2.config import Config
from saml2.cache import Cache    


class Server(object):
    """ A class that does things that IdPs or AAs do """
    def __init__(self, config_file="", config=None, cache="",
                    log=None, debug=0):
        if config_file:
            self.load_config(config_file)
        elif config:
            self.conf = config
        
        self.metadata = self.conf["metadata"]
        if cache:
            self.cache = Cache(cache)
        else:
            self.cache = Cache()
        self.log = log
        self.debug = debug
        
    def load_config(self, config_file):
        self.conf = Config()
        self.conf.load_file(config_file)
        if "subject_data" in self.conf:
            self.id_map = shelve.open(self.conf["subject_data"],
                                        writeback=True)
        else:
            self.id_map = None
    
    def issuer(self):
        return issuer_factory( self.conf["entityid"], 
                        format=saml.NAMEID_FORMAT_ENTITY)
        
    def persistent_id(self, entity_id, subject_id):
        """ Keeps the link between a permanent identifier and a 
        temporary/pseudotemporary identifier for a subject
        
        :param entity_id: SP entity ID or VO entity ID
        :param subject_id: The local identifier of the subject
        :return: A arbitrary identifier for the subject unique to the
            entity_id
        """
        if self.debug:
            self.log and self.log.debug("Id map keys: %s" % self.id_map.keys())
            
        try:
            emap = self.id_map[entity_id]
        except KeyError:
            emap = self.id_map[entity_id] = {"forward":{}, "backward":{}}

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
            self.id_map[entity_id] = emap
            self.id_map.sync()
            
            return temp_id
        
    def parse_authn_request(self, enc_request):
        """Parse a Authentication Request
        
        :param enc_request: The request in its transport format
        :return: A dictionary with keys:
            consumer_url - as gotten from the SPs entity_id and the metadata
            id - the id of the request
            name_id_policy - how to chose the subjects identifier
            sp_entityid - the entity id of the SP
        """
        
        response = {}
        request_xml = decode_base64_and_inflate(enc_request)
        try:
            request = correctly_signed_authn_request(request_xml, 
                        self.conf["xmlsec_binary"], log=self.log)
            if self.log and self.debug:
                self.log.error("Request was correctly signed")
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
        sp_entityid = request.issuer.text
        # used to find return address in metadata
        try:
            consumer_url = self.metadata.consumer_url(sp_entityid)
        except KeyError:
            self.log and self.log.info(
                    "entities: %s" % self.metadata.entity.keys())
            raise UnknownPrincipal(sp_entityid)
        if not consumer_url: # what to do ?
            raise UnsupportedBinding(sp_entityid)

        response["sp_entityid"] = sp_entityid

        if consumer_url != return_destination:
            # serious error on someones behalf
            self.log and self.log.info("%s != %s" % (consumer_url,
                            return_destination))
            print "%s != %s" % (consumer_url, return_destination)
            raise OtherError("ConsumerURL and return destination mismatch")
        
        response["consumer_url"] = consumer_url
        response["request"] = request
        self.log and self.log.info("AuthNRequest: %s" % request)
        return response
                        
    def wants(self, sp_entity_id):
        """
        :param sp_entity_id: The entity id of the SP
        :return: 2-tuple, list of required and list of optional attributes
        """
        return self.metadata.requests(sp_entity_id)
        
    def parse_attribute_query(self, xml_string):
        query = samlp.attribute_query_from_string(xml_string)
        assert query.version == VERSION
        self.log and self.log.info(
            "%s ?= %s" % (query.destination, 
                            self.conf["service"]["aa"]["url"]))
        assert query.destination == self.conf["service"]["aa"]["url"]
        
        # verify signature
        
        subject = query.subject.name_id.text
        if query.attribute:
            attribute = query.attribute
        else:
            attribute = None
        return (subject, attribute, query)
        
    def find_subject(self, subject, attribute=None):
        pass
                
    def _not_on_or_after(self, sp_entity_id):
        """ When the assertion stops being valid, should not be
        used after this time.
        
        :return: String representation of the time
        """
        if "assertions" in self.conf:
            try:
                spec = self.conf["assertions"][sp_entity_id]["lifetime"]
                return in_a_while(**spec)
            except KeyError:
                try:
                    spec = self.conf["assertions"]["default"]["lifetime"]
                    return in_a_while(**spec)
                except KeyError:
                    pass
        
        # default is a hour
        return in_a_while(**{"hours":1})
            
    def do_sso_response(self, consumer_url, in_response_to,
                        sp_entity_id, identity, name_id=None, status=None ):
        """ Create a Response the follows the ??? profile.
        
        :param consumer_url: The URL which should receive the response
        :param in_response_to: The session identifier of the request
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param name_id: The identifier of the subject 
        :return: A Response instance
        """
        attr_statement = do_attribute_statement(identity)
        
        # start using now and for a hour
        conds = conditions_factory(
                        not_before=instant(), 
                        # How long might depend on who's getting it
                        not_on_or_after=self._not_on_or_after(sp_entity_id), 
                        audience_restriction=audience_restriction_factory(
                                audience=audience_factory(sp_entity_id)))
                                
        # temporary identifier or ??
        if not name_id:
            name_id = name_id_factory(sid(), format=saml.NAMEID_FORMAT_TRANSIENT)

        assertion = assertion_factory(
            attribute_statement = attr_statement,
            authn_statement= authn_statement_factory(
                        authn_instant=instant(),
                        session_index=sid()),
            conditions=conds,
            subject=subject_factory(
                name_id=name_id,
                method=saml.SUBJECT_CONFIRMATION_METHOD_BEARER,
                subject_confirmation=subject_confirmation_factory(
                    subject_confirmation_data=subject_confirmation_data_factory(
                            in_response_to=in_response_to))),
            ),
            
        if not status:
            status = success_status_factory()
            
        tmp = response_factory(
            issuer=self.issuer(),
            in_response_to = in_response_to,
            destination = consumer_url,
            status = status,
            assertion=assertion,
            )
        
        # Store which assertion that has been sent to which SP about which
        # subject.
        self.cache.set(name_id["text"], sp_entity_id, assertion, 
                        conds["not_on_or_after"])
                        
        return make_instance(samlp.Response, tmp)

    def do_aa_response(self, consumer_url, in_response_to,
                        sp_entity_id, identity, 
                        name_id=None, ip_address="", issuer=None, sign=False):

        attr_statement = do_attribute_statement(identity)
        
        # start using now and for a hour
        conds = conditions_factory(
                        not_before=instant(), 
                        # an hour from now
                        not_on_or_after=self._not_on_or_after(sp_entity_id), 
                        audience_restriction=audience_restriction_factory(
                                audience=audience_factory(sp_entity_id)))

        # temporary identifier or ??
        if not name_id:
            name_id = name_id_factory(sid(), format=saml.NAMEID_FORMAT_TRANSIENT)

        assertion = assertion_factory(
            subject = subject_factory(
                name_id = name_id,
                method = saml.SUBJECT_CONFIRMATION_METHOD_BEARER,
                subject_confirmation = subject_confirmation_factory(
                    subject_confirmation_data = subject_confirmation_data_factory(
                        in_response_to = in_response_to,
                        not_on_or_after = self._not_on_or_after(sp_entity_id),
                        address = ip_address,
                        recipient = consumer_url))),
            attribute_statement = attr_statement,
            authn_statement = authn_statement_factory(
                        authn_instant = instant(),
                        session_index = sid()),
            conditions=conds,
            )
            
        if sign:
            assertion["signature"] = pre_signature_part(assertion["id"])
            
        self.cache.set(name_id["text"], sp_entity_id, assertion, 
                            conds["not_on_or_after"])
            
        tmp = response_factory(
            issuer=issuer,
            in_response_to=in_response_to,
            destination=consumer_url,
            status=success_status_factory(),
            assertion=assertion,
            )

        return make_instance(samlp.Response, tmp)

    def filter_ava(self, ava, sp_entity_id, required=None, optional=None,
                    typ="idp"):
        """ What attribute and attribute values returns depends on what
        the SP has said it wants in the request or in the metadata file and
        what the IdP/AA wants to release. An assumption is that what the SP
        asks for overrides whatever is in the metadata. But of course the 
        IdP never releases anything it doesn't want to.    
        
        :param ava: All the attributes and values that are available
        :param sp_entity_id: The entity ID of the SP
        :param required: Attributes that the SP requires in the assertion
        :param optional: Attributes that the SP thinks is optional
        :param typ: IdPs and AAs does this, and they have different parts
            of the configuration.
        :return: A possibly modified AVA
        """

        try:
            assertions = self.conf["service"][typ]["assertions"]
            try:
                restrictions = assertions[sp_entity_id][
                                                "attribute_restrictions"]
            except KeyError:
                try:
                    restrictions = assertions["default"][
                                                "attribute_restrictions"]
                except KeyError:
                    restrictions = None
        except KeyError:
            restrictions = None
                
        if restrictions:
            ava = filter_attribute_value_assertions(ava, restrictions)

        if required or optional:
            ava = filter_on_attributes(ava, required, optional)
            
        return ava
        
    def authn_response(self, identity, in_response_to, destination, spid,
                    name_id_policy, userid):
        """ Constructs an AuthenticationResponse
        
        :param identity: Information about an user
        :param in_response_to: The identifier of the authentication request
            this response is an answer to.
        :param destination: Where the response should be sent
        :param sid: The entity identifier of the Service Provider
        :param name_id_policy: ...
        :param userid: The subject identifier
        :return: A XML string representing an authentication response
        """
        name_id = None
        if name_id_policy.sp_name_qualifier:
            try:
                vo_conf = self.conf["virtual_organization"][
                                name_id_policy.sp_name_qualifier]
                subj_id = identity[vo_conf["common_identifier"]]
            except KeyError:
                self.log.info(
                    "Get persistent ID (%s,%s)" % (
                                    name_id_policy.sp_name_qualifier,userid))
                subj_id = self.persistent_id(name_id_policy.sp_name_qualifier, 
                                            userid)
                self.log.info("=> %s" % subj_id)
                
            name_id = name_id_factory(subj_id, 
                        format=saml.NAMEID_FORMAT_PERSISTENT,
                        sp_name_qualifier=name_id_policy.sp_name_qualifier)
        
        # Do attribute filtering
        (required, optional) = self.conf["metadata"].attribute_consumer(spid)
        try:
            identity = self.filter_ava( identity, spid, required, optional)
            resp = self.do_sso_response(
                            destination,    # consumer_url
                            in_response_to, # in_response_to
                            spid,           # sp_entity_id
                            identity,       # identity as dictionary
                            name_id,
                        )
        except MissingValue, exc:
            
            resp = self.do_sso_response(
                            destination,    # consumer_url
                            in_response_to, # in_response_to
                            spid,           # sp_entity_id
                            name_id,
                            status = status_from_exception_factory(exc)
                        )
            
        
        
        return ("%s" % resp).split("\n")