#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2 import saml
from saml2 import config

from saml2.server import Server
from saml2.response import response_factory
from saml2.response import StatusResponse
from saml2.response import AuthnResponse
from saml2.sigver import security_context, MissingKey

from pytest import raises

XML_RESPONSE_FILE = "saml_signed.xml"
XML_RESPONSE_FILE2 = "saml2_response.xml"

def _eq(l1,l2):
    return set(l1) == set(l2)

IDENTITY = {"eduPersonAffiliation": ["staff", "member"],
            "surName": ["Jeter"], "givenName": ["Derek"],
            "mail": ["foo@gmail.com"],
            "title": ["shortstop"]}

class TestResponse:
    def setup_class(self):
        server = Server("idp_conf")
        name_id = server.ident.transient_nameid(
                                "urn:mace:example.com:saml:roland:sp","id12")

        self._resp_ = server.create_authn_response(IDENTITY,
                                            "id12",     # in_response_to
                                            "http://lingon.catalogix.se:8087/",   # consumer_url
                                            "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                                            name_id=name_id)
                
        self._sign_resp_ = server.create_authn_response(
                                IDENTITY,
                                "id12",                       # in_response_to
                                "http://lingon.catalogix.se:8087/",   # consumer_url
                                "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                                name_id = name_id,
                                sign_assertion=True)

        self._resp_authn = server.create_authn_response(
                                IDENTITY,
                                "id12",                       # in_response_to
                                "http://lingon.catalogix.se:8087/",   # consumer_url
                                "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                                name_id = name_id,
                                authn=(saml.AUTHN_PASSWORD,
                                       "http://www.example.com/login"))
        
        conf = config.SPConfig()
        conf.load_file("server_conf")
        self.conf = conf
        
    def test_1(self):
        xml_response = ("%s" % (self._resp_,))
        resp = response_factory(xml_response, self.conf, 
                                return_addr="http://lingon.catalogix.se:8087/",
                                outstanding_queries={"id12": "http://localhost:8088/sso"},
                                timeslack=10000, decode=False)
        
        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, AuthnResponse)

    def test_2(self):
        xml_response = self._sign_resp_
        resp = response_factory(xml_response, self.conf,
                                return_addr="http://lingon.catalogix.se:8087/",
                                outstanding_queries={"id12": "http://localhost:8088/sso"},
                                timeslack=10000, decode=False)

        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, AuthnResponse)


    def test_only_use_keys_in_metadata(self):
        conf = config.SPConfig()
        conf.load_file("sp_2_conf")

        sc = security_context(conf)
        # should fail
        raises(MissingKey,
               'sc.correctly_signed_response("%s" % self._sign_resp_)')
