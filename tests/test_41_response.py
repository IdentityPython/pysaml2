#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2 import saml
from saml2 import config

from saml2.server import Server
from saml2.response import response_factory
from saml2.response import StatusResponse
from saml2.response import AuthnResponse
from saml2.sigver import SecurityContext
from saml2.sigver import security_context
from saml2.sigver import get_xmlsec_binary
from saml2.sigver import MissingKey

from pytest import raises

XML_RESPONSE_FILE = "saml_signed.xml"
XML_RESPONSE_FILE2 = "saml2_response.xml"


def _eq(l1,l2):
    return set(l1) == set(l2)
    
class TestResponse:
    def setup_class(self):
        server = Server("idp_conf")
        name_id = server.ident.transient_nameid(
                                "urn:mace:example.com:saml:roland:sp",
                                "id12")

        self._resp_ = server.do_response(
                    "id12",                       # in_response_to
                    "http://lingon.catalogix.se:8087/",   # consumer_url
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                    {"eduPersonEntitlement":"Jeter"},
                    name_id = name_id
                )
                
        self._sign_resp_ = server.do_response(
                    "id12",                       # in_response_to
                    "http://lingon.catalogix.se:8087/",   # consumer_url
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                    {"eduPersonEntitlement":"Jeter"},
                    name_id = name_id,
                    sign=True
                )

        self._resp_authn = server.do_response(
                    "id12",                       # in_response_to
                    "http://lingon.catalogix.se:8087/",   # consumer_url
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                    {"eduPersonEntitlement":"Jeter"},
                    name_id = name_id,
                    authn=(saml.AUTHN_PASSWORD, "http://www.example.com/login")
                )
        
        conf = config.SPConfig()
        conf.load_file("server_conf")
        self.conf = conf
        
    def test_1(self):
        xml_response = ("%s" % (self._resp_,)).split("\n")[1]
        resp = response_factory(xml_response, self.conf, 
                                return_addr="http://lingon.catalogix.se:8087/",
                                outstanding_queries={"id12": "http://localhost:8088/sso"},
                                timeslack=10000, decode=False)
        
        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, AuthnResponse)

    def test_2(self):
        xml_response = ("%s" % (self._sign_resp_,)).split("\n",1)[1]
        resp = response_factory(xml_response, self.conf,
                                return_addr="http://lingon.catalogix.se:8087/",
                                outstanding_queries={"id12": "http://localhost:8088/sso"},
                                timeslack=10000, decode=False)

        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, AuthnResponse)

    # def test_3(self):
    #     xml_response = ("%s" % (self._logout_resp,)).split("\n")[1]
    #     sec = security_context(self.conf)
    #     resp = response_factory(xml_response, self.conf, 
    #                             return_addr="http://lingon.catalogix.se:8087/",
    #                             outstanding_queries={"id12": "http://localhost:8088/sso"},
    #                             timeslack=10000, decode=False)
    # 
    #     assert isinstance(resp, StatusResponse)
    #     assert isinstance(resp, LogoutResponse)

    def test_decrypt(self):
        attr_stat = saml.attribute_statement_from_string(
                            open("encrypted_attribute_statement.xml").read())

        assert len(attr_stat.attribute) == 0
        assert len(attr_stat.encrypted_attribute) == 4

        xmlsec = get_xmlsec_binary()
        sec = SecurityContext(xmlsec, key_file="private_key.pem")

        resp = AuthnResponse(sec, None, "entity_id")
        resp.decrypt_attributes(attr_stat)

        assert len(attr_stat.attribute) == 4
        assert len(attr_stat.encrypted_attribute) == 4


    def test_only_use_keys_in_metadata(self):
        conf = config.SPConfig()
        conf.load_file("sp_2_conf")

        sc = security_context(conf)
        # should fail
        raises(MissingKey,
               'sc.correctly_signed_response("%s" % self._sign_resp_)')
