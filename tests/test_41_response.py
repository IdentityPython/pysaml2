#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2 import samlp, BINDING_HTTP_POST
from saml2 import saml, config, class_name, make_instance

from saml2.server import Server
from saml2.response import response_factory
from saml2.response import LogoutResponse
from saml2.response import StatusResponse
from saml2.response import AuthnResponse
from saml2.sigver import security_context

XML_RESPONSE_FILE = "saml_signed.xml"
XML_RESPONSE_FILE2 = "saml2_response.xml"

import os
        
def _eq(l1,l2):
    return set(l1) == set(l2)
    
class TestResponse:
    def setup_class(self):
        server = Server("idp.config")
        name_id = server.ident.temporary_nameid()

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

        self._logout_resp = server.logout_response("id12")
        
        conf = config.Config()
        try:
            conf.load_file("tests/server.config")
        except IOError:
            conf.load_file("server.config")
        self.conf = conf
        
    def test_1(self):
        xml_response = ("%s" % (self._resp_,)).split("\n")[1]
        resp = response_factory(xml_response, self.conf, 
                                entity_id="urn:mace:example.com:saml:roland:sp", 
                                return_addr="http://lingon.catalogix.se:8087/", 
                                outstanding_queries={"id12": "http://localhost:8088/sso"},
                                timeslack=10000, decode=False)
        
        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, AuthnResponse)

    def test_2(self):
        xml_response = ("%s" % (self._sign_resp_,)).split("\n",1)[1]
        sec = security_context(self.conf)
        resp = response_factory(xml_response, self.conf, 
                                entity_id="urn:mace:example.com:saml:roland:sp", 
                                return_addr="http://lingon.catalogix.se:8087/", 
                                outstanding_queries={"id12": "http://localhost:8088/sso"},
                                timeslack=10000, decode=False)

        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, AuthnResponse)

    def test_3(self):
        xml_response = ("%s" % (self._logout_resp,)).split("\n")[1]
        sec = security_context(self.conf)
        resp = response_factory(xml_response, self.conf, 
                                entity_id="urn:mace:example.com:saml:roland:sp", 
                                return_addr="http://lingon.catalogix.se:8087/", 
                                outstanding_queries={"id12": "http://localhost:8088/sso"},
                                timeslack=10000, decode=False)

        assert isinstance(resp, StatusResponse)
        assert isinstance(resp, LogoutResponse)
        