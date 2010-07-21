#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2 import samlp, BINDING_HTTP_POST
from saml2 import saml, config, class_name, make_instance
from saml2.server import Server
from saml2.authnresponse import authn_response

XML_RESPONSE_FILE = "saml_signed.xml"
XML_RESPONSE_FILE2 = "saml2_response.xml"

import os
        
def _eq(l1,l2):
    return set(l1) == set(l2)
    
class TestAuthnResponse:
    def setup_class(self):
        server = Server("idp.config")
        name_id = server.ident.temporary_nameid()

        self._resp_ = server.do_response(
                    "http://lingon.catalogix.se:8087/",   # consumer_url
                    "12",                       # in_response_to
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                    {"eduPersonEntitlement":"Jeter"},
                    name_id = name_id
                )
                
        self._sign_resp_ = server.do_response(
                    "http://lingon.catalogix.se:8087/",   # consumer_url
                    "12",                       # in_response_to
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                    {"eduPersonEntitlement":"Jeter"},
                    name_id = name_id,
                    sign=True
                )

        conf = config.Config()
        try:
            conf.load_file("tests/server.config")
        except IOError:
            conf.load_file("server.config")
        self.ar = authn_response(conf,"")
    
    def test_verify_1(self):
        xml_response = ("%s" % (self._resp_,)).split("\n")[1]
        self.ar.outstanding_queries = {"12": "http://localhost:8088/sso"}
        self.ar.requestor = "urn:mace:example.com:saml:roland:sp"
        self.ar.timeslack = 10000
        self.ar.loads(xml_response, decode=False)
        self.ar.verify()
        
        print self.ar.__dict__
        assert self.ar.came_from == 'http://localhost:8088/sso'
        assert self.ar.session_id() == "12"
        assert self.ar.ava == {'eduPersonEntitlement': ['Jeter'] }
        assert self.ar.name_id
        assert self.ar.issuer() == 'urn:mace:example.com:saml:roland:idp'
    
    def test_verify_signed_1(self):
        xml_response = ("%s" % (self._sign_resp_,)).split("\n",1)[1]
        print xml_response
        
        self.ar.outstanding_queries = {"12": "http://localhost:8088/sso"}
        self.ar.requestor = "urn:mace:example.com:saml:roland:sp"
        self.ar.timeslack = 10000
        self.ar.loads(xml_response, decode=False)
        self.ar.verify()
        
        print self.ar.__dict__
        assert self.ar.came_from == 'http://localhost:8088/sso'
        assert self.ar.session_id() == "12"
        assert self.ar.ava == {'eduPersonEntitlement': ['Jeter'] }
        assert self.ar.issuer() == 'urn:mace:example.com:saml:roland:idp'
        assert self.ar.name_id

    def test_parse_2(self):
        xml_response = open(XML_RESPONSE_FILE).read()
        ID = "bahigehogffohiphlfmplepdpcohkhhmheppcdie"
        self.ar.outstanding_queries = {ID: "http://localhost:8088/foo"}    
        self.ar.requestor = "xenosmilus.umdc.umu.se"
        # roughly a year, should create the response on the fly
        self.ar.timeslack = 31536000
        self.ar.loads(xml_response, decode=False)
        self.ar.verify()
        
        print self.ar.__dict__
        assert self.ar.came_from == 'http://localhost:8088/foo'
        assert self.ar.session_id() == ID
        assert self.ar.name_id

