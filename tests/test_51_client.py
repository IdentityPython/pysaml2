#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2.client import Saml2Client
from saml2 import samlp, client, BINDING_HTTP_POST
from saml2 import saml, utils, config, class_name, make_instance
#from saml2.sigver import correctly_signed_authn_request, verify_signature
#from saml2.server import Server

XML_RESPONSE_FILE = "saml_signed.xml"
XML_RESPONSE_FILE2 = "saml2_response.xml"

import os
        
def for_me(condition, me ):
    for restriction in condition.audience_restriction:
        audience = restriction.audience
        if audience.text.strip() == me:
            return True

def ava(attribute_statement):
    result = {}
    for attribute in attribute_statement.attribute:
        # Check name_format ??
        name = attribute.name.strip()
        result[name] = []
        for value in attribute.attribute_value:
            result[name].append(value.text.strip())
    return result

        
# def test_parse_3():
#     xml_response = open(XML_RESPONSE_FILE3).read()
#     response = samlp.response_from_string(xml_response)
#     client = Saml2Client({})
#     (ava, name_id, real_uri) = \
#             client.do_response(response, "xenosmilus.umdc.umu.se")
#     print 40*"="
#     print ava
#     print 40*","
#     print name_id
#     assert False

REQ1 = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:AttributeQuery Destination="https://idp.example.com/idp/" ID="1" IssueInstant="%s" Version="2.0" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns1:Issuer xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">http://vo.example.com/sp1</ns1:Issuer><ns1:Subject xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"><ns1:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">E8042FB4-4D5B-48C3-8E14-8EDD852790DD</ns1:NameID></ns1:Subject></ns0:AttributeQuery>"""
    
    
class TestClient:
    def setup_class(self):
        conf = config.Config()
        try:
            conf.load_file("tests/server.config")
        except IOError:
            conf.load_file("server.config")
        self.client = Saml2Client({},conf)
    
    def test_create_attribute_query1(self):
        req = self.client.create_attribute_query("1", 
            "E8042FB4-4D5B-48C3-8E14-8EDD852790DD",
            "http://vo.example.com/sp1",
            "https://idp.example.com/idp/",
            nameformat=saml.NAMEID_FORMAT_PERSISTENT)
        str = "%s" % req.to_string()
        print str
        assert str == REQ1 % req.issue_instant
        assert req.destination == "https://idp.example.com/idp/"
        assert req.id == "1"
        assert req.version == "2.0"
        subject = req.subject
        name_id = subject.name_id
        assert name_id.format == saml.NAMEID_FORMAT_PERSISTENT
        assert name_id.text == "E8042FB4-4D5B-48C3-8E14-8EDD852790DD"
        issuer = req.issuer
        assert issuer.text == "http://vo.example.com/sp1"
        
    def test_create_attribute_query2(self):
        req = self.client.create_attribute_query("1", 
            "E8042FB4-4D5B-48C3-8E14-8EDD852790DD", 
            "http://vo.example.com/sp1",
            "https://idp.example.com/idp/",
            attribute={
                ("urn:oid:2.5.4.42",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                "givenName"):None,
                ("urn:oid:2.5.4.4",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                "surname"):None,
                ("urn:oid:1.2.840.113549.1.9.1",
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"):None,
                },
            nameformat=saml.NAMEID_FORMAT_PERSISTENT)
                
        print req.to_string()
        assert req.destination == "https://idp.example.com/idp/"
        assert req.id == "1"
        assert req.version == "2.0"
        subject = req.subject
        name_id = subject.name_id
        assert name_id.format == saml.NAMEID_FORMAT_PERSISTENT
        assert name_id.text == "E8042FB4-4D5B-48C3-8E14-8EDD852790DD"
        assert len(req.attribute) == 3
        # one is givenName
        seen = []
        for attribute in req.attribute:
            if attribute.name == "urn:oid:2.5.4.42":
                assert attribute.name_format == saml.NAME_FORMAT_URI
                assert attribute.friendly_name == "givenName"
                seen.append("givenName")
            elif attribute.name == "urn:oid:2.5.4.4":
                assert attribute.name_format == saml.NAME_FORMAT_URI
                assert attribute.friendly_name == "surname"
                seen.append("surname")
            elif attribute.name == "urn:oid:1.2.840.113549.1.9.1":
                assert attribute.name_format == saml.NAME_FORMAT_URI
                if getattr(attribute,"friendly_name"):
                    assert False
                seen.append("email")
        assert set(seen) == set(["givenName","surname","email"])
        
    def test_create_attribute_query_3(self):
        req = self.client.create_attribute_query("1",
                "_e7b68a04488f715cda642fbdd90099f5", 
                "urn:mace:umu.se:saml/rolandsp",
                "https://aai-demo-idp.switch.ch/idp/shibboleth",
                nameformat=saml.NAMEID_FORMAT_TRANSIENT )
                
        assert isinstance(req, samlp.AttributeQuery)
        assert req.destination == "https://aai-demo-idp.switch.ch/idp/shibboleth"
        assert req.id == "1"
        assert req.version == "2.0"
        assert req.issue_instant
        assert req.issuer.text == "urn:mace:umu.se:saml/rolandsp"
        nameid = req.subject.name_id
        assert nameid.format == saml.NAMEID_FORMAT_TRANSIENT
        assert nameid.text == "_e7b68a04488f715cda642fbdd90099f5"

    def test_attribute_query(self):
        req = self.client.attribute_query( 
                "_e7b68a04488f715cda642fbdd90099f5", 
                "urn:mace:umu.se:saml/rolandsp",
                "https://aai-demo-idp.switch.ch/idp/shibboleth", 
                format=saml.NAMEID_FORMAT_TRANSIENT)

        # since no one is answering on the other end
        assert req == None
                
    def test_idp_entry(self):
        idp_entry = make_instance( samlp.IDPEntry,
                            self.client.idp_entry(name="Umeå Universitet",
                            location="https://idp.umu.se/"))
        
        assert idp_entry.name == "Umeå Universitet"
        assert idp_entry.loc == "https://idp.umu.se/"
        
    def test_scope(self):
        scope = make_instance(samlp.Scoping, self.client.scoping(
                                [self.client.idp_entry(name="Umeå Universitet",
                                    location="https://idp.umu.se/")]))
        
        assert scope.idp_list
        assert len(scope.idp_list.idp_entry) == 1
        idp_entry = scope.idp_list.idp_entry[0]
        assert idp_entry.name == "Umeå Universitet"
        assert idp_entry.loc == "https://idp.umu.se/"
    
    def test_create_auth_request_0(self):
        ar_str = self.client.authn_request("1",
                                    "http://www.example.com/sso",
                                    "http://www.example.org/service",
                                    "urn:mace:example.org:saml:sp",
                                    "My Name")
        ar = samlp.authn_request_from_string(ar_str)
        print ar
        assert ar.assertion_consumer_service_url == "http://www.example.org/service"
        assert ar.destination == "http://www.example.com/sso"
        assert ar.protocol_binding == BINDING_HTTP_POST
        assert ar.version == "2.0"
        assert ar.provider_name == "My Name"
        assert ar.issuer.text == "urn:mace:example.org:saml:sp"
        nid_policy = ar.name_id_policy
        assert nid_policy.allow_create == "true"
        assert nid_policy.format == saml.NAMEID_FORMAT_TRANSIENT

    def test_create_auth_request_vo(self):
        assert self.client.config["virtual_organization"].keys() == [
                                    "urn:mace:example.com:it:tek"]
                                    
        ar_str = self.client.authn_request("1",
                                    "http://www.example.com/sso",
                                    "http://www.example.org/service",
                                    "urn:mace:example.org:saml:sp",
                                    "My Name",
                                    vorg="urn:mace:example.com:it:tek")
              
        ar = samlp.authn_request_from_string(ar_str)
        print ar
        assert ar.assertion_consumer_service_url == "http://www.example.org/service"
        assert ar.destination == "http://www.example.com/sso"
        assert ar.protocol_binding == BINDING_HTTP_POST
        assert ar.version == "2.0"
        assert ar.provider_name == "My Name"
        assert ar.issuer.text == "urn:mace:example.org:saml:sp"
        nid_policy = ar.name_id_policy
        assert nid_policy.allow_create == "true"
        assert nid_policy.format == saml.NAMEID_FORMAT_PERSISTENT
        assert nid_policy.sp_name_qualifier == "urn:mace:example.com:it:tek"
        
    def test_sign_auth_request_0(self):
        #print self.client.config
        
        ar_str = self.client.authn_request("1",
                                    "http://www.example.com/sso",
                                    "http://www.example.org/service",
                                    "urn:mace:example.org:saml:sp",
                                    "My Name", sign=True)
                                    
        ar = samlp.authn_request_from_string(ar_str)

        assert ar
        assert ar.signature
        assert ar.signature.signature_value
        signed_info = ar.signature.signed_info
        #print signed_info
        assert len(signed_info.reference) == 1
        assert signed_info.reference[0].uri == "#1"
        assert signed_info.reference[0].digest_value
        print "------------------------------------------------"
        try:
            assert correctly_signed_authn_request(ar_str,
                    self.client.config["xmlsec_binary"],
                    self.client.config["metadata"])
        except Exception: # missing certificate
            self.client.sc.verify_signature(ar_str, node_name=class_name(ar))
