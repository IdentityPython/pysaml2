#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
from urlparse import urlparse, parse_qs

from saml2.client import Saml2Client, LogoutError
from saml2 import samlp, client, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import saml, s_utils, config, class_name
#from saml2.sigver import correctly_signed_authn_request, verify_signature
from saml2.server import Server
from saml2.s_utils import decode_base64_and_inflate
from saml2.time_util import in_a_while
from saml2.sigver import xmlsec_version

from py.test import raises

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

def _leq(l1, l2):
    return set(l1) == set(l2)
        
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

REQ1 = { "1.2.14": """<?xml version='1.0' encoding='UTF-8'?>
<ns0:AttributeQuery Destination="https://idp.example.com/idp/" ID="id1" IssueInstant="%s" Version="2.0" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">urn:mace:example.com:saml:roland:sp</ns1:Issuer><ns1:Subject xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"><ns1:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">E8042FB4-4D5B-48C3-8E14-8EDD852790DD</ns1:NameID></ns1:Subject></ns0:AttributeQuery>""",
    "":"""<?xml version='1.0' encoding='UTF-8'?>
<ns0:AttributeQuery xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion" Destination="https://idp.example.com/idp/" ID="id1" IssueInstant="%s" Version="2.0"><ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">urn:mace:example.com:saml:roland:sp</ns1:Issuer><ns1:Subject><ns1:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">E8042FB4-4D5B-48C3-8E14-8EDD852790DD</ns1:NameID></ns1:Subject></ns0:AttributeQuery>"""}

class TestClient:
    def setup_class(self):
        self.server = Server("idp.config")

        conf = config.SPConfig()
        try:
            conf.load_file("tests/server.config")
        except IOError:
            conf.load_file("server.config")
        self.client = Saml2Client(conf)
    
    def test_create_attribute_query1(self):
        req = self.client.create_attribute_query("id1", 
            "E8042FB4-4D5B-48C3-8E14-8EDD852790DD",
            "https://idp.example.com/idp/",
            self.client.issuer(),
            nameid_format=saml.NAMEID_FORMAT_PERSISTENT)
        reqstr = "%s" % req.to_string()
        xmlsec_vers = xmlsec_version(self.client.config["xmlsec_binary"])
        print "XMLSEC version: %s" % xmlsec_vers
        print reqstr
        print REQ1[xmlsec_vers] % req.issue_instant
        assert reqstr == REQ1[xmlsec_vers] % req.issue_instant
        assert req.destination == "https://idp.example.com/idp/"
        assert req.id == "id1"
        assert req.version == "2.0"
        subject = req.subject
        name_id = subject.name_id
        assert name_id.format == saml.NAMEID_FORMAT_PERSISTENT
        assert name_id.text == "E8042FB4-4D5B-48C3-8E14-8EDD852790DD"
        issuer = req.issuer
        assert issuer.text == "urn:mace:example.com:saml:roland:sp"
        
    def test_create_attribute_query2(self):
        req = self.client.create_attribute_query("id1", 
            "E8042FB4-4D5B-48C3-8E14-8EDD852790DD", 
            "https://idp.example.com/idp/",
            self.client.issuer(),
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
            nameid_format=saml.NAMEID_FORMAT_PERSISTENT)
                
        print req.to_string()
        assert req.destination == "https://idp.example.com/idp/"
        assert req.id == "id1"
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
        req = self.client.create_attribute_query("id1",
                "_e7b68a04488f715cda642fbdd90099f5", 
                "https://aai-demo-idp.switch.ch/idp/shibboleth",
                self.client.issuer(),
                nameid_format=saml.NAMEID_FORMAT_TRANSIENT )
                
        assert isinstance(req, samlp.AttributeQuery)
        assert req.destination == "https://aai-demo-idp.switch.ch/idp/shibboleth"
        assert req.id == "id1"
        assert req.version == "2.0"
        assert req.issue_instant
        assert req.issuer.text == "urn:mace:example.com:saml:roland:sp"
        nameid = req.subject.name_id
        assert nameid.format == saml.NAMEID_FORMAT_TRANSIENT
        assert nameid.text == "_e7b68a04488f715cda642fbdd90099f5"

    def test_attribute_query(self):
        req = self.client.attribute_query( 
                "_e7b68a04488f715cda642fbdd90099f5", 
                "https://aai-demo-idp.switch.ch/idp/shibboleth", 
                self.client.issuer(),
                nameid_format=saml.NAMEID_FORMAT_TRANSIENT)

        # since no one is answering on the other end
        assert req == None
                
    # def test_idp_entry(self):
    #     idp_entry = self.client.idp_entry(name="Umeå Universitet",
    #                         location="https://idp.umu.se/")
    #     
    #     assert idp_entry.name == "Umeå Universitet"
    #     assert idp_entry.loc == "https://idp.umu.se/"
    #     
    # def test_scope(self):
    #     entity_id = "urn:mace:example.com:saml:roland:idp"
    #     locs = self.client.metadata.single_sign_on_services(entity_id)
    #     scope = self.client.scoping_from_metadata(entity_id, locs)
    #     
    #     assert scope.idp_list
    #     assert len(scope.idp_list.idp_entry) == 1
    #     idp_entry = scope.idp_list.idp_entry[0]
    #     assert idp_entry.name == 'Exempel AB'
    #     assert idp_entry.loc == ['http://localhost:8088/sso']
    
    def test_create_auth_request_0(self):
        ar_str = self.client.authn_request("id1",
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
                                    
        ar_str = self.client.authn_request("666",
                                    "http://www.example.com/sso",
                                    "http://www.example.org/service",
                                    "urn:mace:example.org:saml:sp",
                                    "My Name",
                                    vorg="urn:mace:example.com:it:tek")
              
        ar = samlp.authn_request_from_string(ar_str)
        print ar
        assert ar.id == "666"
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
        
        ar_str = self.client.authn_request("id1",
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
        assert signed_info.reference[0].uri == "#id1"
        assert signed_info.reference[0].digest_value
        print "------------------------------------------------"
        try:
            assert correctly_signed_authn_request(ar_str,
                    self.client.config["xmlsec_binary"],
                    self.client.config["metadata"])
        except Exception: # missing certificate
            self.client.sec.verify_signature(ar_str, node_name=class_name(ar))

    def test_response(self):
        IDP = "urn:mace:example.com:saml:roland:idp"
        
        ava = { "givenName": ["Derek"], "surname": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com"]}

        resp_str = "\n".join(self.server.authn_response(
                    identity=ava, 
                    in_response_to="id1", 
                    destination="http://lingon.catalogix.se:8087/", 
                    sp_entity_id="urn:mace:example.com:saml:roland:sp",
                    name_id_policy=samlp.NameIDPolicy(
                        format=saml.NAMEID_FORMAT_PERSISTENT),
                    userid="foba0001@example.com"))

        resp_str = base64.encodestring(resp_str)
        
        authn_response = self.client.response({"SAMLResponse":resp_str},
                            "urn:mace:example.com:saml:roland:sp",
                            {"id1":"http://foo.example.com/service"})
                            
        assert authn_response != None
        assert authn_response.issuer() == IDP
        assert authn_response.response.assertion[0].issuer.text == IDP
        session_info = authn_response.session_info()

        print session_info
        assert session_info["ava"] == {'mail': ['derek@nyy.mlb.com'], 'givenName': ['Derek'], 'sn': ['Jeter']}
        assert session_info["issuer"] == IDP
        assert session_info["came_from"] == "http://foo.example.com/service"
        response = samlp.response_from_string(authn_response.xmlstr)        
        assert response.destination == "http://lingon.catalogix.se:8087/"

        # One person in the cache
        assert len(self.client.users.subjects()) == 1
        subject_id = self.client.users.subjects()[0]
        print "||||", self.client.users.get_info_from(subject_id, IDP)
        # The information I have about the subject comes from one source
        assert self.client.users.issuers_of_info(subject_id) == [IDP]

        # --- authenticate another person
        
        ava = { "givenName": ["Alfonson"], "surname": ["Soriano"], 
                "mail": ["alfonson@chc.mlb.com"]}

        resp_str = "\n".join(self.server.authn_response(
                    identity=ava, 
                    in_response_to="id2", 
                    destination="http://lingon.catalogix.se:8087/", 
                    sp_entity_id="urn:mace:example.com:saml:roland:sp",
                    name_id_policy=samlp.NameIDPolicy(
                        format=saml.NAMEID_FORMAT_PERSISTENT),
                    userid="also0001@example.com"))

        resp_str = base64.encodestring(resp_str)
        
        authn_response = self.client.response({"SAMLResponse":resp_str},
                            "urn:mace:example.com:saml:roland:sp",
                            {"id2":"http://foo.example.com/service"})
        
        # Two persons in the cache
        assert len(self.client.users.subjects()) == 2
        issuers = [self.client.users.issuers_of_info(s) for s in self.client.users.subjects()]
        # The information I have about the subjects comes from the same source
        print issuers
        assert issuers == [[IDP], [IDP]]
        
    def test_init_values(self):
        print self.client.config["service"]["sp"]
        spentityid = self.client._spentityid()
        print spentityid
        assert spentityid == "urn:mace:example.com:saml:roland:sp"
        location = self.client._sso_location()
        print location
        assert location == 'http://localhost:8088/sso'
        service_url = self.client._service_url()
        print service_url
        assert service_url == "http://lingon.catalogix.se:8087/"
        my_name = self.client._my_name()
        print my_name
        assert my_name == "urn:mace:example.com:saml:roland:sp"

    def test_authenticate(self):
        (sid, response) = self.client.authenticate(
                                    "http://www.example.com/sso",
                                    "http://www.example.org/service",
                                    "urn:mace:example.org:saml:sp",
                                    "My Name",
                                    "http://www.example.com/relay_state")
        assert sid != None
        assert response[0] == "Location"
        o = urlparse(response[1])
        qdict = parse_qs(o.query)
        assert _leq(qdict.keys(), ['SAMLRequest', 'RelayState'])
        saml_request = decode_base64_and_inflate(qdict["SAMLRequest"][0])
        print saml_request
        authnreq = samlp.authn_request_from_string(saml_request)
        assert authnreq.id == sid

    def test_authenticate_no_args(self):
        (sid, request) = self.client.authenticate(relay_state="http://www.example.com/relay_state")
        assert sid != None
        assert request[0] == "Location"
        o = urlparse(request[1])
        qdict = parse_qs(o.query)
        assert _leq(qdict.keys(), ['SAMLRequest', 'RelayState'])
        saml_request = decode_base64_and_inflate(qdict["SAMLRequest"][0])
        assert qdict["RelayState"][0] == "http://www.example.com/relay_state"
        print saml_request
        authnreq = samlp.authn_request_from_string(saml_request)
        print authnreq.keyswv()
        assert authnreq.id == sid
        assert authnreq.destination == "http://localhost:8088/sso"
        assert authnreq.assertion_consumer_service_url == "http://lingon.catalogix.se:8087/"
        assert authnreq.provider_name == "urn:mace:example.com:saml:roland:sp"
        assert authnreq.protocol_binding == BINDING_HTTP_POST
        name_id_policy = authnreq.name_id_policy
        assert name_id_policy.allow_create == "true" 
        assert name_id_policy.format == "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" 
        issuer = authnreq.issuer
        assert issuer.text == "urn:mace:example.com:saml:roland:sp"
        
        
    def test_logout_1(self):
        """ one IdP/AA with BINDING_HTTP_REDIRECT on single_logout_service"""

        # information about the user from an IdP
        session_info = {
            "name_id": "123456",
            "issuer": "urn:mace:example.com:saml:roland:idp",
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "givenName": "Anders",
                "surName": "Andersson",
                "mail": "anders.andersson@example.com"
            }
        }
        self.client.users.add_information_about_person(session_info)
        entity_ids = self.client.users.issuers_of_info("123456")
        assert entity_ids == ["urn:mace:example.com:saml:roland:idp"]
        resp = self.client.global_logout("123456", "Tired", in_a_while(minutes=5))
        print resp
        assert resp
        assert resp[0] # a session_id
        assert resp[1] == '200 OK'
        assert resp[2] == [('Content-type', 'text/html')]
        assert resp[3][0] == '<head>'
        assert resp[3][1] == '<title>SAML 2.0 POST</title>'
        session_info = self.client.state[resp[0]]
        print session_info
        assert session_info["entity_id"] == entity_ids[0]
        assert session_info["subject_id"] == "123456"
        assert session_info["reason"] == "Tired"
        assert session_info["operation"] == "SLO"
        assert session_info["entity_ids"] == entity_ids
        assert session_info["sign"] == False

    def test_logout_2(self):
        """ one IdP/AA with BINDING_SOAP, can't actually send something"""

        conf = config.SPConfig()
        conf.load_file("server2.config")
        client = Saml2Client(conf)

        # information about the user from an IdP
        session_info = {
            "name_id": "123456",
            "issuer": "urn:mace:example.com:saml:roland:idp",
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "givenName": "Anders",
                "surName": "Andersson",
                "mail": "anders.andersson@example.com"
            }
        }
        client.users.add_information_about_person(session_info)
        entity_ids = self.client.users.issuers_of_info("123456")
        assert entity_ids == ["urn:mace:example.com:saml:roland:idp"]
        destination = client.config.logout_service(entity_ids[0], BINDING_SOAP)
        print destination
        assert destination == 'http://localhost:8088/slo'

        # Will raise an error since there is noone at the other end.
        raises(LogoutError, 'client.global_logout("123456", "Tired", in_a_while(minutes=5))')

    def test_logout_3(self):
        """ two or more IdP/AA with BINDING_HTTP_REDIRECT"""

        conf = config.SPConfig()
        conf.load_file("server3.config")
        client = Saml2Client(conf)

        # information about the user from an IdP
        session_info_authn = {
            "name_id": "123456",
            "issuer": "urn:mace:example.com:saml:roland:idp",
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "givenName": "Anders",
                "surName": "Andersson",
                "mail": "anders.andersson@example.com"
            }
        }
        client.users.add_information_about_person(session_info_authn)
        session_info_aa = {
            "name_id": "123456",
            "issuer": "urn:mace:example.com:saml:roland:aa",
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "eduPersonEntitlement": "Foobar",
            }
        }
        client.users.add_information_about_person(session_info_aa)
        entity_ids = client.users.issuers_of_info("123456")
        assert _leq(entity_ids, ["urn:mace:example.com:saml:roland:idp",
                                "urn:mace:example.com:saml:roland:aa"])
        resp = client.global_logout("123456", "Tired", in_a_while(minutes=5))
        print resp
        assert resp
        assert resp[0] # a session_id
        assert resp[1] == '200 OK'
        # HTTP POST
        assert resp[2] == [('Content-type', 'text/html')]
        assert resp[3][0] == '<head>'
        assert resp[3][1] == '<title>SAML 2.0 POST</title>'
        
        state_info = client.state[resp[0]]
        print state_info
        assert state_info["entity_id"] == entity_ids[0]
        assert state_info["subject_id"] == "123456"
        assert state_info["reason"] == "Tired"
        assert state_info["operation"] == "SLO"
        assert state_info["entity_ids"] == entity_ids
        assert state_info["sign"] == False
