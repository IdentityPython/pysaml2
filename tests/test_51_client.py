#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import urllib
from saml2.samlp import logout_request_from_string

from saml2.client import Saml2Client
from saml2 import samlp, BINDING_HTTP_POST
from saml2 import saml, config, class_name
from saml2.config import SPConfig
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT, \
    AUTHN_PASSWORD
from saml2.server import Server
from saml2.time_util import in_a_while

from py.test import raises
from fakeIDP import FakeIDP, unpack_form

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
    "1.2.16":"""<?xml version='1.0' encoding='UTF-8'?>
<ns0:AttributeQuery xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion" Destination="https://idp.example.com/idp/" ID="id1" IssueInstant="%s" Version="2.0"><ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">urn:mace:example.com:saml:roland:sp</ns1:Issuer><ns1:Subject><ns1:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">E8042FB4-4D5B-48C3-8E14-8EDD852790DD</ns1:NameID></ns1:Subject></ns0:AttributeQuery>"""}

AUTHN = (AUTHN_PASSWORD, "http://www.example.com/login")

class TestClient:
    def setup_class(self):
        self.server = Server("idp_conf")

        conf = config.SPConfig()
        conf.load_file("server_conf")
        self.client = Saml2Client(conf)
    
    def test_create_attribute_query1(self):
        req = self.client.create_attribute_query(
                                "https://idp.example.com/idp/",
                                "E8042FB4-4D5B-48C3-8E14-8EDD852790DD",
                                format=saml.NAMEID_FORMAT_PERSISTENT,
                                id="id1")
        reqstr = "%s" % req.to_string()

        assert req.destination == "https://idp.example.com/idp/"
        assert req.id == "id1"
        assert req.version == "2.0"
        subject = req.subject
        name_id = subject.name_id
        assert name_id.format == saml.NAMEID_FORMAT_PERSISTENT
        assert name_id.text == "E8042FB4-4D5B-48C3-8E14-8EDD852790DD"
        issuer = req.issuer
        assert issuer.text == "urn:mace:example.com:saml:roland:sp"

        attrq = samlp.attribute_query_from_string(reqstr)

        print attrq.keyswv()
        assert _leq(attrq.keyswv(), ['destination', 'subject', 'issue_instant',
                                    'version', 'id', 'issuer'])

        assert attrq.destination == req.destination
        assert attrq.id == req.id
        assert attrq.version == req.version
        assert attrq.issuer.text == issuer.text
        assert attrq.issue_instant == req.issue_instant
        assert attrq.subject.name_id.format == name_id.format
        assert attrq.subject.name_id.text == name_id.text

    def test_create_attribute_query2(self):
        req = self.client.create_attribute_query(
            "https://idp.example.com/idp/",
            "E8042FB4-4D5B-48C3-8E14-8EDD852790DD",
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
            format=saml.NAMEID_FORMAT_PERSISTENT,
            id="id1")
                
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
        assert _leq(seen,["givenName", "surname", "email"])
        
    def test_create_attribute_query_3(self):
        req = self.client.create_attribute_query(
                "https://aai-demo-idp.switch.ch/idp/shibboleth",
                "_e7b68a04488f715cda642fbdd90099f5",
                format=saml.NAMEID_FORMAT_TRANSIENT,
                id="id1")
                
        assert isinstance(req, samlp.AttributeQuery)
        assert req.destination == "https://aai-demo-idp.switch.ch/idp/shibboleth"
        assert req.id == "id1"
        assert req.version == "2.0"
        assert req.issue_instant
        assert req.issuer.text == "urn:mace:example.com:saml:roland:sp"
        nameid = req.subject.name_id
        assert nameid.format == saml.NAMEID_FORMAT_TRANSIENT
        assert nameid.text == "_e7b68a04488f715cda642fbdd90099f5"


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
        ar_str = "%s" % self.client.create_authn_request(
                                        "http://www.example.com/sso",
                                        id="id1")
        ar = samlp.authn_request_from_string(ar_str)
        print ar
        assert ar.assertion_consumer_service_url == "http://lingon.catalogix.se:8087/"
        assert ar.destination == "http://www.example.com/sso"
        assert ar.protocol_binding == BINDING_HTTP_POST
        assert ar.version == "2.0"
        assert ar.provider_name == "urn:mace:example.com:saml:roland:sp"
        assert ar.issuer.text == "urn:mace:example.com:saml:roland:sp"
        nid_policy = ar.name_id_policy
        assert nid_policy.allow_create == "false"
        assert nid_policy.format == saml.NAMEID_FORMAT_TRANSIENT

    def test_create_auth_request_vo(self):
        assert self.client.config.vorg.keys() == [
                                    "urn:mace:example.com:it:tek"]
                                    
        ar_str = "%s" % self.client.create_authn_request(
                                        "http://www.example.com/sso",
                                        "urn:mace:example.com:it:tek", # vo
                                        nameid_format=NAMEID_FORMAT_PERSISTENT,
                                        id="666")
              
        ar = samlp.authn_request_from_string(ar_str)
        print ar
        assert ar.id == "666"
        assert ar.assertion_consumer_service_url == "http://lingon.catalogix.se:8087/"
        assert ar.destination == "http://www.example.com/sso"
        assert ar.protocol_binding == BINDING_HTTP_POST
        assert ar.version == "2.0"
        assert ar.provider_name == "urn:mace:example.com:saml:roland:sp"
        assert ar.issuer.text == "urn:mace:example.com:saml:roland:sp"
        nid_policy = ar.name_id_policy
        assert nid_policy.allow_create == "false"
        assert nid_policy.format == saml.NAMEID_FORMAT_PERSISTENT
        assert nid_policy.sp_name_qualifier == "urn:mace:example.com:it:tek"
        
    def test_sign_auth_request_0(self):
        #print self.client.config
        
        ar_str = "%s" % self.client.create_authn_request(
                                        "http://www.example.com/sso",
                                        sign=True,
                                        id="id1")

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
            assert self.client.sec.correctly_signed_authn_request(ar_str,
                    self.client.config.xmlsec_binary,
                    self.client.config.metadata)
        except Exception: # missing certificate
            self.client.sec.verify_signature(ar_str, node_name=class_name(ar))

    def test_response(self):
        IDP = "urn:mace:example.com:saml:roland:idp"
        
        ava = { "givenName": ["Derek"], "surName": ["Jeter"],
                "mail": ["derek@nyy.mlb.com"], "title":["The man"]}

        nameid_policy=samlp.NameIDPolicy(allow_create="false",
                                         format=saml.NAMEID_FORMAT_PERSISTENT)

        resp = self.server.create_authn_response(identity=ava,
                                in_response_to="id1",
                                destination="http://lingon.catalogix.se:8087/",
                                sp_entity_id="urn:mace:example.com:saml:roland:sp",
                                name_id_policy=nameid_policy,
                                userid="foba0001@example.com",
                                authn=AUTHN)

        resp_str = "%s" % resp

        resp_str = base64.encodestring(resp_str)
        
        authn_response = self.client.parse_authn_request_response(
                                    resp_str, BINDING_HTTP_POST,
                                    {"id1":"http://foo.example.com/service"})
                            
        assert authn_response is not None
        assert authn_response.issuer() == IDP
        assert authn_response.response.assertion[0].issuer.text == IDP
        session_info = authn_response.session_info()

        print session_info
        assert session_info["ava"] == {'mail': ['derek@nyy.mlb.com'],
                                       'givenName': ['Derek'],
                                       'sn': ['Jeter'],
                                       'title': ["The man"]}
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
        
        ava = { "givenName": ["Alfonson"], "surName": ["Soriano"],
                "mail": ["alfonson@chc.mlb.com"], "title": ["outfielder"]}

        resp_str = "%s" % self.server.create_authn_response(
                                identity=ava,
                                in_response_to="id2",
                                destination="http://lingon.catalogix.se:8087/",
                                sp_entity_id="urn:mace:example.com:saml:roland:sp",
                                name_id_policy=nameid_policy,
                                userid="also0001@example.com",
                                authn=AUTHN)

        resp_str = base64.encodestring(resp_str)
        
        self.client.parse_authn_request_response(resp_str, BINDING_HTTP_POST,
                            {"id2":"http://foo.example.com/service"})
        
        # Two persons in the cache
        assert len(self.client.users.subjects()) == 2
        issuers = [self.client.users.issuers_of_info(s) for s in self.client.users.subjects()]
        # The information I have about the subjects comes from the same source
        print issuers
        assert issuers == [[IDP], [IDP]]
        
    def test_init_values(self):
        entityid = self.client.config.entityid
        print entityid
        assert entityid == "urn:mace:example.com:saml:roland:sp"
        print self.client.metadata.with_descriptor("idpsso")
        location = self.client._sso_location()
        print location
        assert location == 'http://localhost:8088/sso'
        service_url = self.client.service_url()
        print service_url
        assert service_url == "http://lingon.catalogix.se:8087/"
        my_name = self.client._my_name()
        print my_name
        assert my_name == "urn:mace:example.com:saml:roland:sp"

# Below can only be done with dummy Server

IDP = "urn:mace:example.com:saml:roland:idp"
class TestClientWithDummy():
    def setup_class(self):
        self.server = FakeIDP("idp_all_conf")

        conf = SPConfig()
        conf.load_file("servera_conf")
        self.client = Saml2Client(conf)

        self.client.send = self.server.receive

    def test_do_authn(self):
        id, http_args = self.client.prepare_for_authenticate(IDP,
                                          "http://www.example.com/relay_state")

        assert isinstance(id, basestring)
        assert len(http_args) == 4
        assert http_args["headers"][0][0] == "Location"
        assert http_args["data"] == []

    def test_do_attribute_query(self):
        response = self.client.do_attribute_query(IDP,
                                     "_e7b68a04488f715cda642fbdd90099f5",
                                     attribute={"eduPersonAffiliation":None},
                                     nameid_format=NAMEID_FORMAT_TRANSIENT)


    def test_logout_1(self):
        """ one IdP/AA logout from"""

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
        assert len(resp) == 1
        assert resp.keys() == entity_ids
        http_args = resp[entity_ids[0]]
        assert isinstance(http_args, dict)
        assert http_args["headers"] == [('Content-type', 'text/html')]
        info = unpack_form(http_args["data"][3])
        xml_str = base64.b64decode(info["SAMLRequest"])
        req = logout_request_from_string(xml_str)
        print req
        assert req.reason == "Tired"

    def test_post_sso(self):
        id, http_args = self.client.prepare_for_authenticate(
                                    "urn:mace:example.com:saml:roland:idp",
                                    relay_state="really",
                                    binding=BINDING_HTTP_POST)

        # Normally a response would now be sent back to the users web client
        # Here I fake what the client will do
        # create the form post

        _dic = unpack_form(http_args["data"][3])
        http_args["data"] = urllib.urlencode(_dic)
        http_args["method"] = "POST"
        http_args["dummy"] = _dic["SAMLRequest"]
        http_args["headers"] = [('Content-type','application/x-www-form-urlencoded')]

        response = self.client.send(**http_args)
        print response.text
        _dic = unpack_form(response.text[3], "SAMLResponse")
        resp = self.client.parse_authn_request_response(_dic["SAMLResponse"],
                                                        BINDING_HTTP_POST,
                                                        {id: "/"})
        ac = resp.assertion.authn_statement[0].authn_context
        assert ac.authenticating_authority[0].text == 'http://www.example.com/login'
        assert ac.authn_context_class_ref.text == AUTHN_PASSWORD

#    def test_logout_2(self):
#        """ one IdP/AA with BINDING_SOAP, can't actually send something"""
#
#        conf = config.SPConfig()
#        conf.load_file("server2_conf")
#        client = Saml2Client(conf)
#
#        # information about the user from an IdP
#        session_info = {
#            "name_id": "123456",
#            "issuer": "urn:mace:example.com:saml:roland:idp",
#            "not_on_or_after": in_a_while(minutes=15),
#            "ava": {
#                "givenName": "Anders",
#                "surName": "Andersson",
#                "mail": "anders.andersson@example.com"
#            }
#        }
#        client.users.add_information_about_person(session_info)
#        entity_ids = self.client.users.issuers_of_info("123456")
#        assert entity_ids == ["urn:mace:example.com:saml:roland:idp"]
#        destinations = client.config.single_logout_services(entity_ids[0],
#                                                            BINDING_SOAP)
#        print destinations
#        assert destinations == ['http://localhost:8088/slo']
#
#        # Will raise an error since there is noone at the other end.
#        raises(LogoutError, 'client.global_logout("123456", "Tired", in_a_while(minutes=5))')
#
#    def test_logout_3(self):
#        """ two or more IdP/AA with BINDING_HTTP_REDIRECT"""
#
#        conf = config.SPConfig()
#        conf.load_file("server3_conf")
#        client = Saml2Client(conf)
#
#        # information about the user from an IdP
#        session_info_authn = {
#            "name_id": "123456",
#            "issuer": "urn:mace:example.com:saml:roland:idp",
#            "not_on_or_after": in_a_while(minutes=15),
#            "ava": {
#                "givenName": "Anders",
#                "surName": "Andersson",
#                "mail": "anders.andersson@example.com"
#            }
#        }
#        client.users.add_information_about_person(session_info_authn)
#        session_info_aa = {
#            "name_id": "123456",
#            "issuer": "urn:mace:example.com:saml:roland:aa",
#            "not_on_or_after": in_a_while(minutes=15),
#            "ava": {
#                "eduPersonEntitlement": "Foobar",
#            }
#        }
#        client.users.add_information_about_person(session_info_aa)
#        entity_ids = client.users.issuers_of_info("123456")
#        assert _leq(entity_ids, ["urn:mace:example.com:saml:roland:idp",
#                                "urn:mace:example.com:saml:roland:aa"])
#        resp = client.global_logout("123456", "Tired", in_a_while(minutes=5))
#        print resp
#        assert resp
#        assert resp[0] # a session_id
#        assert resp[1] == '200 OK'
#        # HTTP POST
#        assert resp[2] == [('Content-type', 'text/html')]
#        assert resp[3][0] == '<head>'
#        assert resp[3][1] == '<title>SAML 2.0 POST</title>'
#
#        state_info = client.state[resp[0]]
#        print state_info
#        assert state_info["entity_id"] == entity_ids[0]
#        assert state_info["subject_id"] == "123456"
#        assert state_info["reason"] == "Tired"
#        assert state_info["operation"] == "SLO"
#        assert state_info["entity_ids"] == entity_ids
#        assert state_info["sign"] == True
#
#    def test_authz_decision_query(self):
#        conf = config.SPConfig()
#        conf.load_file("server3_conf")
#        client = Saml2Client(conf)
#
#        AVA = {'mail': u'roland.hedberg@adm.umu.se',
#               'eduPersonTargetedID': '95e9ae91dbe62d35198fbbd5e1fb0976',
#               'displayName': u'Roland Hedberg',
#               'uid': 'http://roland.hedberg.myopenid.com/'}
#
#        sp_entity_id = "sp_entity_id"
#        in_response_to = "1234"
#        consumer_url = "http://example.com/consumer"
#        name_id = saml.NameID(saml.NAMEID_FORMAT_TRANSIENT, text="name_id")
#        policy = Policy()
#        ava = Assertion(AVA)
#        assertion = ava.construct(sp_entity_id, in_response_to,
#                                    consumer_url, name_id,
#                                    conf.attribute_converters,
#                                    policy, issuer=client._issuer())
#
#        adq = client.create_authz_decision_query_using_assertion("entity_id",
#                                                         assertion,
#                                                        "read",
#                                                        "http://example.com/text")
#
#        assert adq
#        print adq
#        assert adq.keyswv() != []
#        assert adq.destination == "entity_id"
#        assert adq.resource == "http://example.com/text"
#        assert adq.action[0].text == "read"
#
#    def test_request_to_discovery_service(self):
#        disc_url = "http://example.com/saml2/idp/disc"
#        url = discovery_service_request_url("urn:mace:example.com:saml:roland:sp",
#                                            disc_url)
#        print url
#        assert url == "http://example.com/saml2/idp/disc?entityID=urn%3Amace%3Aexample.com%3Asaml%3Aroland%3Asp"
#
#        url = discovery_service_request_url(
#                            self.client.config.entityid,
#                            disc_url,
#                            return_url= "http://example.org/saml2/sp/ds")
#
#        print url
#        assert url == "http://example.com/saml2/idp/disc?entityID=urn%3Amace%3Aexample.com%3Asaml%3Aroland%3Asp&return=http%3A%2F%2Fexample.org%2Fsaml2%2Fsp%2Fds"
#
#    def test_get_idp_from_discovery_service(self):
#        pdir = {"entityID": "http://example.org/saml2/idp/sso"}
#        params = urllib.urlencode(pdir)
#        redirect_url = "http://example.com/saml2/sp/disc?%s" % params
#
#        entity_id = discovery_service_response(url=redirect_url)
#        assert entity_id == "http://example.org/saml2/idp/sso"
#
#        pdir = {"idpID": "http://example.org/saml2/idp/sso"}
#        params = urllib.urlencode(pdir)
#        redirect_url = "http://example.com/saml2/sp/disc?%s" % params
#
#        entity_id = discovery_service_response(url=redirect_url,
#                                               returnIDParam="idpID")
#
#        assert entity_id == "http://example.org/saml2/idp/sso"
#        self.server.close_shelve_db()
#
#    def test_unsolicited_response(self):
#        """
#
#        """
#        self.server = Server("idp_conf")
#
#        conf = config.SPConfig()
#        conf.load_file("server_conf")
#        self.client = Saml2Client(conf)
#
#        for subject in self.client.users.subjects():
#            self.client.users.remove_person(subject)
#
#        IDP = "urn:mace:example.com:saml:roland:idp"
#
#        ava = { "givenName": ["Derek"], "surName": ["Jeter"],
#                "mail": ["derek@nyy.mlb.com"], "title": ["The man"]}
#
#        resp_str = "%s" % self.server.create_authn_response(
#                                identity=ava,
#                                in_response_to="id1",
#                                destination="http://lingon.catalogix.se:8087/",
#                                sp_entity_id="urn:mace:example.com:saml:roland:sp",
#                                name_id_policy=samlp.NameIDPolicy(
#                                        format=saml.NAMEID_FORMAT_PERSISTENT),
#                                userid="foba0001@example.com")
#
#        resp_str = base64.encodestring(resp_str)
#
#        self.client.allow_unsolicited = True
#        authn_response = self.client.authn_request_response(
#                                                {"SAMLResponse":resp_str}, ())
#
#        assert authn_response is not None
#        assert authn_response.issuer() == IDP
#        assert authn_response.response.assertion[0].issuer.text == IDP
#        session_info = authn_response.session_info()
#
#        print session_info
#        assert session_info["ava"] == {'mail': ['derek@nyy.mlb.com'],
#                                       'givenName': ['Derek'],
#                                       'surName': ['Jeter']}
#        assert session_info["issuer"] == IDP
#        assert session_info["came_from"] == ""
#        response = samlp.response_from_string(authn_response.xmlstr)
#        assert response.destination == "http://lingon.catalogix.se:8087/"
#
#        # One person in the cache
#        assert len(self.client.users.subjects()) ==  1
#        self.server.close_shelve_db()