#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2.server import Server
from saml2 import server
from saml2 import samlp, saml, client, utils
from saml2.utils import make_instance, OtherError
from saml2.utils import do_attribute_statement
from py.test import raises
import shelve
import re

def _eq(l1,l2):
    return set(l1) == set(l2)


class TestServer1():
    def setup_class(self):
        try:
            self.server = Server("idp.config")
        except IOError, e:
            self.server = Server("tests/idp.config")
        
    def test_issuer(self):
        issuer = make_instance( saml.Issuer, self.server.issuer())
        assert isinstance(issuer, saml.Issuer)
        assert _eq(issuer.keyswv(), ["text","format"])
        assert issuer.format == saml.NAMEID_FORMAT_ENTITY
        assert issuer.text == self.server.conf["entityid"]
        

    def test_assertion(self):
        tmp = utils.assertion_factory(
            subject= utils.subject_factory("_aaa",
                                name_id=saml.NAMEID_FORMAT_TRANSIENT),
            attribute_statement = utils.attribute_statement_factory(
                attribute=[
                    utils.attribute_factory(attribute_value="Derek", 
                                        friendly_name="givenName"),
                    utils.attribute_factory(attribute_value="Jeter", 
                                        friendly_name="surName"),
                ]),
            issuer=self.server.issuer(),
            )
            
        assertion = make_instance(saml.Assertion, tmp)
        assert _eq(assertion.keyswv(),['attribute_statement', 'issuer', 'id',
                                    'subject', 'issue_instant', 'version'])
        assert assertion.version == "2.0"
        assert assertion.issuer.text == "urn:mace:example.com:saml:roland:idp"
        #
        assert len(assertion.attribute_statement) == 1
        attribute_statement = assertion.attribute_statement[0]
        assert len(attribute_statement.attribute) == 2
        attr0 = attribute_statement.attribute[0]
        attr1 = attribute_statement.attribute[1]
        if attr0.attribute_value[0].text == "Derek":
            assert attr0.friendly_name == "givenName"
            assert attr1.friendly_name == "surName"
            assert attr1.attribute_value[0].text == "Jeter"
        else:
            assert attr1.friendly_name == "givenName"
            assert attr1.attribute_value[0].text == "Derek"
            assert attr0.friendly_name == "surName"
            assert attr0.attribute_value[0].text == "Jeter"
        # 
        subject = assertion.subject
        assert _eq(subject.keyswv(),["text", "name_id"])
        assert subject.text == "_aaa"
        assert subject.name_id.text == saml.NAMEID_FORMAT_TRANSIENT
        
    def test_response(self):
        tmp = utils.response_factory(
                in_response_to="_012345",
                destination="https:#www.example.com",
                status=utils.success_status_factory(),
                assertion=utils.assertion_factory(
                    subject = utils.subject_factory("_aaa",
                                        name_id=saml.NAMEID_FORMAT_TRANSIENT),
                    attribute_statement = utils.attribute_statement_factory([
                        utils.attribute_factory(attribute_value="Derek", 
                                                friendly_name="givenName"),
                        utils.attribute_factory(attribute_value="Jeter", 
                                                friendly_name="surName"),
                    ]),
                    issuer=self.server.issuer(),
                ),
                issuer=self.server.issuer(),
            )
            
        response = make_instance(samlp.Response, tmp)
        print response.keyswv()
        assert _eq(response.keyswv(),['destination', 'assertion','status', 
                                    'in_response_to', 'issue_instant', 
                                    'version', 'issuer', 'id'])
        assert response.version == "2.0"
        assert response.issuer.text == "urn:mace:example.com:saml:roland:idp"
        assert response.destination == "https:#www.example.com"
        assert response.in_response_to == "_012345"
        #
        status = response.status
        print status
        assert status.status_code.value == samlp.STATUS_SUCCESS

    def test_parse_faulty_request(self):
        sc = client.Saml2Client({},None)
        authn_request = sc.authn_request(
                            query_id = "1",
                            destination = "http://www.example.com",
                            service_url = "http://www.example.org",
                            spentityid = "urn:mace:example.com:saml:roland:sp",
                            my_name = "My real name",
                        )
                        
        intermed = utils.deflate_and_base64_encode(authn_request)
        # should raise an error because faulty spentityid
        raises(OtherError,self.server.parse_authn_request,intermed)
        
    def test_parse_faulty_request_to_err_status(self):
        sc = client.Saml2Client({},None)
        authn_request = sc.authn_request(
                            query_id = "1",
                            destination = "http://www.example.com",
                            service_url = "http://www.example.org",
                            spentityid = "urn:mace:example.com:saml:roland:sp",
                            my_name = "My real name",
                        )
                        
        intermed = utils.deflate_and_base64_encode(authn_request)
        try:
            self.server.parse_authn_request(intermed)
            status = None
        except OtherError, oe:
            print oe.args
            status = utils.make_instance(samlp.Status,
                            utils.status_from_exception_factory(oe))
            
        assert status
        print status
        assert _eq(status.keyswv(), ["status_code", "status_message"])
        assert status.status_message.text == (
                        'ConsumerURL and return destination mismatch')
        status_code = status.status_code
        assert _eq(status_code.keyswv(), ["status_code","value"])
        assert status_code.value == samlp.STATUS_RESPONDER
        assert status_code.status_code.value == samlp.STATUS_UNKNOWN_PRINCIPAL

    def test_parse_ok_request(self):
        sc = client.Saml2Client({},None)
        authn_request = sc.authn_request(
                            query_id = "1",
                            destination = "http://www.example.com",
                            service_url = "http://localhost:8087/",
                            spentityid = "urn:mace:example.com:saml:roland:sp",
                            my_name = "My real name",
                        )
                        
        print authn_request
        intermed = utils.deflate_and_base64_encode(authn_request)
        response = self.server.parse_authn_request(intermed)
                                                        
        assert response["consumer_url"] == "http://localhost:8087/"
        assert response["id"] == "1"
        name_id_policy = response["request"].name_id_policy
        assert _eq(name_id_policy.keyswv(), ["format", "allow_create"])
        assert name_id_policy.format == saml.NAMEID_FORMAT_TRANSIENT
        assert response["sp_entityid"] == "urn:mace:example.com:saml:roland:sp"

    def test_sso_response_with_identity(self):
        resp = self.server.do_response(
                    "http://localhost:8087/",   # consumer_url
                    "12",                       # in_response_to
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                    { "eduPersonEntitlement": "Bat"}
                )
                
        print resp.keyswv()
        assert _eq(resp.keyswv(),['status', 'destination', 'assertion', 
                                    'in_response_to', 'issue_instant', 
                                    'version', 'id', 'issuer'])
        assert resp.destination == "http://localhost:8087/"
        assert resp.in_response_to == "12"
        assert resp.status
        assert resp.status.status_code.value == samlp.STATUS_SUCCESS
        assert resp.assertion
        assert len(resp.assertion) == 1
        assertion = resp.assertion[0]
        assert len(assertion.authn_statement) == 1
        assert assertion.conditions
        assert len(assertion.attribute_statement) == 1
        assert assertion.subject
        assert assertion.subject.name_id
        assert len(assertion.subject.subject_confirmation) == 1
        confirmation = assertion.subject.subject_confirmation[0]
        print confirmation.keyswv()
        print confirmation.subject_confirmation_data
        assert confirmation.subject_confirmation_data.in_response_to == "12"

    def test_sso_response_without_identity(self):
        resp = self.server.do_response(
                    "http://localhost:8087/",   # consumer_url
                    "12",                       # in_response_to
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                )
                
        print resp.keyswv()
        assert _eq(resp.keyswv(),['status', 'destination', 'in_response_to', 
                                  'issue_instant', 'version', 'id', 'issuer'])
        assert resp.destination == "http://localhost:8087/"
        assert resp.in_response_to == "12"
        assert resp.status
        assert resp.status.status_code.value == samlp.STATUS_SUCCESS
        assert resp.issuer.text == "urn:mace:example.com:saml:roland:idp"
        assert not resp.assertion 

    def test_sso_failure_response(self):
        exc = utils.MissingValue("eduPersonAffiliation missing")
        resp = self.server.error_response( "http://localhost:8087/", "12", 
                        "urn:mace:example.com:saml:roland:sp", exc )
                
        print resp.keyswv()
        assert _eq(resp.keyswv(),['status', 'destination', 'in_response_to', 
                                  'issue_instant', 'version', 'id', 'issuer'])
        assert resp.destination == "http://localhost:8087/"
        assert resp.in_response_to == "12"
        assert resp.status
        print resp.status
        assert resp.status.status_code.value == samlp.STATUS_RESPONDER
        assert resp.status.status_code.status_code.value == \
                                        samlp.STATUS_REQUEST_UNSUPPORTED
        assert resp.status.status_message.text == \
                                        "eduPersonAffiliation missing"
        assert resp.issuer.text == "urn:mace:example.com:saml:roland:idp"
        assert not resp.assertion 

    def test_persistence_0(self):
        pid1 = self.server.persistent_id(
                    "urn:mace:example.com:saml:roland:sp", "jeter")

        pid2 = self.server.persistent_id(
                    "urn:mace:example.com:saml:roland:sp", "jeter")

        print pid1, pid2
        assert pid1 == pid2

    def test_filter_ava_0(self):
        ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com"]}
        
        # No restrictions apply
        ava = self.server.filter_ava(ava, 
                                    "urn:mace:example.com:saml:roland:sp",
                                    [], [])
                                    
        assert _eq(ava.keys(), ["givenName", "surName", "mail"])
        assert ava["givenName"] == ["Derek"]
        assert ava["surName"] == ["Jeter"]
        assert ava["mail"] == ["derek@nyy.mlb.com"]
        
        
    def test_filter_ava_1(self):
        """ No mail address returned """
        self.server.conf["service"]["idp"]["assertions"][
                            "urn:mace:example.com:saml:roland:sp"] = {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions":{
                        "givenName": None,
                        "surName": None,
                    }
                }

        print self.server.conf["service"]["idp"]["assertions"]
        
        ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com"]}
        
        # No restrictions apply
        ava = self.server.filter_ava(ava, 
                                    "urn:mace:example.com:saml:roland:sp",
                                    [], [])
                                    
        assert _eq(ava.keys(), ["givenName", "surName"])
        assert ava["givenName"] == ["Derek"]
        assert ava["surName"] == ["Jeter"]

    def test_filter_ava_2(self):
        """ Only mail returned """
        self.server.conf["service"]["idp"]["assertions"][
                            "urn:mace:example.com:saml:roland:sp"] = {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions":{
                        "mail": None,
                    }
                }

        print self.server.conf["service"]["idp"]["assertions"]
        
        ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com"]}
        
        # No restrictions apply
        ava = self.server.filter_ava(ava, 
                                    "urn:mace:example.com:saml:roland:sp",
                                    [], [])
                                    
        assert _eq(ava.keys(), ["mail"])
        assert ava["mail"] == ["derek@nyy.mlb.com"]

    def test_filter_ava_3(self):
        """ Only example.com mail addresses returned """
        self.server.conf["service"]["idp"]["assertions"][
                            "urn:mace:example.com:saml:roland:sp"] = {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions":{
                        "mail": [re.compile(".*@example\.com$")],
                    }
                }

        print self.server.conf["service"]["idp"]["assertions"]
        
        ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com", "dj@example.com"]}
        
        # No restrictions apply
        ava = self.server.filter_ava(ava, 
                                    "urn:mace:example.com:saml:roland:sp",
                                    [], [])
                                    
        assert _eq(ava.keys(), ["mail"])
        assert ava["mail"] == ["dj@example.com"]

    def test_authn_response_0(self):
        # reset 
        del self.server.conf["service"]["idp"]["assertions"][
                            "urn:mace:example.com:saml:roland:sp"]

        ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com"]}

        resp_str = self.server.authn_response(ava, 
                    "1", "http://local:8087/", 
                    "urn:mace:example.com:saml:roland:sp",
                    utils.make_instance(samlp.NameIDPolicy,
                                utils.name_id_policy_factory(
                                        format=saml.NAMEID_FORMAT_TRANSIENT,
                                        allow_create="true")),
                    "foba0001@example.com")
                   
        response = samlp.response_from_string("\n".join(resp_str))
        print response.keyswv()
        assert _eq(response.keyswv(),['status', 'destination', 'assertion', 
                        'in_response_to', 'issue_instant', 'version', 
                        'issuer', 'id'])
        print response.assertion[0].keyswv()
        assert len(response.assertion) == 1
        assert _eq(response.assertion[0].keyswv(), ['authn_statement', 
                        'attribute_statement', 'subject', 'issue_instant', 
                        'version', 'conditions', 'id'])
        assertion = response.assertion[0]
        assert len(assertion.attribute_statement) == 1
        astate = assertion.attribute_statement[0]
        print astate
        assert len(astate.attribute) == 3
        

IDENTITY = {"eduPersonAffiliation": ["staff", "member"],
            "surName": ["Jeter"], "givenName": ["Derek"],
            "mail": ["foo@gmail.com"]}

class TestServer2():
    def setup_class(self):
        try:
            self.server = Server("restrictive_idp.config")
        except IOError, e:
            self.server = Server("tests/restrictive_idp.config")
            
    
    def test_0(self):
                
        ident = self.server.restrict_ava(IDENTITY.copy(), 
                                        "urn:mace:example.com:saml:roland:sp")
        assert len(ident) == 3
        assert ident == {'eduPersonAffiliation': ['staff'], 
                        'givenName': ['Derek'], 'surName': ['Jeter']}
                        
        print self.server.conf.keys()
        attr = utils.ava_to_attributes(ident, self.server.conf["am_backward"])
        assert len(attr) == 3
        assert {'attribute_value': [{'text': 'staff'}], 
                'friendly_name': 'eduPersonAffiliation', 
                'name': 'urn:oid:1.3.6.1.4.1.5923.1.1.1.1', 
                'name_format': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'} in attr

    def test_do_aa_reponse(self):
        response = self.server.do_aa_response( "http://example.com/sp/", "aaa",
                        "urn:mace:example.com:sp:1", IDENTITY.copy(), 
                        issuer = self.server.conf["entityid"])

        assert response != None
        assert response.destination == "http://example.com/sp/"
        assert response.in_response_to == "aaa"
        assert response.version == "2.0"
        assert response.issuer.text == "urn:mace:example.com:saml:roland:idpr"
        assert response.status.status_code.value == samlp.STATUS_SUCCESS
        assert len(response.assertion) == 1
        assertion = response.assertion[0]
        assert assertion.version == "2.0"
        subject = assertion.subject
        assert subject.name_id.format == saml.NAMEID_FORMAT_TRANSIENT
        assert len(subject.subject_confirmation) == 1
        subject_confirmation = subject.subject_confirmation[0]
        assert subject_confirmation.subject_confirmation_data.in_response_to == "aaa"
        
