#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2.server import Server, Identifier
from saml2 import samlp, saml, client, config
from saml2 import s_utils
from saml2 import sigver
from saml2 import time_util
from saml2.s_utils import OtherError
from saml2.s_utils import do_attribute_statement, factory
from saml2.soap import make_soap_enveloped_saml_thingy
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

from py.test import raises
import os

def _eq(l1,l2):
    return set(l1) == set(l2)

class TestIdentifier():
    def setup_class(self):
        self.ident = Identifier("foobar.db")

    def test_persistent_nameid(self):
        sp_id = "urn:mace:umu.se:sp"
        nameid = self.ident.persistent_nameid(sp_id, "abcd0001")
        remote_id = nameid.text.strip()
        print remote_id
        print self.ident.map
        local = self.ident.local_name(sp_id, remote_id)
        assert local == "abcd0001"
        assert self.ident.local_name(sp_id, "pseudo random string") is None
        assert self.ident.local_name(sp_id+":x", remote_id) is None

        # Always get the same
        nameid2 = self.ident.persistent_nameid(sp_id, "abcd0001")
        assert nameid.text.strip() == nameid2.text.strip()

    def test_transient_nameid(self):
        sp_id = "urn:mace:umu.se:sp"
        nameid = self.ident.transient_nameid(sp_id, "abcd0001")
        remote_id = nameid.text.strip()
        print remote_id
        print self.ident.map
        local = self.ident.local_name(sp_id, remote_id)
        assert local == "abcd0001"
        assert self.ident.local_name(sp_id, "pseudo random string") is None
        assert self.ident.local_name(sp_id+":x", remote_id) is None

        # Getting a new, means really getting a new !
        nameid2 = self.ident.transient_nameid(sp_id, "abcd0001")
        assert nameid.text.strip() != nameid2.text.strip()

    def teardown_class(self):
        if os.path.exists("foobar.db"):
            os.unlink("foobar.db")

class TestServer1():
    def setup_class(self):
        self.server = Server("idp_conf")

        conf = config.SPConfig()
        conf.load_file("server_conf")
        self.client = client.Saml2Client(conf)

    def test_issuer(self):
        issuer = self.server.issuer()
        assert isinstance(issuer, saml.Issuer)
        assert _eq(issuer.keyswv(), ["text","format"])
        assert issuer.format == saml.NAMEID_FORMAT_ENTITY
        assert issuer.text == self.server.conf.entityid


    def test_assertion(self):
        assertion = s_utils.assertion_factory(
            subject= factory(saml.Subject, text="_aaa",
                                name_id=factory(saml.NameID,
                                    format=saml.NAMEID_FORMAT_TRANSIENT)),
            attribute_statement = do_attribute_statement({
                                    ("","","surName"): ("Jeter",""),
                                    ("","","givenName") :("Derek",""),
                                }),
            issuer=self.server.issuer(),
            )

        assert _eq(assertion.keyswv(),['attribute_statement', 'issuer', 'id',
                                    'subject', 'issue_instant', 'version'])
        assert assertion.version == "2.0"
        assert assertion.issuer.text == "urn:mace:example.com:saml:roland:idp"
        #
        assert assertion.attribute_statement
        attribute_statement = assertion.attribute_statement
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
        assert subject.name_id.format == saml.NAMEID_FORMAT_TRANSIENT

    def test_response(self):
        response = sigver.response_factory(
                in_response_to="_012345",
                destination="https:#www.example.com",
                status=s_utils.success_status_factory(),
                assertion=s_utils.assertion_factory(
                    subject = factory( saml.Subject, text="_aaa",
                                        name_id=saml.NAMEID_FORMAT_TRANSIENT),
                    attribute_statement = do_attribute_statement({
                                            ("","","surName"): ("Jeter",""),
                                            ("","","givenName") :("Derek",""),
                                        }),
                    issuer=self.server.issuer(),
                ),
                issuer=self.server.issuer(),
            )

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
        authn_request = self.client.authn_request(
                            query_id = "id1",
                            destination = "http://www.example.com",
                            service_url = "http://www.example.org",
                            spentityid = "urn:mace:example.com:saml:roland:sp",
                            my_name = "My real name",
                        )

        intermed = s_utils.deflate_and_base64_encode("%s" % authn_request)
        # should raise an error because faulty spentityid
        raises(OtherError, self.server.parse_authn_request, intermed)

    def test_parse_faulty_request_to_err_status(self):
        authn_request = self.client.authn_request(
                            query_id = "id1",
                            destination = "http://www.example.com",
                            service_url = "http://www.example.org",
                            spentityid = "urn:mace:example.com:saml:roland:sp",
                            my_name = "My real name",
                        )

        intermed = s_utils.deflate_and_base64_encode("%s" % authn_request)
        try:
            self.server.parse_authn_request(intermed)
            status = None
        except OtherError, oe:
            print oe.args
            status = s_utils.error_status_factory(oe)

        assert status
        print status
        assert _eq(status.keyswv(), ["status_code", "status_message"])
        assert status.status_message.text == 'Not destined for me!'
        status_code = status.status_code
        assert _eq(status_code.keyswv(), ["status_code","value"])
        assert status_code.value == samlp.STATUS_RESPONDER
        assert status_code.status_code.value == samlp.STATUS_UNKNOWN_PRINCIPAL

    def test_parse_ok_request(self):
        authn_request = self.client.authn_request(
                            query_id = "id1",
                            destination = "http://localhost:8088/sso",
                            service_url = "http://localhost:8087/",
                            spentityid = "urn:mace:example.com:saml:roland:sp",
                            my_name = "My real name",
                        )

        print authn_request
        intermed = s_utils.deflate_and_base64_encode("%s" % authn_request)
        response = self.server.parse_authn_request(intermed)
        # returns a dictionary
        print response
        assert response["consumer_url"] == "http://localhost:8087/"
        assert response["id"] == "id1"
        name_id_policy = response["request"].name_id_policy
        assert _eq(name_id_policy.keyswv(), ["format", "allow_create"])
        assert name_id_policy.format == saml.NAMEID_FORMAT_TRANSIENT
        assert response["sp_entity_id"] == "urn:mace:example.com:saml:roland:sp"

    def test_sso_response_with_identity(self):
        name_id = self.server.ident.transient_nameid(
                                        "urn:mace:example.com:saml:roland:sp",
                                        "id12")
        resp = self.server.do_response(
                    "id12",                         # in_response_to
                    "http://localhost:8087/",       # consumer_url
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                    { "eduPersonEntitlement": "Short stop"}, # identity
                    name_id
                )

        print resp.keyswv()
        assert _eq(resp.keyswv(),['status', 'destination', 'assertion', 
                                    'in_response_to', 'issue_instant', 
                                    'version', 'id', 'issuer'])
        assert resp.destination == "http://localhost:8087/"
        assert resp.in_response_to == "id12"
        assert resp.status
        assert resp.status.status_code.value == samlp.STATUS_SUCCESS
        assert resp.assertion
        assert resp.assertion
        assertion = resp.assertion
        print assertion
        assert assertion.authn_statement
        assert assertion.conditions
        assert assertion.attribute_statement
        attribute_statement = assertion.attribute_statement
        print attribute_statement
        assert len(attribute_statement.attribute) == 1
        attribute = attribute_statement.attribute[0]
        assert len(attribute.attribute_value) == 1
        assert attribute.friendly_name == "eduPersonEntitlement"
        assert attribute.name == "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
        assert attribute.name_format == "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        value = attribute.attribute_value[0]
        assert value.text.strip() == "Short stop"
        assert value.get_type() == "xs:string"
        assert assertion.subject
        assert assertion.subject.name_id
        assert assertion.subject.subject_confirmation
        confirmation = assertion.subject.subject_confirmation
        print confirmation.keyswv()
        print confirmation.subject_confirmation_data
        assert confirmation.subject_confirmation_data.in_response_to == "id12"

    def test_sso_response_without_identity(self):
        resp = self.server.do_response(
                    "id12",                             # in_response_to
                    "http://localhost:8087/",           # consumer_url
                    "urn:mace:example.com:saml:roland:sp", # sp_entity_id
                )

        print resp.keyswv()
        assert _eq(resp.keyswv(),['status', 'destination', 'in_response_to', 
                                  'issue_instant', 'version', 'id', 'issuer'])
        assert resp.destination == "http://localhost:8087/"
        assert resp.in_response_to == "id12"
        assert resp.status
        assert resp.status.status_code.value == samlp.STATUS_SUCCESS
        assert resp.issuer.text == "urn:mace:example.com:saml:roland:idp"
        assert not resp.assertion 

    def test_sso_failure_response(self):
        exc = s_utils.MissingValue("eduPersonAffiliation missing")
        resp = self.server.error_response("id12", "http://localhost:8087/", 
                        "urn:mace:example.com:saml:roland:sp", exc )

        print resp.keyswv()
        assert _eq(resp.keyswv(),['status', 'destination', 'in_response_to', 
                                  'issue_instant', 'version', 'id', 'issuer'])
        assert resp.destination == "http://localhost:8087/"
        assert resp.in_response_to == "id12"
        assert resp.status
        print resp.status
        assert resp.status.status_code.value == samlp.STATUS_RESPONDER
        assert resp.status.status_code.status_code.value == \
                                        samlp.STATUS_REQUEST_UNSUPPORTED
        assert resp.status.status_message.text == \
                                        "eduPersonAffiliation missing"
        assert resp.issuer.text == "urn:mace:example.com:saml:roland:idp"
        assert not resp.assertion 

    def test_authn_response_0(self):
        self.server = Server("idp_conf")

        conf = config.SPConfig()
        conf.load_file("server_conf")
        self.client = client.Saml2Client(conf)
        ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com"]}

        resp_str = self.server.authn_response(ava, 
                    "id1", "http://local:8087/", 
                    "urn:mace:example.com:saml:roland:sp",
                    samlp.NameIDPolicy(format=saml.NAMEID_FORMAT_TRANSIENT,
                                        allow_create="true"),
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
                    'version', 'issuer', 'conditions', 'id'])
        assertion = response.assertion[0]
        assert len(assertion.attribute_statement) == 1
        astate = assertion.attribute_statement[0]
        print astate
        assert len(astate.attribute) == 3

    def test_signed_response(self):
        name_id = self.server.ident.transient_nameid(
                                        "urn:mace:example.com:saml:roland:sp",
                                        "id12")

        signed_resp = self.server.do_response(
                    "id12",                                 # in_response_to
                    "http://lingon.catalogix.se:8087/",     # consumer_url
                    "urn:mace:example.com:saml:roland:sp",  # sp_entity_id
                    {"eduPersonEntitlement":"Jeter"},
                    name_id = name_id,
                    sign=True
                )

        print "%s" % signed_resp
        assert signed_resp

        # It's the assertions that are signed not the response per se
        assert len(signed_resp.assertion) == 1
        assertion = signed_resp.assertion[0]

        # Since the reponse is created dynamically I don't know the signature
        # value. Just that there should be one
        assert assertion.signature.signature_value.text != ""

    def test_slo_http_post(self):
        soon = time_util.in_a_while(days=1)
        sinfo = {
            "name_id": "foba0001",
            "issuer": "urn:mace:example.com:saml:roland:idp",
            "not_on_or_after" : soon,
            "user": {
                "givenName": "Leo",
                "surName": "Laport",
            }
        }
        self.client.users.add_information_about_person(sinfo)

        logout_request = self.client.construct_logout_request(
                    subject_id="foba0001",
                    destination = "http://localhost:8088/slop",
                    issuer_entity_id = "urn:mace:example.com:saml:roland:idp",
                    reason = "I'm tired of this")

        intermed = s_utils.deflate_and_base64_encode("%s" % (logout_request,))

        #saml_soap = make_soap_enveloped_saml_thingy(logout_request)
        request = self.server.parse_logout_request(intermed, BINDING_HTTP_POST)
        assert request

    def test_slo_soap(self):
        soon = time_util.in_a_while(days=1)
        sinfo = {
            "name_id": "foba0001",
            "issuer": "urn:mace:example.com:saml:roland:idp",
            "not_on_or_after" : soon,
            "user": {
                "givenName": "Leo",
                "surName": "Laport",
            }
        }

        sp = client.Saml2Client(config_file="server_conf")
        sp.users.add_information_about_person(sinfo)

        logout_request = sp.construct_logout_request(subject_id = "foba0001",
                    destination = "http://localhost:8088/slo",
                    issuer_entity_id = "urn:mace:example.com:saml:roland:idp",
                    reason = "I'm tired of this")

        _ = s_utils.deflate_and_base64_encode("%s" % (logout_request,))

        saml_soap = make_soap_enveloped_saml_thingy(logout_request)
        idp = Server("idp_soap_conf")
        request = idp.parse_logout_request(saml_soap)
        assert request

#------------------------------------------------------------------------

IDENTITY = {"eduPersonAffiliation": ["staff", "member"],
            "surName": ["Jeter"], "givenName": ["Derek"],
            "mail": ["foo@gmail.com"]}

class TestServer2():
    def setup_class(self):
        self.server = Server("restrictive_idp_conf")

    def test_do_aa_reponse(self):
        aa_policy = self.server.conf.policy
        print aa_policy.__dict__
        response = self.server.do_aa_response("aaa", "http://example.com/sp/", 
                        "urn:mace:example.com:sp:1", IDENTITY.copy())

        assert response is not None
        assert response.destination == "http://example.com/sp/"
        assert response.in_response_to == "aaa"
        assert response.version == "2.0"
        assert response.issuer.text == "urn:mace:example.com:saml:roland:idpr"
        assert response.status.status_code.value == samlp.STATUS_SUCCESS
        assert response.assertion
        assertion = response.assertion
        assert assertion.version == "2.0"
        subject = assertion.subject
        #assert subject.name_id.format == saml.NAMEID_FORMAT_TRANSIENT
        assert subject.subject_confirmation
        subject_confirmation = subject.subject_confirmation
        assert subject_confirmation.subject_confirmation_data.in_response_to == "aaa"

def _logout_request(conf_file):
    conf = config.SPConfig()
    conf.load_file(conf_file)
    sp = client.Saml2Client(conf)

    soon = time_util.in_a_while(days=1)
    sinfo = {
        "name_id": "foba0001",
        "issuer": "urn:mace:example.com:saml:roland:idp",
        "not_on_or_after" : soon,
        "user": {
            "givenName": "Leo",
            "surName": "Laport",
        }
    }
    sp.users.add_information_about_person(sinfo)

    return sp.construct_logout_request(
                subject_id = "foba0001",
                destination = "http://localhost:8088/slo",
                issuer_entity_id = "urn:mace:example.com:saml:roland:idp",
                reason = "I'm tired of this")

class TestServerLogout():

    def test_1(self):
        server = Server("idp_slo_redirect_conf")
        request = _logout_request("sp_slo_redirect_conf")
        print request
        bindings = [BINDING_HTTP_REDIRECT]
        (resp, headers, message) = server.logout_response(request, bindings)
        assert resp == '302 Found'
        assert len(headers) == 1
        assert headers[0][0] == "Location"
        assert message == ['']

# class TestSign():
#     def test_1(self):
#         IDP = server.Server("restrictive_idp.config", debug=1)
#         ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
#                 "mail": ["derek@nyy.mlb.com"]}
# 
#         authn_resp = IDP.authn_response(ava, 
#                     "id1", "http://local:8087/", 
#                     "urn:mace:example.com:saml:roland:sp",
#                     samlp.NameIDPolicy(format=saml.NAMEID_FORMAT_TRANSIENT,
#                                         allow_create="true"),
#                     "foba0001@example.com", sign=True)
#         print authn_resp
#         assert False
