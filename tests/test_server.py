#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2.server import Server, OtherError, UnknownPricipal
from saml2 import samlp, saml, client, utils
from saml2.utils import make_instance
from py.test import raises

SUCCESS_STATUS = """<?xml version=\'1.0\' encoding=\'UTF-8\'?>
<ns0:Status xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></ns0:Status>"""

ERROR_STATUS = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:Status xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal" /></ns0:StatusCode><ns0:StatusMessage>Error resolving principal</ns0:StatusMessage></ns0:Status>"""

def _eq(l1,l2):
    return set(l1) == set(l2)

class TestServer():
    def setup_class(self):
        self.server = Server("tests/server.config")

    def test_status_success(self):
        stat = self.server.status(
                status_code=self.server.status_code(
                                value=samlp.STATUS_SUCCESS))
        status = make_instance( samlp.Status, stat)
        status_text = "%s" % status
        assert status_text == SUCCESS_STATUS
        assert status.status_code.value == samlp.STATUS_SUCCESS
        
    def test_success_status(self):
        stat = self.server.success_status()
        status = make_instance(samlp.Status, stat)
        status_text = "%s" % status
        assert status_text == SUCCESS_STATUS
        assert status.status_code.value == samlp.STATUS_SUCCESS
    
    def test_error_status(self):
        stat = self.server.status(
            status_message=self.server.status_message(
                                    "Error resolving principal"),
            status_code=self.server.status_code(
                            value=samlp.STATUS_RESPONDER,
                            status_code=self.server.status_code(
                                value=samlp.STATUS_UNKNOWN_PRINCIPAL)))
            
        status_text = "%s" % make_instance( samlp.Status, stat )
        print status_text
        assert status_text == ERROR_STATUS

    def test_status_from_exception(self):
        e = UnknownPricipal("Error resolving principal")
        stat = self.server.status_from_exception(e)
        status_text = "%s" % make_instance( samlp.Status, stat )
        
        assert status_text == ERROR_STATUS
        
    def test_attribute_statement(self):
        astat = self.server.do_attribute_statement({"surName":"Jeter",
                                            "givenName":"Derek"})
        statement = make_instance(saml.AttributeStatement,astat)
        assert statement.keyswv() == ["attribute"]
        assert len(statement.attribute) == 2
        attr0 = statement.attribute[0]
        assert _eq(attr0.keyswv(), ["name","attribute_value"])
        assert len(attr0.attribute_value) == 1
        attr1 = statement.attribute[1]
        assert _eq(attr1.keyswv(), ["name","attribute_value"])
        assert len(attr1.attribute_value) == 1
        if attr0.name == "givenName":
            assert attr0.attribute_value[0].text == "Derek"
            assert attr1.name == "surName"
            assert attr1.attribute_value[0].text == "Jeter"
        else:
            assert attr0.name == "surName"
            assert attr0.attribute_value[0].text == "Jeter"
            assert attr1.name == "givenName"
            assert attr1.attribute_value[0].text == "Derek"
        
    def test_issuer(self):
        issuer = make_instance( saml.Issuer, self.server.issuer())
        assert isinstance(issuer, saml.Issuer)
        assert _eq(issuer.keyswv(), ["text","format"])
        assert issuer.format == saml.NAMEID_FORMAT_ENTITY
        assert issuer.text == self.server.conf["entityid"]
        
    def test_audience(self):
        aud_restr = make_instance( saml.AudienceRestriction, 
                self.server.audience_restriction(
                        audience=self.server.audience("urn:foo:bar")))
                
        assert aud_restr.keyswv() == ["audience"]
        assert aud_restr.audience.text == "urn:foo:bar"
        
    def test_conditions(self):
        conds_dict = self.server.conditions(
                        not_before="2009-10-30T07:58:10.852Z",
                        not_on_or_after="2009-10-30T08:03:10.852Z", 
                        audience_restriction=self.server.audience_restriction(
                            audience=self.server.audience("urn:foo:bar")))
                        
        conditions = make_instance(saml.Conditions, conds_dict)
        assert _eq(conditions.keyswv(), ["not_before", "not_on_or_after",
                                    "audience_restriction"])
        assert conditions.not_before == "2009-10-30T07:58:10.852Z" 
        assert conditions.not_on_or_after == "2009-10-30T08:03:10.852Z"
        assert conditions.audience_restriction[0].audience.text == "urn:foo:bar"
        
    def test_value_1(self):
        #FriendlyName="givenName" Name="urn:oid:2.5.4.42" 
        # NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        adict = self.server.attribute(name="urn:oid:2.5.4.42",
                                        name_format=saml.NAME_FORMAT_URI)
        attribute = make_instance(saml.Attribute, adict)
        assert _eq(attribute.keyswv(),["name","name_format"])
        assert attribute.name == "urn:oid:2.5.4.42"
        assert attribute.name_format == saml.NAME_FORMAT_URI

    def test_value_2(self):
        adict = self.server.attribute(name="urn:oid:2.5.4.42",
                                        name_format=saml.NAME_FORMAT_URI,
                                        friendly_name="givenName")
        attribute = make_instance(saml.Attribute, adict)
        assert _eq(attribute.keyswv(),["name","name_format","friendly_name"])
        assert attribute.name == "urn:oid:2.5.4.42"
        assert attribute.name_format == saml.NAME_FORMAT_URI
        assert attribute.friendly_name == "givenName"

    def test_value_3(self):
        adict = self.server.attribute(attribute_value="Derek",
                                        name="urn:oid:2.5.4.42",
                                        name_format=saml.NAME_FORMAT_URI,
                                        friendly_name="givenName")
        attribute = make_instance(saml.Attribute, adict)
        assert _eq(attribute.keyswv(),["name", "name_format",
                                        "friendly_name", "attribute_value"])
        assert attribute.name == "urn:oid:2.5.4.42"
        assert attribute.name_format == saml.NAME_FORMAT_URI
        assert attribute.friendly_name == "givenName"
        assert len(attribute.attribute_value) == 1
        assert attribute.attribute_value[0].text == "Derek"

    def test_value_4(self):
        adict = self.server.attribute(attribute_value="Derek",
                                        friendly_name="givenName")
        attribute = make_instance(saml.Attribute, adict)
        assert _eq(attribute.keyswv(),["friendly_name", "attribute_value"])
        assert attribute.friendly_name == "givenName"
        assert len(attribute.attribute_value) == 1
        assert attribute.attribute_value[0].text == "Derek"

    def test_do_attribute_statement(self):
        astat = self.server.do_attribute_statement({"surName":"Jeter",
                                            "givenName":["Derek","Sanderson"]})
        statement = make_instance(saml.AttributeStatement,astat)
        assert statement.keyswv() == ["attribute"]
        assert len(statement.attribute) == 2
        attr0 = statement.attribute[0]
        assert _eq(attr0.keyswv(), ["name","attribute_value"])
        attr1 = statement.attribute[1]
        assert _eq(attr1.keyswv(), ["name","attribute_value"])
        if attr0.name == "givenName":
            assert len(attr0.attribute_value) == 2
            assert _eq([av.text for av in attr0.attribute_value],
                        ["Derek","Sanderson"])
            assert attr1.name == "surName"
            assert attr1.attribute_value[0].text == "Jeter"
            assert len(attr1.attribute_value) == 1
        else:
            assert attr0.name == "surName"
            assert attr0.attribute_value[0].text == "Jeter"
            assert len(attr0.attribute_value) == 1
            assert attr1.name == "givenName"
            assert len(attr1.attribute_value) == 2
            assert _eq([av.text for av in attr1.attribute_value],
                        ["Derek","Sanderson"])
        
    def test_do_attribute_statement_multi(self):
        astat = self.server.do_attribute_statement(
                    {("urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
                        "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                        "eduPersonEntitlement"):"Jeter"})
        statement = make_instance(saml.AttributeStatement,astat)
        assert statement.keyswv() == ["attribute"]
        assert len(statement.attribute)
        assert _eq(statement.attribute[0].keyswv(),
                    ["name","name_format","friendly_name","attribute_value"])
        attribute = statement.attribute[0]
        assert attribute.name == "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
        assert attribute.name_format == (
                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
        assert attribute.friendly_name == "eduPersonEntitlement"

    def test_subject(self):
        adict = self.server.subject("_aaa",
                                        name_id=saml.NAMEID_FORMAT_TRANSIENT)
        subject = make_instance(saml.Subject, adict)
        assert _eq(subject.keyswv(),["text", "name_id"])
        assert subject.text == "_aaa"
        assert subject.name_id.text == saml.NAMEID_FORMAT_TRANSIENT
        
    def test_assertion(self):
        tmp = self.server.assertion(
            subject= self.server.subject("_aaa",
                                name_id=saml.NAMEID_FORMAT_TRANSIENT),
            attribute_statement = self.server.attribute_statement(
                attribute=[
                    self.server.attribute(attribute_value="Derek", 
                                        friendly_name="givenName"),
                    self.server.attribute(attribute_value="Jeter", 
                                        friendly_name="surName"),
                ]),
            issuer=self.server.issuer(),
            )
            
        assertion = make_instance(saml.Assertion, tmp)
        assert _eq(assertion.keyswv(),['attribute_statement', 'issuer', 'id',
                                    'subject', 'issue_instant', 'version'])
        assert assertion.version == "2.0"
        assert assertion.issuer.text == "urn:mace:umu.se:saml:roland:sp"
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
        tmp = self.server.response(
                in_response_to="_012345",
                destination="https:#www.example.com",
                status=self.server.success_status(),
                assertion=self.server.assertion(
                    subject = self.server.subject("_aaa",
                                        name_id=saml.NAMEID_FORMAT_TRANSIENT),
                    attribute_statement = self.server.attribute_statement([
                        self.server.attribute(attribute_value="Derek", 
                                                friendly_name="givenName"),
                        self.server.attribute(attribute_value="Jeter", 
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
        assert response.issuer.text == "urn:mace:umu.se:saml:roland:sp"
        assert response.destination == "https:#www.example.com"
        assert response.in_response_to == "_012345"
        #
        status = response.status
        print status
        assert status.status_code.value == samlp.STATUS_SUCCESS

    def test_parse_faulty_request(self):
        authn_request = client.d_authn_request(
                            query_id = "1",
                            destination = "http://www.example.com",
                            service_url = "http://www.example.org",
                            spentityid = "urn:mace:umu.se:saml:roland:sp",
                            my_name = "My real name",
                        )
                        
        intermed = utils.deflate_and_base64_encode("%s" % authn_request)
        # should raise an error because faulty spentityid
        raises(OtherError,self.server.parse_authn_request,intermed)
        
    def test_parse_faulty_request_to_err_status(self):
        authn_request = client.d_authn_request(
                            query_id = "1",
                            destination = "http://www.example.com",
                            service_url = "http://www.example.org",
                            spentityid = "urn:mace:umu.se:saml:roland:sp",
                            my_name = "My real name",
                        )
                        
        intermed = utils.deflate_and_base64_encode("%s" % authn_request)
        try:
            self.server.parse_authn_request(intermed)
            status = None
        except OtherError, oe:
            print oe.args
            status = utils.make_instance(samlp.Status,
                            self.server.status_from_exception(oe))
            
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
        authn_request = client.d_authn_request(
                            query_id = "1",
                            destination = "http://www.example.com",
                            service_url = "http://localhost:8087/",
                            spentityid = "urn:mace:umu.se:saml:roland:sp",
                            my_name = "My real name",
                        )
                        
        intermed = utils.deflate_and_base64_encode("%s" % authn_request)
        (consumer_url, id, name_id_policies, 
                            sp) = self.server.parse_authn_request(intermed)
                                                        
        assert consumer_url == "http://localhost:8087/"
        assert id == "1"
        assert name_id_policies == saml.NAMEID_FORMAT_TRANSIENT
        assert sp == "urn:mace:umu.se:saml:roland:sp"

    def test_sso_response(self):
        resp = self.server.do_sso_response(
                    "http://localhost:8087/",   # consumer_url
                    "12",                       # in_response_to
                    "urn:mace:umu.se:saml:roland:sp", # sp_entity_id
                    {("urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
                        "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                        "eduPersonEntitlement"):"Jeter"}
                )
                
        print resp.keyswv()
        assert _eq(resp.keyswv(),['status', 'destination', 'assertion', 
                                    'in_response_to', 'issue_instant', 
                                    'version', 'id'])
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

