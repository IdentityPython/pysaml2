#!/usr/bin/env python

from saml2.server import Server
from saml2 import samlp, saml
from saml2.utils import make_instance

SUCCESS_STATUS = """<?xml version=\'1.0\' encoding=\'UTF-8\'?>
<ns0:Status xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></ns0:Status>"""

ERROR_STATUS = """<?xml version='1.0' encoding='UTF-8'?>
<ns0:Status xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal" /></ns0:StatusCode><ns0:StatusMessage>Error resolving principal</ns0:StatusMessage></ns0:Status>"""

def _eq(l1,l2):
    return set(l1) == set(l2)

class TestServer():
    def setup_class(self):
        self.server = Server("tests/server.config")

    def test_success_status(self):
        stat = self.server.status(samlp.STATUS_SUCCESS)            
        status = make_instance( samlp.Status, stat )
        status_text = "%s" % status
        assert status_text == SUCCESS_STATUS
        assert status.status_code.value == samlp.STATUS_SUCCESS
        
    def test_error_status(self):
        stat = self.server.status(samlp.STATUS_RESPONDER,
            message="Error resolving principal",
            status_code=self.server.status(samlp.STATUS_UNKNOWN_PRINCIPAL))
            
        status_text = "%s" % make_instance( samlp.Status, stat )
        assert status_text == ERROR_STATUS

    def test_issuer(self):
        issuer = make_instance( saml.Issuer, self.server.issuer())
        assert isinstance(issuer, saml.Issuer)
        assert _eq(issuer.keyswv(), ["text","format"])
        assert issuer.format == saml.NAMEID_FORMAT_ENTITY
        assert issuer.text == self.server.conf["entityid"]
        
    def test_audience(self):
        aud_restr = make_instance( saml.AudienceRestriction, 
                self.server.audience_restriction("urn:foo:bar"))
                
        assert aud_restr.keyswv() == ["audience"]
        assert aud_restr.audience.text == "urn:foo:bar"
        
    def test_conditions(self):
        conds_dict = self.server.conditions("2009-10-30T07:58:10.852Z",
                        "2009-10-30T08:03:10.852Z", 
                        self.server.audience_restriction("urn:foo:bar"))
                        
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
        adict = self.server.attribute("Derek",name="urn:oid:2.5.4.42",
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
        adict = self.server.attribute("Derek",
                                        friendly_name="givenName")
        attribute = make_instance(saml.Attribute, adict)
        assert _eq(attribute.keyswv(),["friendly_name", "attribute_value"])
        assert attribute.friendly_name == "givenName"
        assert len(attribute.attribute_value) == 1
        assert attribute.attribute_value[0].text == "Derek"

    def test_attribute_statement(self):
        asdict = self.server.attribute_statement([
                        self.server.attribute("Derek", 
                                                friendly_name="givenName"),
                        self.server.attribute("Jeter", 
                                                friendly_name="surName"),
                            ])
        attribute_statement = make_instance(saml.AttributeStatement,asdict)
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
            attribute_statement = self.server.attribute_statement([
                self.server.attribute("Derek", friendly_name="givenName"),
                self.server.attribute("Jeter", friendly_name="surName"),
                ])
            )
            
        assertion = make_instance(saml.Assertion, tmp)
        assert _eq(assertion.keyswv(),['attribute_statement', 'issuer', 'id',
                                    'subject', 'issue_instant', 'version'])
        assert assertion.version == "2.0"
        assert assertion.issuer.text == "urn:mace:umu.se:saml:rolandsp"
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
                destination="https://www.example.com",
                status=self.server.status(samlp.STATUS_SUCCESS),
                assertion=self.server.assertion(
                    subject = self.server.subject("_aaa",
                                        name_id=saml.NAMEID_FORMAT_TRANSIENT),
                    attribute_statement = self.server.attribute_statement([
                        self.server.attribute("Derek", 
                                                friendly_name="givenName"),
                        self.server.attribute("Jeter", 
                                                friendly_name="surName"),
                    ])
                )
            )
            
        response = make_instance(samlp.Response, tmp)
        print response.keyswv()
        assert _eq(response.keyswv(),['destination', 'assertion','status', 
                                    'in_response_to', 'issue_instant', 
                                    'version', 'issuer', 'id'])
        assert response.version == "2.0"
        assert response.issuer.text == "urn:mace:umu.se:saml:rolandsp"
        assert response.destination == "https://www.example.com"
        assert response.in_response_to == "_012345"
        #
        status = response.status
        print status
        assert status.status_code.value == samlp.STATUS_SUCCESS
