#!/usr/bin/env python

from saml2.client import Saml2Client
from saml2 import samlp

XML_RESPONSE_FILE = "tests/saml_signed.xml"
XML_RESPONSE_FILE2 = "tests/saml2_response.xml"

import os

try:
    XMLSEC_BINARY = "/usr/local/bin/xmlsec1"
    os.stat(XMLSEC_BINARY)
except OSError:
    try:
        XMLSEC_BINARY = "/usr/bin/xmlsec1"
        os.stat(XMLSEC_BINARY)
    except OSError:
        raise
        
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

def test_verify_1():
    xml_response = open(XML_RESPONSE_FILE).read()
    client = Saml2Client({}, xmlsec_binary=XMLSEC_BINARY)
    (ava, came_from) = \
            client.verify_response(xml_response, "xenosmilus.umdc.umu.se", 
                            decode=False)
    assert ava == {'__userid': '_cddc88563d433f556d4cc70c3162deabddea3b5019', 
                    'eduPersonAffiliation': ['member', 'student'], 
                    'uid': ['student']}
    
def test_parse_1():
    xml_response = open(XML_RESPONSE_FILE).read()
    response = samlp.response_from_string(xml_response)
    client = Saml2Client({}, xmlsec_binary=XMLSEC_BINARY)
    (ava, name_id, real_uri) = \
            client.do_response(response, "xenosmilus.umdc.umu.se")
    assert ava == {'eduPersonAffiliation': ['member', 'student'],
                    'uid': ['student']}
    assert name_id == "_cddc88563d433f556d4cc70c3162deabddea3b5019"

def test_parse_2():
    xml_response = open(XML_RESPONSE_FILE2).read()
    response = samlp.response_from_string(xml_response)
    client = Saml2Client({}, xmlsec_binary=XMLSEC_BINARY)
    (ava, name_id, real_uri) = \
            client.do_response(response, "xenosmilus.umdc.umu.se")
    assert ava == {'uid': ['andreas'], 
                    'mobile': ['+4741107700'], 
                    'edupersonnickname': ['erlang'], 
                    'o': ['Feide RnD'], 
                    'edupersonentitlement': [
                            'urn:mace:feide.no:entitlement:test'], 
                    'edupersonaffiliation': ['employee'], 
                    'eduPersonPrincipalName': ['andreas@rnd.feide.no'], 
                    'sn': ['Solberg'], 
                    'mail': ['andreas@uninett.no'], 
                    'ou': ['Guests'], 
                    'cn': ['Andreas Solberg']}
    assert name_id == "_242f88493449e639aab95dd9b92b1d04234ab84fd8"
        
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
<ns0:AttributeQuery Destination="https://idp.example.com/idp/" ID="1" IssueInstant="%s" Version="2.0" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns1:Subject xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"><ns1:NameID SPNameQualifier="http://vo.example.org/biomed">E8042FB4-4D5B-48C3-8E14-8EDD852790DD</ns1:NameID></ns1:Subject></ns0:AttributeQuery>"""

class TestClient:
    def setup_class(self):
        self.client = Saml2Client({}, xmlsec_binary=XMLSEC_BINARY)
    
    def test_create_attribute_query(self):
        req = self.client.create_attribute_request("1", 
            subject_id = "E8042FB4-4D5B-48C3-8E14-8EDD852790DD", 
            destination = "https://idp.example.com/idp/", 
            sp_name_qualifier="http://vo.example.org/biomed")
        str = "%s" % req.to_string()
        print str
        assert str == REQ1 % req.issue_instant
        assert req.destination == "https://idp.example.com/idp/"
        assert req.id == "1"
        assert req.version == "2.0"
        subject = req.subject
        name_id = subject.name_id
        assert name_id.sp_name_qualifier == "http://vo.example.org/biomed"
        assert name_id.text == "E8042FB4-4D5B-48C3-8E14-8EDD852790DD"
        