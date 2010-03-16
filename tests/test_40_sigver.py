#!/usr/bin/env python

from saml2 import sigver, make_instance
from saml2 import utils
from saml2 import time_util
from saml2 import saml
import xmldsig as ds
from py.test import raises

SIGNED = "saml_signed.xml"
UNSIGNED = "saml_unsigned.xml"
FALSE_SIGNED = "saml_false_signed.xml"
#PUB_KEY = "test.pem"
PRIV_KEY = "test.key"

def _eq(l1,l2):
    return set(l1) == set(l2)

def test_verify_1(xmlsec):
    xml_response = open(SIGNED).read()
    response = sigver.correctly_signed_response(xml_response, xmlsec)
    assert response

def test_non_verify_1(xmlsec):
    """ unsigned is OK if not good """
    xml_response = open(UNSIGNED).read()
    response = sigver.correctly_signed_response(xml_response, xmlsec)
    assert response

def test_non_verify_2(xmlsec):
    xml_response = open(FALSE_SIGNED).read()
    raises(sigver.SignatureError,sigver.correctly_signed_response,
            xml_response, xmlsec)

SIGNED_VALUE= """AS1kHHtA4eTOU2XLTWhLMSJQ6V+TSDymRoTF78CqjrYURNLk9wjdPjAReNn9eykv
ryFiHNk0p9wMBknha5pH8aeCI/LmcVhLa5xteGZrtE/Udh5vv8z4kRQX51Uz/5x8
ToiobGw83MEW6A0dRUn0O20NBMMTaFZZPXye7RvVlHY="""

DIGEST_VALUE = "WFRXmImfoO3M6JOLE6BGGpU9Ud0="

def test_sign(xmlsec):
    ass = make_instance(saml.Assertion, {
        "version": "2.0",
        "id": "11111",
        "issue_instant": "2009-10-30T13:20:28Z",
        "signature": sigver.pre_signature_part("11111"),
        "attribute_statement": {
            "attribute": [{
                    "friendly_name": "surName",
                    "attribute_value": "Foo",
                },
                {
                    "friendly_name": "givenName",
                    "attribute_value": "Bar",
                }
                ]
            }
        })
        
    print ass
    sign_ass = sigver.sign_assertion_using_xmlsec("%s" % ass, xmlsec, 
                                                    key_file=PRIV_KEY)
    sass = saml.assertion_from_string(sign_ass)
    print sass
    assert _eq(sass.keyswv(), ['attribute_statement', 'issue_instant', 
                            'version', 'signature', 'id'])
    assert sass.version == "2.0"
    assert sass.id == "11111"
    assert time_util.str_to_time(sass.issue_instant)
    sig = sass.signature
    assert sig.signature_value.text == SIGNED_VALUE
    assert len(sig.signed_info.reference) == 1
    assert len(sig.signed_info.reference[0].digest_value) == 1
    assert sig.signed_info.reference[0].digest_value[0].text == DIGEST_VALUE
    
