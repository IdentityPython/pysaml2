#!/usr/bin/env python

import os

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

SIGNED_VALUE= """AS1kHHtA4eTOU2XLTWhLMSJQ6V+TSDymRoTF78CqjrYURNLk9wjdPjAReNn9eykv
ryFiHNk0p9wMBknha5pH8aeCI/LmcVhLa5xteGZrtE/Udh5vv8z4kRQX51Uz/5x8
ToiobGw83MEW6A0dRUn0O20NBMMTaFZZPXye7RvVlHY="""

DIGEST_VALUE = "WFRXmImfoO3M6JOLE6BGGpU9Ud0="

def get_xmlsec():
    for path in os.environ["PATH"].split(":"):
        fil = os.path.join(path, "xmlsec1")
        if os.access(fil,os.X_OK):
            return fil

    raise Exception("Can't find xmlsec1")

class TestSecurity():
    def setup_class(self):
        self.sec = sigver.SecurityContext(get_xmlsec(), PRIV_KEY, "pem")
        
    def test_verify_1(self):
        xml_response = open(SIGNED).read()
        response = self.sec.correctly_signed_response(xml_response)
        assert response

    def test_non_verify_1(self):
        """ unsigned is OK if not good """
        xml_response = open(UNSIGNED).read()
        response = self.sec.correctly_signed_response(xml_response)
        assert response

    def test_non_verify_2(self):
        xml_response = open(FALSE_SIGNED).read()
        raises(sigver.SignatureError,self.sec.correctly_signed_response,
                xml_response)

    def test_sign(self):
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
            
        sign_ass = self.sec.sign_assertion_using_xmlsec("%s" % ass)
        
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
        
