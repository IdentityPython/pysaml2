#!/usr/bin/env python

import os
import base64

from saml2 import sigver, make_instance
from saml2 import utils, class_name
from saml2 import time_util
from saml2 import saml, samlp
import xmldsig as ds
from py.test import raises

SIGNED = "saml_signed.xml"
UNSIGNED = "saml_unsigned.xml"
FALSE_SIGNED = "saml_false_signed.xml"
SIMPLE_SAML_PHP_RESPONSE = "simplesamlphp_authnresponse.xml"

PUB_KEY = "test.pem"
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

CERT1 = """MIICsDCCAhmgAwIBAgIJAJrzqSSwmDY9MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMDkxMDA2MTk0OTQxWhcNMDkxMTA1MTk0OTQxWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJg2cms7MqjniT8Fi/XkNHZNPbNVQyMUMXE9tXOdqwYCA1cc8vQdzkihscQMXy3iPw2cMggBu6gjMTOSOxECkuvX5ZCclKr8pXAJM5cY6gVOaVO2PdTZcvDBKGbiaNefiEw5hnoZomqZGp8wHNLAUkwtH9vjqqvxyS/vclc6k2ewIDAQABo4GnMIGkMB0GA1UdDgQWBBRePsKHKYJsiojE78ZWXccK9K4aJTB1BgNVHSMEbjBsgBRePsKHKYJsiojE78ZWXccK9K4aJaFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAJrzqSSwmDY9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAJSrKOEzHO7TL5cy6h3qh+3+JAk8HbGBW+cbX6KBCAw/mzU8flK25vnWwXS3dv2FF3Aod0/S7AWNfKib5U/SA9nJaz/mWeF9S0farz9AQFc8/NSzAzaVq7YbM4F6f6N2FRl7GikdXRCed45j6mrPzGzk3ECbupFnqyREH3+ZPSdk="""

CERT_SSP = """MIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UECxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0BCQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoXDTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhlaW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBvcGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdAdW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlxAZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4HlnO4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZjcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQYj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1jwKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3KjjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w=="""

from pyasn1.codec.der import decoder
 
def test_cert_from_instance_1():
    xml_response = open(SIGNED).read()
    response = samlp.response_from_string(xml_response)
    assertion = response.assertion[0]
    certs = sigver.cert_from_instance(assertion)
    assert len(certs) == 1
    assert certs[0] == CERT1

def test_cert_from_instance_ssp():
    xml_response = open(SIMPLE_SAML_PHP_RESPONSE).read()
    response = samlp.response_from_string(xml_response)
    assertion = response.assertion[0]
    certs = sigver.cert_from_instance(assertion)
    assert len(certs) == 1
    print certs[0]
    der = base64.b64decode(certs[0])
    print str(decoder.decode(der)).replace('.',"\n.")
    assert decoder.decode(der)
    assert certs[0] == CERT_SSP

    
class TestSecurity():
    def setup_class(self):
        self.sec = sigver.SecurityContext(get_xmlsec(), PRIV_KEY, "pem",
                                            PUB_KEY, "pem", debug=1)
        
    def test_verify_1(self):
        xml_response = open(SIGNED).read()
        response = self.sec.correctly_signed_response(xml_response)
        assert response

    def test_non_verify_1(self):
        """ unsigned is OK """
        xml_response = open(UNSIGNED).read()
        response = self.sec.correctly_signed_response(xml_response)
        assert response

    def test_non_verify_2(self):
        xml_response = open(FALSE_SIGNED).read()
        raises(sigver.SignatureError,self.sec.correctly_signed_response,
                xml_response)

    def test_sign_assertion(self):
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
        
    def test_sign_response(self):
        assertion = {
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
            }

        s_response = sigver.signed_instance_factory(samlp.Response, {
                "assertion" : assertion,
                "id": "22222",
                "signature": sigver.pre_signature_part("22222"),
            }, self.sec)
            
        assert s_response != None
        print s_response
        print
        sass = s_response.assertion[0]
        
        print sass
        assert _eq(sass.keyswv(), ['attribute_statement', 'issue_instant', 
                                'version', 'signature', 'id'])
        assert sass.version == "2.0"
        assert sass.id == "11111"
        assert time_util.str_to_time(sass.issue_instant)
        sig = sass.signature
        assert sig.signature_value.text == """AS1kHHtA4eTOU2XLTWhLMSJQ6V+TSDymRoTF78CqjrYURNLk9wjdPjAReNn9eykv\nryFiHNk0p9wMBknha5pH8aeCI/LmcVhLa5xteGZrtE/Udh5vv8z4kRQX51Uz/5x8\nToiobGw83MEW6A0dRUn0O20NBMMTaFZZPXye7RvVlHY="""
        
        assert len(sig.signed_info.reference) == 1
        assert len(sig.signed_info.reference[0].digest_value) == 1
        digest = sig.signed_info.reference[0].digest_value[0].text
        assert digest == """WFRXmImfoO3M6JOLE6BGGpU9Ud0="""

    def test_sign_response_2(self):
        assertion1 = {
            "version": "2.0",
            "id": "11111",
            "issue_instant": "2009-10-30T13:20:28Z",
            "signature": sigver.pre_signature_part("11111").copy(),
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
            }
        assertion2 = {
            "version": "2.0",
            "id": "11122",
            "issue_instant": "2009-10-30T13:20:28Z",
            "signature": sigver.pre_signature_part("11122").copy(),
            "attribute_statement": {
                "attribute": [{
                        "friendly_name": "surName",
                        "attribute_value": "Fox",
                    },
                    {
                        "friendly_name": "givenName",
                        "attribute_value": "Bear",
                    }
                    ]
                }
            }

        s_response = sigver.signed_instance_factory(samlp.Response, {
                "assertion" : [assertion1,assertion2],
                "id": "22233",
                "signature": sigver.pre_signature_part("22233"),
            }, self.sec)
            
        assert s_response != None
        print s_response
        print
        sass = s_response.assertion[0]
        
        print sass
        assert _eq(sass.keyswv(), ['attribute_statement', 'issue_instant', 
                                'version', 'signature', 'id'])
        assert sass.version == "2.0"
        assert sass.id == "11111"
        assert time_util.str_to_time(sass.issue_instant)
        sig = sass.signature
        assert sig.signature_value.text == """AS1kHHtA4eTOU2XLTWhLMSJQ6V+TSDymRoTF78CqjrYURNLk9wjdPjAReNn9eykv\nryFiHNk0p9wMBknha5pH8aeCI/LmcVhLa5xteGZrtE/Udh5vv8z4kRQX51Uz/5x8\nToiobGw83MEW6A0dRUn0O20NBMMTaFZZPXye7RvVlHY="""
        
        assert len(sig.signed_info.reference) == 1
        assert len(sig.signed_info.reference[0].digest_value) == 1
        digest = sig.signed_info.reference[0].digest_value[0].text
        assert digest == """WFRXmImfoO3M6JOLE6BGGpU9Ud0="""

    def test_sign_verify(self):
        assertion = {
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
            }

        s_response = sigver.signed_instance_factory(samlp.Response, {
                "assertion" : assertion,
                "id": "22222",
                "signature": sigver.pre_signature_part("22222"),
            }, self.sec)

        res = self.sec.verify_signature("%s" % s_response, 
                                    node_name=class_name(samlp.Response()))

        print res        
        assert res

    def test_sign_verify_with_cert_from_instance(self):
        assertion = {
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
            }

        s_response = sigver.signed_instance_factory(samlp.Response, {
                "assertion" : assertion,
                "id": "22222",
                "signature": sigver.pre_signature_part("22222", 
                    "".join(open(self.sec.cert_file).read().split("\n")[1:-2])),
            }, self.sec)
            
        ci = sigver.cert_from_instance(s_response)
        
        print ci
        
        res = self.sec._check_signature("%s" % s_response, s_response, 
                                        class_name(s_response))
        
        assert res == s_response

    def test_exception_sign_verify_with_cert_from_instance(self):
        assertion = {
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
            }

        s_response = sigver.signed_instance_factory(samlp.Response, {
                "assertion" : assertion,
                "id": "22222",
                "signature": sigver.pre_signature_part("22222", 
                    "".join(open(self.sec.cert_file).read().split("\n")[1:-2])),
            }, self.sec)
            

        # Change something that should make everything fail
        s_response.id = "23456"
        raises(sigver.SignatureError, self.sec._check_signature,
                "%s" % s_response, s_response, class_name(s_response))
        
