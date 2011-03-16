#!/usr/bin/env python

import os
import base64

from saml2 import sigver, make_instance
from saml2 import class_name
from saml2 import time_util
from saml2 import saml, samlp
from saml2.s_utils import factory, do_attribute_statement
from saml2.sigver import xmlsec_version, get_xmlsec_binary

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

SIGNATURE_DIGEST = {
    "1.2.14": [(
        "kMuyOK17nyp4CbA1v7KE32rX4+NQQ8EvdglTK61uIMEo3ax0PgFU7bgZGey+Aj8H\nhTPVyAzWmBDxHpSCFe050PTtNoKHx7nXprLfhuQXsPq8s0KBoZR+2qYfVCkWYVX7\nT3zG/Tn+fesBA1zLo4lYdAovol7C35KAsAWoknmZdOE=",
        "SXw3kqTf+PtTiUnI8nQ6xmrM3qw="),
        (
        "upeKPE1pkzXLy9BvKFOSTnjn4du59lQQ74TN5CqDGae9D21uY/zLuOWql7LiSTSi\nC945F0WrOvG7s0eZnpuNPZobdfdeCOffCMMrq5RQ2+abPFBamkjmceuEKGdO5PWQ\nt7B1GkzXAMMgeMuU+YmvIJkHbbv5Yn6M0/ICE/COaKQ=",
        "uX92C/YDroqITDfDY1IeekGtZac="),
        (
        "xHECLk1jj4NBvk1jhGrb2mwnrLFKXk6JN3NogjMVMtnnarg9vtk7jYzy1M9RPWdj\nRSa2Jph7yVZJENm4bGuBkT91w+FYm2X4jREULPUsnupPHTQyhJEVZ07EhnluOWa3\n95KkqnZ5gbnTxn1ZvpsANzThLmYY3eSGzNXz+S7758M=",
        "l36wHa6Lyed9ZeAZ3jFL77wPVQ4="
        )
    ],
    "1.2.16":[
        (
        "imvo3quPyMND8yCv8D3LNCbeiG98hKl+F5VekEY5N7EEBoq7S3A7mArz4yZUVJVw\n1migufgOZEiZX80vzR0lwfjAEjwRp+NjKRvOcWHfIgjz+dG8q9n4LcI5YmsjveLa\n+iNTujev1PYA+UWf57S5mqGFoi0KaS8Xnp0FG1olAZ0=",
        "0+0Td5mWbs+CF7xZeYSlcQ/pjKw="),
        (
        "NEoJEpCLRi35e+cK8fwInrThausuD3xNlKZFhZda6qS8GU93s8J3sKLpd5BwB9my\nesHX38c9WhQkXeuQu6O75hMwLWb7496vG+QcodaWvLJ8u/Cgp2XdQopkNWLOqLJC\n7XyLa0fEDhPY/kvX88kx9xBnA/VhIYVjQtNrTD9M5Q8=",
        "gqe292uV8r7LfSomiMh9VS9wYZw="),
        (
        "DS5V623NrKCXmBjzCgVDUkPXSg8kMezZIeEqg8RC6Q/0/vjoBgZDt1hMvOmOX4Vf\nA1ckqeEEHnsqegjBRUUiV41SALJmKSVvUG5V29ZonGK4EXtdC5dxRPa/2tqN1i8N\nwtTlD7DE/YLAPIM5nhL8qHKKovQvwypZmC2YVmKIuQ0=",
        "h6o97FThq9XqEzw+njeKjH45QgM="),
    ]
}

CERT1 = """MIICsDCCAhmgAwIBAgIJAJrzqSSwmDY9MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMDkxMDA2MTk0OTQxWhcNMDkxMTA1MTk0OTQxWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDJg2cms7MqjniT8Fi/XkNHZNPbNVQyMUMXE9tXOdqwYCA1cc8vQdzkihscQMXy
3iPw2cMggBu6gjMTOSOxECkuvX5ZCclKr8pXAJM5cY6gVOaVO2PdTZcvDBKGbiaN
efiEw5hnoZomqZGp8wHNLAUkwtH9vjqqvxyS/vclc6k2ewIDAQABo4GnMIGkMB0G
A1UdDgQWBBRePsKHKYJsiojE78ZWXccK9K4aJTB1BgNVHSMEbjBsgBRePsKHKYJs
iojE78ZWXccK9K4aJaFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUt
U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAJrzqSSw
mDY9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAJSrKOEzHO7TL5cy6
h3qh+3+JAk8HbGBW+cbX6KBCAw/mzU8flK25vnWwXS3dv2FF3Aod0/S7AWNfKib5
U/SA9nJaz/mWeF9S0farz9AQFc8/NSzAzaVq7YbM4F6f6N2FRl7GikdXRCed45j6
mrPzGzk3ECbupFnqyREH3+ZPSdk="""

CERT_SSP = """MIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMC
Tk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UE
CxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0B
CQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoX
DTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhl
aW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBv
cGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdA
dW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlx
AZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4Hln
O4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZ
jcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQ
Yj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1j
wKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3K
jjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w=="""

from pyasn1.codec.der import decoder
 
def test_cert_from_instance_1():
    xml_response = open(SIGNED).read()
    response = samlp.response_from_string(xml_response)
    assertion = response.assertion[0]
    certs = sigver.cert_from_instance(assertion)
    assert len(certs) == 1
    print certs[0]
    assert certs[0] == CERT1

def test_cert_from_instance_ssp():
    xml_response = open(SIMPLE_SAML_PHP_RESPONSE).read()
    response = samlp.response_from_string(xml_response)
    assertion = response.assertion[0]
    certs = sigver.cert_from_instance(assertion)
    assert len(certs) == 1
    assert certs[0] == CERT_SSP
    der = base64.b64decode(certs[0])
    print str(decoder.decode(der)).replace('.',"\n.")
    assert decoder.decode(der)

    
class TestSecurity():
    def setup_class(self):
        xmlexec = get_xmlsec_binary()
        self.sec = sigver.SecurityContext(xmlexec, PRIV_KEY, "pem",
                                            PUB_KEY, "pem", debug=1)
        
        #self.sign_digest = SIGNATURE_DIGEST[xmlsec_version(xmlexec)]
        self.sign_digest = SIGNATURE_DIGEST["1.2.16"]

        self._assertion = factory( saml.Assertion,
            version="2.0",
            id="11111",
            issue_instant="2009-10-30T13:20:28Z",
            signature=sigver.pre_signature_part("11111", self.sec.my_cert, 1),
            attribute_statement=do_attribute_statement({
                    ("","","surName"): ("Foo",""),
                    ("","","givenName") :("Bar",""),
                })
            )

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
        ass = self._assertion
        print ass
        sign_ass = self.sec.sign_assertion_using_xmlsec("%s" % ass, nodeid=ass.id)
        #print sign_ass
        sass = saml.assertion_from_string(sign_ass)
        #print sass
        assert _eq(sass.keyswv(), ['attribute_statement', 'issue_instant', 
                                'version', 'signature', 'id'])
        assert sass.version == "2.0"
        assert sass.id == "11111"
        assert time_util.str_to_time(sass.issue_instant)
        sig = sass.signature
        print xmlsec_version(get_xmlsec_binary())
        print sig.signature_value.text
        print self.sign_digest[0][0]
        assert sig.signature_value.text == self.sign_digest[0][0]
        assert len(sig.signed_info.reference) == 1
        assert sig.signed_info.reference[0].digest_value
        assert sig.signed_info.reference[0].digest_value.text == self.sign_digest[0][1]
        
    def test_sign_response(self):
        response = factory(samlp.Response,
                assertion=self._assertion,
                id="22222",
                signature=sigver.pre_signature_part("22222", self.sec.my_cert))
        
        to_sign = [(class_name(self._assertion), self._assertion.id),
                    (class_name(response), response.id)]
        s_response = sigver.signed_instance_factory( response, self.sec, to_sign)
            
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
        assert sig.signature_value.text == self.sign_digest[1][0]
        
        assert len(sig.signed_info.reference) == 1
        assert sig.signed_info.reference[0].digest_value
        digest = sig.signed_info.reference[0].digest_value.text
        assert digest == self.sign_digest[1][1]

    def test_sign_response_2(self):
        assertion2 = factory( saml.Assertion,
            version= "2.0",
            id= "11122",
            issue_instant= "2009-10-30T13:20:28Z",
            signature= sigver.pre_signature_part("11122", self.sec.my_cert),
            attribute_statement=do_attribute_statement({
                    ("","","surName"): ("Fox",""),
                    ("","","givenName") :("Bear",""),
                })
            )
        response = factory(samlp.Response,
                assertion=assertion2,
                id="22233",
                signature=sigver.pre_signature_part("22233"))

        to_sign = [(class_name(assertion2), assertion2.id),
                    (class_name(response), response.id)]

        s_response = sigver.signed_instance_factory( response, self.sec, to_sign)

        assert s_response != None
        print s_response
        print
        sass = s_response.assertion[0]
        
        print sass
        assert _eq(sass.keyswv(), ['attribute_statement', 'issue_instant', 
                                'version', 'signature', 'id'])
        assert sass.version == "2.0"
        assert sass.id == "11122"
        assert time_util.str_to_time(sass.issue_instant)
        sig = sass.signature
        assert sig.signature_value.text == self.sign_digest[2][0]
        
        assert len(sig.signed_info.reference) == 1
        assert sig.signed_info.reference[0].digest_value
        digest = sig.signed_info.reference[0].digest_value.text
        assert digest == self.sign_digest[2][1]

    def test_sign_verify(self):        
        response = factory(samlp.Response,
                assertion=self._assertion,
                id="22233",
                signature=sigver.pre_signature_part("22233", self.sec.my_cert))

        to_sign = [(class_name(self._assertion), self._assertion.id),
                    (class_name(response), response.id)]

        s_response = sigver.signed_instance_factory(response, self.sec, to_sign)

        print s_response
        res = self.sec.verify_signature("%s" % s_response, 
                                    node_name=class_name(samlp.Response()))

        print res        
        assert res

    def test_sign_verify_with_cert_from_instance(self):
        response = factory(samlp.Response,
                assertion=self._assertion,
                id="22222",
                signature=sigver.pre_signature_part("22222", self.sec.my_cert))

        to_sign = [(class_name(self._assertion), self._assertion.id),
                    (class_name(response), response.id)]

        s_response = sigver.signed_instance_factory(response, self.sec, to_sign)

        print s_response.keyswv()
        print s_response.signature.keyswv()
        print s_response.signature.key_info.keyswv()
        
        ci = "".join(sigver.cert_from_instance(s_response)[0].split())
        
        print ci
        print self.sec.my_cert
        
        assert ci == self.sec.my_cert
        
        res = self.sec.verify_signature("%s" % s_response, 
                                    node_name=class_name(samlp.Response()))
        assert res
        res = self.sec._check_signature("%s" % s_response, s_response, 
                                        class_name(s_response))
        
        assert res == s_response
                
    def test_sign_verify_assertion_with_cert_from_instance(self):
        assertion = factory( saml.Assertion,
            version= "2.0",
            id= "11100",
            issue_instant= "2009-10-30T13:20:28Z",
            signature= sigver.pre_signature_part("11100", self.sec.my_cert),
            attribute_statement=do_attribute_statement({
                    ("","","surName"): ("Fox",""),
                    ("","","givenName") :("Bear",""),
                })
            )

        to_sign = [(class_name(assertion), assertion.id)]
        s_assertion = sigver.signed_instance_factory(assertion, self.sec, to_sign)
        print s_assertion
        
        ci = "".join(sigver.cert_from_instance(s_assertion)[0].split())
        assert ci == self.sec.my_cert
        
        res = self.sec.verify_signature("%s" % s_assertion, 
                                    node_name=class_name(s_assertion))
        assert res 
        
        res = self.sec._check_signature("%s" % s_assertion, s_assertion, 
                                        class_name(s_assertion))
        
        assert res

    def test_exception_sign_verify_with_cert_from_instance(self):
        assertion = factory( saml.Assertion,
            version= "2.0",
            id= "11100",
            issue_instant= "2009-10-30T13:20:28Z",
            #signature= sigver.pre_signature_part("11100", self.sec.my_cert),
            attribute_statement=do_attribute_statement({
                    ("","","surName"): ("Foo",""),
                    ("","","givenName") :("Bar",""),
                })
            )

        response = factory(samlp.Response,
                assertion=assertion,
                id="22222",
                signature=sigver.pre_signature_part("22222", self.sec.my_cert))

        to_sign = [(class_name(response), response.id)]
                    
        s_response = sigver.signed_instance_factory(response, self.sec, to_sign)
            

        # Change something that should make everything fail
        s_response.id = "23456"
        raises(sigver.SignatureError, self.sec._check_signature,
                "%s" % s_response, s_response, class_name(s_response))
        
