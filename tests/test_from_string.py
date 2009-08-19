#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for saml2.saml"""

__author__ = 'roland.hedberg@adm.umu.se'

try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree
from saml2 import md
import xmldsig as ds

X509DATA = """<?xml version="1.0" encoding="utf-8"?>
<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#">
    <X509Certificate>MIICgTCCAeoCCQCbOlrWDdX7FTANBg</X509Certificate>
</X509Data>"""

KEY_INFO = """<?xml version="1.0"?>
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
    <X509Data>
        <X509Certificate>MIICgTCCAeoCCQCbOlrWDdX7FTANBg</X509Certificate>
    </X509Data>
</KeyInfo>"""

KEY_DESCRIPTOR = """<?xml version="1.0"?>
<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="signing">
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
            <ds:X509Certificate>MIICgTCCAeoCCQCbOlrWDdX7FTANBg</ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>
</KeyDescriptor>"""

IDP = """
"""

ED = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICgTCCAeoCCQCbOlrWDdX7</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICgTCCAeoCCQCbOlrWDdX7</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SingleLogoutService.php"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SSOService.php"/>
  </IDPSSODescriptor>
  <ContactPerson contactType="technical">
    <GivenName>Roland</GivenName>
    <SurName>Hedberg</SurName>
    <EmailAddress>roland.hedberg@adm.umu.se</EmailAddress>
  </ContactPerson>
</EntityDescriptor>"""

ED2 = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SingleLogoutService.php"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SSOService.php"/>
  </IDPSSODescriptor>
  <ContactPerson contactType="technical">
    <GivenName>Roland</GivenName>
    <SurName>Hedberg</SurName>
    <EmailAddress>roland.hedberg@adm.umu.se</EmailAddress>
  </ContactPerson>
</EntityDescriptor>"""

def _verify_x509data(x509data):
    assert x509data.x509_certificate != []
    assert len(x509data.x509_certificate) == 1
    cert = x509data.x509_certificate[0]
    assert cert.text == "MIICgTCCAeoCCQCbOlrWDdX7FTANBg"
        
def test_x509data():
    x509data = ds.x509_data_from_string(X509DATA)
    _verify_x509data(x509data)

def _verify_info(info):
    assert info.x509_data != []
    assert len(info.x509_data) == 1
    x509data = info.x509_data[0]
    _verify_x509data(x509data)
    
def test_key_info():
    info = ds.key_info_from_string(KEY_INFO)
    _verify_info(info)


def test_key_descriptor():
    desc = md.key_descriptor_from_string(KEY_DESCRIPTOR)
    assert desc.use == "signing"
    print desc.__dict__
    assert desc.key_info != None
    info = desc.key_info
    _verify_info(info)

def _verify_contact_person(person):
    assert person.contact_type == "technical"
    assert person.given_name.text == "Roland"
    assert person.sur_name.text == "Hedberg"
    assert person.email_address[0].text == "roland.hedberg@adm.umu.se"
    
def _verify_single_sign_on_service(sso):
    assert sso.binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    assert sso.location == "http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SSOService.php"

def _verify_single_logout_service(sso):
    assert sso.binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    assert sso.location == "http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/SingleLogoutService.php"
    
def _verify_idp_sso_description(idpssodesc):
    for ssoserv in idpssodesc.single_sign_on_service: # only one
        _verify_single_sign_on_service(ssoserv)
    for sloserv in idpssodesc.single_logout_service: # only one
        _verify_single_logout_service(sloserv)
    assert idpssodesc.name_id_format[0].text == "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    
def test_entity_descriptor():
    ed = md.entity_descriptor_from_string(ED)
    assert ed.entity_id == "http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php"
    contact_person = ed.contact_person[0]
    _verify_contact_person(contact_person)
    idpsso = ed.idp_sso_descriptor[0]
    _verify_idp_sso_description(idpsso)
    assert ed.entity_id == "http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php"
    print ed.to_string()
    # all other attributes are supposed to be None,'',[] or {}
    for key,val in ed.__dict__.items():
        if key in ["contact_person", "idp_sso_descriptor", "entity_id"]:
            continue
        else:
            if isinstance(val,basestring):
                val = val.strip('\t\r\n ')
            assert val in [None,'',[],{}]

def test_entity_descriptor_2():
    ed = md.entity_descriptor_from_string(ED2)
    assert ed.entity_id == "http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php"
    contact_person = ed.contact_person[0]
    _verify_contact_person(contact_person)
    idpsso = ed.idp_sso_descriptor[0]
    _verify_idp_sso_description(idpsso)
    assert ed.entity_id == "http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php"
    print ed.to_string()
    # all other attributes are supposed to be None,'',[] or {}
    for key,val in ed.__dict__.items():
        if key in ["contact_person", "idp_sso_descriptor", "entity_id"]:
            continue
        else:
            if isinstance(val,basestring):
                val = val.strip('\t\r\n ')
            assert val in [None,'',[],{}]
    
