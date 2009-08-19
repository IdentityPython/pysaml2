#!/usr/bin/env python

try:
  from xml.etree import ElementTree
except ImportError:
  from elementtree import ElementTree
import saml2
from saml2 import saml, samlp, md
import xmldsig as ds
import base64

def _verify_contact_person(person):
    assert person.contact_type == "technical"
    assert person.given_name.text == "Roland"
    assert person.sur_name.text == "Hedberg"
    assert person.email_address[0].text == "roland.hedberg@adm.umu.se"

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

def _get_keys(key_descriptors):
    res = {}
    for kd in key_descriptors:
        use = kd.use
        coded_key = kd.key_info.x509_data[0].x509_certificate[0].text
        key = base64.b64decode(coded_key)
        try:
            res[use].append(key)
        except KeyError:
            res[use] = [key]
    return res
    
    
def _verify_idp_sso_description(idpssodesc):
    for ssoserv in idpssodesc.single_sign_on_service: # only one
        _verify_single_sign_on_service(ssoserv)
    for sloserv in idpssodesc.single_logout_service: # only one
        _verify_single_logout_service(sloserv)
    assert idpssodesc.name_id_format[0].text == "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    assert len(idpssodesc.key_descriptor) == 2
    keys = _get_keys(idpssodesc.key_descriptor)
    assert set(keys.keys()) == set(["signing","encryption"])
    # one key for signing and one for encryption
    assert len(keys["signing"]) == 1
    assert len(keys["encryption"]) == 1
    
def test_contactdata(contact):
    person = md.contact_person_from_string(contact)
    _verify_contact_person(person)
    
def test_entity_descriptor(idp_metadata):
    ed = md.entity_descriptor_from_string(idp_metadata)
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

# def test_idp_metadata(idp_metadata):
#     entities_descriptor = md.entities_descriptor_from_string(idp_metadata)
#     print type(idp_metadata)
#     print idp_metadata
#     print entities_descriptor.to_string()
#     assert False
    