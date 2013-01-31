# -*- coding: utf-8 -*-
import datetime
import re

from saml2.mdstore import MetadataStore
from saml2.mdstore import destinations
from saml2.mdstore import name

from saml2 import md
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import saml
from saml2.attribute_converter import ac_factory
from saml2.attribute_converter import d_to_local_name

from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
from saml2.s_utils import UnknownPrincipal
import xmldsig
import xmlenc

try:
    from saml2.sigver import get_xmlsec_binary
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
except ImportError:
    xmlsec_path = '/usr/bin/xmlsec1'


ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc
}

ATTRCONV = ac_factory("attributemaps")

METADATACONF = {
    "1": {
        "local": ["swamid-1.0.xml"]
    },
    "2": {
        "local": ["InCommon-metadata.xml"]
    },
    "3": {
        "local": ["extended.xml"]
    },
    "7": {
        "local": ["metadata_sp_1.xml", "InCommon-metadata.xml"],
        "remote": [{"url": "https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2",
                    "cert": "kalmar2.pem"}]
    },
    "4": {
        "local": ["metadata_example.xml"]
    },
    "5": {
        "local": ["metadata.aaitest.xml"]
    },
    "6": {
        "local": ["metasp.xml"]
    }
}

def _eq(l1,l2):
    return set(l1) == set(l2)


def _fix_valid_until(xmlstring):
    new_date = datetime.datetime.now() + datetime.timedelta(days=1)
    new_date = new_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    return re.sub(r' validUntil=".*?"', ' validUntil="%s"' % new_date,
                  xmlstring)

def test_swami_1():
    UMU_IDP = 'https://idp.umu.se/saml2/idp/metadata.php'
    mds = MetadataStore(ONTS.values(), ATTRCONV, xmlsec_path,
                        disable_ssl_certificate_validation=True)

    mds.imp(METADATACONF["1"])
    assert len(mds) == 1 # One source
    idps = mds.with_descriptor("idpsso")
    assert idps.keys()
    idpsso = mds.single_sign_on_service(UMU_IDP)
    assert len(idpsso) == 1
    assert destinations(idpsso) == ['https://idp.umu.se/saml2/idp/SSOService.php']

    _name = name(mds[UMU_IDP])
    assert _name == u'Umeå University (SAML2)'
    certs =  mds.certs(UMU_IDP, "idpsso", "signing")
    assert len(certs) == 1

    sps = mds.with_descriptor("spsso")
    assert len(sps) == 108

    wants = mds.attribute_requirement('https://connect8.sunet.se/shibboleth')
    lnamn = [d_to_local_name(mds.attrc, attr) for attr in wants["optional"]]
    assert _eq(lnamn, ['eduPersonPrincipalName', 'mail', 'givenName', 'sn',
                       'eduPersonScopedAffiliation'])
                
    wants = mds.attribute_requirement('https://beta.lobber.se/shibboleth')
    assert wants["required"] == []
    lnamn = [d_to_local_name(mds.attrc, attr) for attr in wants["optional"]]
    assert _eq(lnamn, ['eduPersonPrincipalName', 'mail', 'givenName', 'sn',
                       'eduPersonScopedAffiliation', 'eduPersonEntitlement'])
                
def test_incommon_1():
    mds = MetadataStore(ONTS.values(), ATTRCONV, xmlsec_path,
                        disable_ssl_certificate_validation=True)

    mds.imp(METADATACONF["2"])

    print mds.entities()
    assert mds.entities() == 169
    idps = mds.with_descriptor("idpsso")
    print idps.keys()
    assert len(idps) == 53 # !!!!???? < 10%
    try:
        _ = mds.single_sign_on_service('urn:mace:incommon:uiuc.edu')
    except UnknownPrincipal:
        pass

    idpsso = mds.single_sign_on_service('urn:mace:incommon:alaska.edu')
    assert len(idpsso) == 1
    print idpsso
    assert destinations(idpsso) == ['https://idp.alaska.edu/idp/profile/SAML2/Redirect/SSO']

    sps = mds.with_descriptor("spsso")

    acs_sp = []
    for nam, desc in sps.items():
        if "attribute_consuming_service" in desc:
            acs_sp.append(nam)

    assert len(acs_sp) == 0

    # Look for attribute authorities
    aas = mds.with_descriptor("attribute_authority")

    print aas.keys()
    assert len(aas) == 53

def test_ext_2():
    mds = MetadataStore(ONTS.values(), ATTRCONV, xmlsec_path,
                        disable_ssl_certificate_validation=True)

    mds.imp(METADATACONF["3"])
    # No specific binding defined

    ents = mds.with_descriptor("spsso")
    for binding in [BINDING_SOAP, BINDING_HTTP_POST, BINDING_HTTP_ARTIFACT,
                    BINDING_HTTP_REDIRECT]:
        assert mds.single_logout_service(ents.keys()[0], binding, "spsso")

def test_example():
    mds = MetadataStore(ONTS.values(), ATTRCONV, xmlsec_path,
                        disable_ssl_certificate_validation=True)

    mds.imp(METADATACONF["4"])
    assert len(mds.keys()) == 1
    idps = mds.with_descriptor("idpsso")

    assert idps.keys() == [
            'http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php']
    certs = mds.certs(
            'http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php',
            "idpsso", "signing")
    assert len(certs) == 1

def test_switch_1():
    mds = MetadataStore(ONTS.values(), ATTRCONV, xmlsec_path,
                        disable_ssl_certificate_validation=True)

    mds.imp(METADATACONF["5"])
    assert len(mds.keys()) == 41
    idps = mds.with_descriptor("idpsso")
    print idps.keys()
    idpsso = mds.single_sign_on_service(
                                'https://aai-demo-idp.switch.ch/idp/shibboleth')
    assert len(idpsso) == 1
    print idpsso
    assert destinations(idpsso) == [
        'https://aai-demo-idp.switch.ch/idp/profile/SAML2/Redirect/SSO']
    assert len(idps) == 16
    aas = mds.with_descriptor("attribute_authority")
    print aas.keys()
    aad = aas['https://aai-demo-idp.switch.ch/idp/shibboleth']
    print aad.keys()
    assert len(aad["attribute_authority_descriptor"]) == 1
    assert len(aad["idpsso_descriptor"]) == 1

    sps = mds.with_descriptor("spsso")
    dual = [id for id,ent in idps.items() if id in sps]
    print len(dual)
    assert len(dual) == 0

def test_sp_metadata():
    mds = MetadataStore(ONTS.values(), ATTRCONV, xmlsec_path,
                        disable_ssl_certificate_validation=True)

    mds.imp(METADATACONF["6"])

    assert len(mds.keys()) == 1
    assert mds.keys() == ['urn:mace:umu.se:saml:roland:sp']
    assert _eq(mds['urn:mace:umu.se:saml:roland:sp'].keys(), [
                            'entity_id', '__class__', 'spsso_descriptor'])

    req = mds.attribute_requirement('urn:mace:umu.se:saml:roland:sp')
    print req
    assert len(req["required"]) == 3
    assert len(req["optional"]) == 1
    assert req["optional"][0]["name"] == 'urn:oid:2.5.4.12'
    assert req["optional"][0]["friendly_name"] == 'title'
    assert _eq([n["name"] for n in req["required"]],['urn:oid:2.5.4.4',
                                            'urn:oid:2.5.4.42',
                                            'urn:oid:0.9.2342.19200300.100.1.3'])
    assert _eq([n["friendly_name"] for n in req["required"]],
                ['surName', 'givenName', 'mail'])

##def test_import_external_metadata(xmlsec):
##    md = metadata.MetaData(xmlsec,attrconv=ATTRCONV)
##    mds.import_external_metadata(KALMAR2_URL, KALMAR2_CERT)
##
##    print len(mds.entity)
##    assert len(mds.entity) > 20
##    idps = dict([
##        (id,ent["idpsso"]) for id,ent in mds.entity.items() if "idpsso" in ent])
##    print idps.keys()
##    assert len(idps) > 1
##    assert "https://idp.umu.se/saml2/idp/metadata.php" in idps
#
## ------------ Constructing metadata ----------------------------------------
#
#def test_construct_contact():
#    c = make_instance(mds.ContactPerson, {
#        "given_name":"Roland",
#        "sur_name": "Hedberg",
#        "email_address": "roland@catalogix.se",
#    })
#    print c
#    assert c.given_name.text == "Roland"
#    assert c.sur_name.text == "Hedberg"
#    assert c.email_address[0].text == "roland@catalogix.se"
#    assert _eq(c.keyswv(), ["given_name","sur_name","email_address"])
#
#
#def test_construct_organisation():
#    c = make_instance( mds.Organization, {
#            "organization_name": ["Example Co.",
#                    {"text":"Exempel AB", "lang":"se"}],
#            "organization_url": "http://www.example.com/"
#        })
#
#    assert _eq(c.keyswv(), ["organization_name","organization_url"])
#    assert len(c.organization_name) == 2
#    org_names = [on.text for on in c.organization_name]
#    assert _eq(org_names,["Exempel AB","Example Co."])
#    assert len(c.organization_url) == 1
#
#def test_construct_entity_descr_1():
#    ed = make_instance(mds.EntityDescriptor,
#        {"organization": {
#            "organization_name":"Catalogix",
#            "organization_url": "http://www.catalogix.se/"},
#         "entity_id": "urn:mace:catalogix.se:sp1",
#        })
#
#    assert ed.entity_id == "urn:mace:catalogix.se:sp1"
#    org = ed.organization
#    assert org
#    assert _eq(org.keyswv(), ["organization_name","organization_url"])
#    assert len(org.organization_name) == 1
#    assert org.organization_name[0].text == "Catalogix"
#    assert org.organization_url[0].text == "http://www.catalogix.se/"
#
#def test_construct_entity_descr_2():
#    ed = make_instance(mds.EntityDescriptor,
#        {"organization": {
#            "organization_name":"Catalogix",
#            "organization_url": "http://www.catalogix.se/"},
#         "entity_id": "urn:mace:catalogix.se:sp1",
#         "contact_person": {
#            "given_name":"Roland",
#            "sur_name": "Hedberg",
#            "email_address": "roland@catalogix.se",
#            }
#        })
#
#    assert _eq(ed.keyswv(), ["entity_id", "contact_person", "organization"])
#    assert ed.entity_id == "urn:mace:catalogix.se:sp1"
#    org = ed.organization
#    assert org
#    assert _eq(org.keyswv(), ["organization_name", "organization_url"])
#    assert len(org.organization_name) == 1
#    assert org.organization_name[0].text == "Catalogix"
#    assert org.organization_url[0].text == "http://www.catalogix.se/"
#    assert len(ed.contact_person) == 1
#    c = ed.contact_person[0]
#    assert c.given_name.text == "Roland"
#    assert c.sur_name.text == "Hedberg"
#    assert c.email_address[0].text == "roland@catalogix.se"
#    assert _eq(c.keyswv(), ["given_name","sur_name","email_address"])
#
#def test_construct_key_descriptor():
#    cert = "".join(_read_lines("test.pem")[1:-1]).strip()
#    spec = {
#        "use": "signing",
#        "key_info" : {
#            "x509_data": {
#                "x509_certificate": cert
#            }
#        }
#    }
#    kd = make_instance(mds.KeyDescriptor, spec)
#    assert _eq(kd.keyswv(), ["use", "key_info"])
#    assert kd.use == "signing"
#    ki = kd.key_info
#    assert _eq(ki.keyswv(), ["x509_data"])
#    assert len(ki.x509_data) == 1
#    data = ki.x509_data[0]
#    assert _eq(data.keyswv(), ["x509_certificate"])
#    assert data.x509_certificate
#    assert len(data.x509_certificate.text.strip()) == len(cert)
#
#def test_construct_key_descriptor_with_key_name():
#    cert = "".join(_read_lines("test.pem")[1:-1]).strip()
#    spec = {
#        "use": "signing",
#        "key_info" : {
#            "key_name": "example.com",
#            "x509_data": {
#                "x509_certificate": cert
#            }
#        }
#    }
#    kd = make_instance(mds.KeyDescriptor, spec)
#    assert _eq(kd.keyswv(), ["use", "key_info"])
#    assert kd.use == "signing"
#    ki = kd.key_info
#    assert _eq(ki.keyswv(), ["x509_data", "key_name"])
#    assert len(ki.key_name) == 1
#    assert ki.key_name[0].text.strip() == "example.com"
#    assert len(ki.x509_data) == 1
#    data = ki.x509_data[0]
#    assert _eq(data.keyswv(), ["x509_certificate"])
#    assert data.x509_certificate
#    assert len(data.x509_certificate.text.strip()) == len(cert)
#
#def test_construct_AttributeAuthorityDescriptor():
#    aad = make_instance(
#            mds.AttributeAuthorityDescriptor, {
#                "valid_until": time_util.in_a_while(30), # 30 days from now
#                "id": "aad.example.com",
#                "protocol_support_enumeration": SAML2_NAMESPACE,
#                "attribute_service": {
#                    "binding": BINDING_SOAP,
#                    "location": "http://example.com:6543/saml2/aad",
#                },
#                "name_id_format":[
#                    NAMEID_FORMAT_TRANSIENT,
#                ],
#                "key_descriptor": {
#                    "use": "signing",
#                    "key_info" : {
#                        "key_name": "example.com",
#                    }
#                }
#            })
#
#    print aad
#    assert _eq(aad.keyswv(),["valid_until", "id", "attribute_service",
#                            "name_id_format", "key_descriptor",
#                            "protocol_support_enumeration"])
#    assert time_util.str_to_time(aad.valid_until)
#    assert aad.id == "aad.example.com"
#    assert aad.protocol_support_enumeration == SAML2_NAMESPACE
#    assert len(aad.attribute_service) == 1
#    atsr = aad.attribute_service[0]
#    assert _eq(atsr.keyswv(),["binding", "location"])
#    assert atsr.binding == BINDING_SOAP
#    assert atsr.location == "http://example.com:6543/saml2/aad"
#    assert len(aad.name_id_format) == 1
#    nif = aad.name_id_format[0]
#    assert nif.text.strip() == NAMEID_FORMAT_TRANSIENT
#    assert len(aad.key_descriptor) == 1
#    kdesc = aad.key_descriptor[0]
#    assert kdesc.use == "signing"
#    assert kdesc.key_info.key_name[0].text.strip() == "example.com"
#
#STATUS_RESULT = """<?xml version='1.0' encoding='UTF-8'?>
#<ns0:Status xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal" /></ns0:StatusCode><ns0:StatusMessage>Error resolving principal</ns0:StatusMessage></ns0:Status>"""
#
#def test_status():
#    input = {
#        "status_code": {
#            "value": samlp.STATUS_RESPONDER,
#            "status_code":
#                {
#                "value": samlp.STATUS_UNKNOWN_PRINCIPAL,
#                },
#        },
#        "status_message": "Error resolving principal",
#        }
#    status_text = "%s" % make_instance( samlp.Status, input)
#    assert status_text == STATUS_RESULT
#
#def test_attributes():
#    required = ["surname", "givenname", "edupersonaffiliation"]
#    ra = metadata.do_requested_attribute(required, ATTRCONV, "True")
#    print ra
#    assert ra
#    assert len(ra) == 3
#    for i in range(3):
#        assert isinstance(ra[i], mds.RequestedAttribute)
#        assert ra[i].name_format == NAME_FORMAT_URI
#        assert ra[i].attribute_value == []
#        assert ra[i].is_required == "True"
#    assert ra[0].friendly_name == "surname"
#    assert ra[0].name == 'urn:oid:2.5.4.4'
#
#def test_extend():
#    md = metadata.MetaData(attrconv=ATTRCONV)
#    mds.import_metadata(_fix_valid_until(_read_file("extended.xml")), "-")
#
#    signcerts = mds.certs("https://coip-test.sunet.se/shibboleth", "signing")
#    assert len(signcerts) == 1
#    enccerts = mds.certs("https://coip-test.sunet.se/shibboleth", "encryption")
#    assert len(enccerts) == 1
#    assert signcerts[0] == enccerts[0]
#
#def test_ui_info():
#    md = metadata.MetaData(attrconv=ATTRCONV)
#    mds.import_metadata(_fix_valid_until(_read_file("idp_uiinfo.xml")), "-")
#    loc = mds.single_sign_on_services_with_uiinfo(
#                                            "http://example.com/saml2/idp.xml")
#    assert len(loc) == 1
#    assert loc[0][0] == "http://example.com/saml2/"
#    assert len(loc[0][1]) == 1
#    ui_info = loc[0][1][0]
#    print ui_info
#    assert ui_info.description[0].text == "Exempel bolag"
#
#def test_pdp():
#    md = metadata.MetaData(attrconv=ATTRCONV)
#    mds.import_metadata(_fix_valid_until(_read_file("pdp_meta.xml")), "-")
#
#    assert md
#
#    pdps = mds.pdp_services("http://www.example.org/pysaml2/")
#
#    assert len(pdps) == 1
#    pdp = pdps[0]
#    assert len(pdp.authz_service) == 1
#    assert pdp.authz_service[0].location == "http://www.example.org/pysaml2/authz"
#    assert pdp.authz_service[0].binding == BINDING_SOAP
#    endpoints = mds.authz_service("http://www.example.org/pysaml2/")
#    assert len(endpoints) == 1
#    assert endpoints[0] == "http://www.example.org/pysaml2/authz"