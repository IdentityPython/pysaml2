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

from pathutils import full_path, xmlsec_path


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

ATTRCONV = ac_factory(full_path("attributemaps"))

METADATACONF = {
    "1": {
        "local": [full_path("swamid-1.0.xml")]
    },
    "2": {
        "local": [full_path("InCommon-metadata.xml")]
    },
    "3": {
        "local": [full_path("extended.xml")]
    },
    "7": {
        "local": [full_path("metadata_sp_1.xml"),
                  full_path("InCommon-metadata.xml")],
        "remote": [
            {"url": "https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2",
             "cert": full_path("kalmar2.pem")}]
    },
    "4": {
        "local": [full_path("metadata_example.xml")]
    },
    "5": {
        "local": [full_path("metadata.aaitest.xml")]
    },
    "6": {
        "local": [full_path("metasp.xml")]
    }
}


def _eq(l1, l2):
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
    assert len(mds) == 1  # One source
    idps = mds.with_descriptor("idpsso")
    assert idps.keys()
    idpsso = mds.single_sign_on_service(UMU_IDP)
    assert len(idpsso) == 1
    assert destinations(idpsso) == [
        'https://idp.umu.se/saml2/idp/SSOService.php']

    _name = name(mds[UMU_IDP])
    assert _name == u'Umeå University (SAML2)'
    certs = mds.certs(UMU_IDP, "idpsso", "signing")
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
    assert len(idps) == 53  # !!!!???? < 10%
    try:
        _ = mds.single_sign_on_service('urn:mace:incommon:uiuc.edu')
    except UnknownPrincipal:
        pass

    idpsso = mds.single_sign_on_service('urn:mace:incommon:alaska.edu')
    assert len(idpsso) == 1
    print idpsso
    assert destinations(idpsso) == [
        'https://idp.alaska.edu/idp/profile/SAML2/Redirect/SSO']

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
    dual = [eid for eid, ent in idps.items() if eid in sps]
    print len(dual)
    assert len(dual) == 0


def test_sp_metadata():
    mds = MetadataStore(ONTS.values(), ATTRCONV, xmlsec_path,
                        disable_ssl_certificate_validation=True)

    mds.imp(METADATACONF["6"])

    assert len(mds.keys()) == 1
    assert mds.keys() == ['urn:mace:umu.se:saml:roland:sp']
    assert _eq(mds['urn:mace:umu.se:saml:roland:sp'].keys(),
               ['entity_id', '__class__', 'spsso_descriptor'])

    req = mds.attribute_requirement('urn:mace:umu.se:saml:roland:sp')
    print req
    assert len(req["required"]) == 3
    assert len(req["optional"]) == 1
    assert req["optional"][0]["name"] == 'urn:oid:2.5.4.12'
    assert req["optional"][0]["friendly_name"] == 'title'
    assert _eq([n["name"] for n in req["required"]],
               ['urn:oid:2.5.4.4', 'urn:oid:2.5.4.42',
                'urn:oid:0.9.2342.19200300.100.1.3'])
    assert _eq([n["friendly_name"] for n in req["required"]],
               ['surName', 'givenName', 'mail'])
