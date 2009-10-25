from saml2 import metadata
from saml2 import md

SWAMI_METADATA = "tests/urn-mace-swami.se-swamid-test-1.0-metadata.xml"
INCOMMON_METADATA = "tests/InCommon-metadata.xml"
EXAMPLE_METADATA = "tests/metadata_example.xml"
SWITCH_METADATA = "tests/metadata.aaitest.xml"

def _eq(l1,l2):
    return set(l1) == set(l2)
    
def test_swami_1():
    md = metadata.MetaData()
    md.import_metadata(open(SWAMI_METADATA).read())
    print len(md.idp)
    assert len(md.idp) == 1
    print md.idp.keys()
    assert md.idp.keys() == ['https://idp.umu.se/saml2/idp/metadata.php']
    idp_sso = md.single_sign_on_services('https://idp.umu.se/saml2/idp/metadata.php')
    assert len(idp_sso) == 1
    assert idp_sso == ['https://idp.umu.se/saml2/idp/SSOService.php']
    ssocerts =  md.certs('https://idp.umu.se/saml2/idp/SSOService.php')
    print ssocerts
    assert len(ssocerts) == 1
    
def test_incommon_1():
    md = metadata.MetaData()
    md.import_metadata(open(INCOMMON_METADATA).read())
    print len(md.idp)
    assert len(md.idp) == 35
    print md.idp.keys()
    idp_sso = md.single_sign_on_services('urn:mace:incommon:uiuc.edu')
    assert idp_sso == []
    idp_sso = md.single_sign_on_services('urn:mace:incommon:alaska.edu')
    assert len(idp_sso) == 1
    print idp_sso
    assert idp_sso == ['https://idp.alaska.edu/idp/profile/SAML2/Redirect/SSO']
    redirect_idps = [
        eid for eid in md.idp.keys() if len( md.single_sign_on_services(eid))]
    print redirect_idps
    assert len(redirect_idps) == 8 # !!!!????

def test_example():
    md = metadata.MetaData()
    md.import_metadata(open(EXAMPLE_METADATA).read())
    print len(md.idp)
    assert len(md.idp) == 1
    print md.idp.keys()
    assert md.idp.keys() == [
            'http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php']
    certs = md.certs(
            'http://xenosmilus.umdc.umu.se/simplesaml/saml2/idp/metadata.php')
    assert len(certs) == 1
    assert isinstance(certs[0], tuple)
    assert len(certs[0]) == 2
        
def test_switch_1():
    md = metadata.MetaData()
    md.import_metadata(open(SWITCH_METADATA).read())
    print len(md.idp)
    assert len(md.idp) == 16
    print len(md.aad)
    assert len(md.aad) == 16
    print md.idp.keys()
    idp_sso = md.single_sign_on_services(
        'https://aai-demo-idp.switch.ch/idp/shibboleth')
    assert len(idp_sso) == 1
    print idp_sso
    assert idp_sso == [
        'https://aai-demo-idp.switch.ch/idp/profile/SAML2/Redirect/SSO']
    redirect_idps = [
        eid for eid in md.idp.keys() if len( md.single_sign_on_services(eid))]
    print redirect_idps
    assert len(redirect_idps) == 16
    print md.aad.keys()
    aads = md.aad['https://aai-demo-idp.switch.ch/idp/shibboleth']
    assert len(aads) == 1
    aad = aads[0]
    assert len(aad.attribute_service) == 1
    assert len(aad.name_id_format) == 2

def test_construct_contact():
    c = metadata.make_contact_person({
        "given_name":"Roland",
        "sur_name": "Hedberg",
        "email_address": "roland@catalogix.se",
    })
    print c
    assert c.given_name.text == "Roland"
    assert c.sur_name.text == "Hedberg"
    assert c.email_address[0].text == "roland@catalogix.se"    
    assert _eq(c.keyswv(), ["given_name","sur_name","email_address"])

def test_construct_organisation_name():
    o = md.Organization()
    metadata._make_vals(o, {"text":"Exempel AB", "lang":"se"}, 
            "organization_name", md.OrganizationName)
    assert str(o) == """<?xml version='1.0' encoding='UTF-8'?>
<ns0:Organization xmlns:ns0="urn:oasis:names:tc:SAML:2.0:metadata"><ns0:OrganizationName ns1:lang="se" xmlns:ns1="http:#www.w3.org/XML/1998/namespace">Exempel AB</ns0:OrganizationName></ns0:Organization>"""
            
def test_construct_organisation():
    c = metadata.make_xyz( md.Organization, {
            "organization_name": ["Example Co.",
                    {"text":"Exempel AB", "lang":"se"}],
            "organization_url": "http://www.example.com/"
        })
        
    assert _eq(c.keyswv(), ["organization_name","organization_url"])
    assert len(c.organization_name) == 2
    org_names = [on.text for on in c.organization_name]
    assert _eq(org_names,["Exempel AB","Example Co."])
    assert len(c.organization_url) == 1
    
def test_construct_entity_descr_1():
    ed = metadata.make_xyz(md.EntityDescriptor,
        {"organization": {
            "organization_name":"Catalogix", 
            "organization_url": "http://www.catalogix.se/"},
         "entity_id": "urn:mace:catalogix.se:sp1",   
        })

    assert ed.entity_id == "urn:mace:catalogix.se:sp1"
    org = ed.organization
    assert _eq(org.keyswv(), ["organization_name","organization_url"])
    assert len(org.organization_name) == 1
    assert org.organization_name[0].text == "Catalogix"
    assert org.organization_url[0].text == "http://www.catalogix.se/"

def test_construct_entity_descr_2():
    ed = metadata.make_xyz(md.EntityDescriptor,
        {"organization": {
            "organization_name":"Catalogix", 
            "organization_url": "http://www.catalogix.se/"},
         "entity_id": "urn:mace:catalogix.se:sp1",
         "contact_person": {
            "given_name":"Roland",
            "sur_name": "Hedberg",
            "email_address": "roland@catalogix.se",
            }   
        })

    assert _eq(ed.keyswv(), ["entity_id", "contact_person", "organization"])
    assert ed.entity_id == "urn:mace:catalogix.se:sp1"
    org = ed.organization
    assert _eq(org.keyswv(), ["organization_name", "organization_url"])
    assert len(org.organization_name) == 1
    assert org.organization_name[0].text == "Catalogix"
    assert org.organization_url[0].text == "http://www.catalogix.se/"
    
