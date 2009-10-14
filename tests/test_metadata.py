from saml2 import metadata

SWAMI_METADATA = "tests/urn-mace-swami.se-swamid-test-1.0-metadata.xml"
INCOMMON_METADATA = "tests/InCommon-metadata.xml"

def test_swami_1():
    md = metadata.MetaData()
    md.import_metadata(open(SWAMI_METADATA).read())
    print len(md)
    assert len(md) == 1
    print md.keys()
    assert md.keys() == ['https://idp.umu.se/saml2/idp/metadata.php']
    idp_sso = md.single_sign_on_services('https://idp.umu.se/saml2/idp/metadata.php')
    assert len(idp_sso) == 1
    assert idp_sso == ['https://idp.umu.se/saml2/idp/SSOService.php']
    ssocerts =  md.certs('https://idp.umu.se/saml2/idp/SSOService.php')
    print ssocerts
    assert len(ssocerts) == 1
    
def test_incommon_1():
    md = metadata.MetaData()
    md.import_metadata(open(INCOMMON_METADATA).read())
    print len(md)
    assert len(md) == 35
    print md.keys()
    idp_sso = md.single_sign_on_services('urn:mace:incommon:uiuc.edu')
    assert idp_sso == []
    idp_sso = md.single_sign_on_services('urn:mace:incommon:alaska.edu')
    assert len(idp_sso) == 1
    print idp_sso
    assert idp_sso == ['https://idp.alaska.edu/idp/profile/SAML2/Redirect/SSO']
    redirect_idps = [eid for eid in md.keys() if len( md.single_sign_on_services(eid))]
    print redirect_idps
    assert len(redirect_idps) == 8 # !!!!????
        