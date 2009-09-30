from saml2 import metadata

SWAMI_METADATA = "urn-mace-swami.se-swamid-test-1.0-metadata.xml"

def test_swami_1():
    idps = metadata.import_metadata(open(SWAMI_METADATA).read())
    print len(idps)
    assert len(idps) == 1
    print idps.keys()
    assert idps.keys() == ['https://idp.umu.se/saml2/idp/SSOService.php']
    
    (odnl,certs) = idps['https://idp.umu.se/saml2/idp/SSOService.php']
    
    c_mngr = metadata.load_certs_to_manager(certs)
    assert c_mngr
    
