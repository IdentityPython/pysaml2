from saml2.discovery import DiscoveryServer

__author__ = 'rolandh'


def test_verify():
    ds = DiscoveryServer(config_file="disco_conf")
    assert ds
    assert ds.verify_sp_in_metadata("urn:mace:example.com:saml:roland:sp")
