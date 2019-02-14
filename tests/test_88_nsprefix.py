from saml2_tophat.saml import NAMEID_FORMAT_TRANSIENT
from saml2_tophat.client import Saml2Client
from saml2_tophat import config, BINDING_HTTP_POST
from saml2_tophat import saml
from saml2_tophat import samlp

__author__ = 'roland'


def test_nsprefix():
    status_message = samlp.StatusMessage()
    status_message.text = "OK"

    txt = "%s" % status_message

    assert "ns0:StatusMessage" in txt

    status_message.register_prefix({"saml2_tophat": saml.NAMESPACE,
                                    "saml2p": samlp.NAMESPACE})

    txt = "%s" % status_message

    assert "saml2p:StatusMessage" in txt


def test_nsprefix2():
    conf = config.SPConfig()
    conf.load_file("servera_conf")
    client = Saml2Client(conf)

    selected_idp = "urn:mace:example.com:saml:roland:idp"

    destination = client._sso_location(selected_idp, BINDING_HTTP_POST)

    reqid, req = client.create_authn_request(
        destination, nameid_format=NAMEID_FORMAT_TRANSIENT,
        nsprefix={"saml2_tophat": saml.NAMESPACE, "saml2p": samlp.NAMESPACE})

    txt = "%s" % req

    assert "saml2p:AuthnRequest" in txt
    assert "saml2_tophat:Issuer" in txt

if __name__ == "__main__":
    test_nsprefix2()
