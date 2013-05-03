from saml2.pack import http_redirect_message
from saml2.sigver import verify_redirect_signature
from saml2.sigver import RSA_SHA1
from saml2.server import Server
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.sigver import rsa_load
from urlparse import parse_qs

from pathutils import dotname

__author__ = 'rolandh'

idp = Server(config_file=dotname("idp_all_conf"))

conf = SPConfig()
conf.load_file(dotname("servera_conf"))
sp = Saml2Client(conf)


def test():
    srvs = sp.metadata.single_sign_on_service(idp.config.entityid,
                                              BINDING_HTTP_REDIRECT)

    destination = srvs[0]["location"]
    req = sp.create_authn_request(destination, id="id1")

    try:
        key = sp.sec.key
    except AttributeError:
        key = rsa_load(sp.sec.key_file)

    info = http_redirect_message(req, destination, relay_state="RS",
                                 typ="SAMLRequest", sigalg=RSA_SHA1, key=key)

    verified_ok = False

    for param, val in info["headers"]:
        if param == "Location":
            _dict = parse_qs(val.split("?")[1])
            _certs = idp.metadata.certs(sp.config.entityid, "any", "signing")
            for cert in _certs:
                if verify_redirect_signature(_dict, cert):
                    verified_ok = True

    assert verified_ok
