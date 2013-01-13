import base64
from hashlib import sha1
import urlparse
from saml2.saml import AUTHN_PASSWORD
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.pack import http_redirect_message
from saml2.client import Saml2Client

from saml2.entity import create_artifact
from saml2.entity import ARTIFACT_TYPECODE
from saml2.s_utils import sid
from saml2.server import Server

__author__ = 'rolandh'

def test_create_artifact():
    b64art = create_artifact("http://sp.example.com/saml.xml",
                             "aabbccddeeffgghhiijj")

    art = base64.b64decode(b64art)

    assert art[:2] == '\x00\x04'
    assert int(art[2:4]) == 0

    s = sha1("http://sp.example.com/saml.xml")
    assert art[4:24] == s.digest()

SP = 'urn:mace:example.com:saml:roland:sp'

def test_create_artifact_resolve():
    b64art = create_artifact(SP, "aabbccddeeffgghhiijj", 1)
    artifact = base64.b64decode(b64art)

    #assert artifact[:2] == '\x00\x04'
    #assert int(artifact[2:4]) == 0
    #
    s = sha1(SP)
    assert artifact[4:24] == s.digest()

    idp = Server(config_file="idp_all_conf")

    typecode = artifact[:2]
    assert typecode == ARTIFACT_TYPECODE

    destination = idp.artifact2destination(b64art, "spsso")

    msg = idp.create_artifact_resolve(b64art, destination, sid())

    print msg

    args = idp.use_soap(msg, destination, None, False)

    sp = Saml2Client(config_file="servera_conf")

    ar = sp.parse_artifact_resolve(args["data"])

    print ar

    assert ar.artifact.text == b64art

def test_artifact_flow():
    sp = Saml2Client(config_file="servera_conf")
    idp = Server(config_file="idp_all_conf")

    # ======= SP ==========
    # original request
    srvs = sp.metadata.single_sign_on_service(idp.config.entityid,
                                              BINDING_HTTP_REDIRECT)

    destination=srvs[0]["location"]
    req = sp.create_authn_request(destination, id = "id1")

    # create the artifact
    artifact = sp.use_artifact(req, 1)
    # HTTP args for sending the message with the artifact
    args = http_redirect_message(artifact, destination, "really", "SAMLart")

    # ====== IDP =========
    # simulating the IDP receiver
    artifact2 = None
    for item, val in args["headers"]:
        if item == "Location":
            part = urlparse.urlparse(val)
            query = urlparse.parse_qs(part.query)
            artifact2 = query["SAMLart"][0]

    # Got an artifact, now want to get the original request
    destination = idp.artifact2destination(artifact2, "spsso")
    msg = idp.create_artifact_resolve(artifact2, destination, sid())

    args = idp.use_soap(msg, destination, None, False)

    # ======== SP ==========

    ar = sp.parse_artifact_resolve(args["data"])

    print ar

    assert ar.artifact.text == artifact

    oreq = sp.artifact[ar.artifact.text]
    # Should be the same as req above

    msg = sp.create_artifact_response(ar, ar.artifact.text)
    args = sp.use_soap(msg, destination)

    # ========== IDP ============

    spreq = idp.parse_artifact_resolve_response(args["data"])

    # should be the same as req above

    print spreq

    assert spreq.id == req.id

    # That was one way
    # ------------------------------------
    # Now for the other

    name_id = idp.ident.transient_nameid(sp.config.entityid, "derek")

    resp_args = idp.response_args(spreq, [BINDING_HTTP_POST])

    response = idp.create_authn_response({"eduPersonEntitlement": "Short stop",
                                          "surName": "Jeter", "givenName": "Derek",
                                          "mail": "derek.jeter@nyy.mlb.com",
                                          "title": "The man"},
                                         name_id=name_id,
                                         authn=(AUTHN_PASSWORD,
                                                "http://www.example.com/login"),
                                         **resp_args)

    print response

    artifact = idp.use_artifact(response, 1)
    args = http_redirect_message(artifact, resp_args["destination"], "really2",
                                 "SAMLart")

    artifact2=None
    for item, val in args["headers"]:
        if item == "Location":
            part = urlparse.urlparse(val)
            query = urlparse.parse_qs(part.query)
            artifact2 = query["SAMLart"][0]

    # ========== SP =========

    destination = sp.artifact2destination(artifact2, "idpsso")

    msg = sp.create_artifact_resolve(artifact2, destination, sid())

    print msg

    args = sp.use_soap(msg, destination, None, False)

    # ======== IDP ==========

    ar = idp.parse_artifact_resolve(args["data"])

    print ar

    assert ar.artifact.text == artifact

    oreq = idp.artifact[ar.artifact.text]
    # Should be the same as req above

    msg = idp.create_artifact_response(ar, ar.artifact.text)
    args = idp.use_soap(msg, destination)

    # ========== SP ============

    sp_resp = sp.parse_artifact_resolve_response(args["data"])


    assert sp_resp.id == response.id
