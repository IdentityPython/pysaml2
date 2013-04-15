from saml2 import BINDING_HTTP_POST
from saml2.saml import AUTHN_PASSWORD
from saml2.client import Saml2Client
from saml2.server import Server

__author__ = 'rolandh'


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_flow():
    sp = Saml2Client(config_file="servera_conf")
    idp1 = Server(config_file="idp_conf_mdb")
    idp2 = Server(config_file="idp_conf_mdb")

    # clean out database
    idp1.ident.mdb.db.drop()

    # -- dummy request ---
    orig_req = sp.create_authn_request(idp1.config.entityid)

    # == Create an AuthnRequest response

    rinfo = idp1.response_args(orig_req, [BINDING_HTTP_POST])

    #name_id = idp1.ident.transient_nameid("id12", rinfo["sp_entity_id"])
    resp = idp1.create_authn_response({"eduPersonEntitlement": "Short stop",
                                      "surName": "Jeter",
                                      "givenName": "Derek",
                                      "mail": "derek.jeter@nyy.mlb.com",
                                      "title": "The man"},
                                      userid="jeter",
                                      authn=(AUTHN_PASSWORD,
                                             "http://www.example.com/login"),
                                      **rinfo)

    # What's stored away is the assertion
    a_info = idp2.session_db.get_assertion(resp.assertion.id)
    # Make sure what I got back from MongoDB is the same as I put in
    assert a_info["assertion"] == resp.assertion

    # By subject
    nid = resp.assertion.subject.name_id
    _assertion = idp2.session_db.get_assertions_by_subject(nid)
    assert len(_assertion) == 1
    assert _assertion[0] == resp.assertion

    nids = idp2.ident.find_nameid("jeter")
    assert len(nids) == 1

if __name__ == "__main__":
    test_flow()
