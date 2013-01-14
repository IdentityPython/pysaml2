from urlparse import parse_qs
from urlparse import urlparse
from saml2.samlp import AuthnRequest
from saml2.samlp import NameIDPolicy
from saml2.saml import AUTHN_PASSWORD
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.client import Saml2Client
from saml2.server import Server

__author__ = 'rolandh'

TAG1 = "name=\"SAMLRequest\" value="

def get_msg(hinfo, binding):
    if binding == BINDING_SOAP:
        xmlstr = hinfo["data"]
    elif binding == BINDING_HTTP_POST:
        _inp = hinfo["data"][3]
        i = _inp.find(TAG1)
        i += len(TAG1) + 1
        j = _inp.find('"', i)
        xmlstr = _inp[i:j]
    else: # BINDING_HTTP_REDIRECT
        parts = urlparse(hinfo["headers"][0][1])
        xmlstr = parse_qs(parts.query)["SAMLRequest"][0]

    return xmlstr

def test_basic_flow():
    sp = Saml2Client(config_file="servera_conf")
    idp = Server(config_file="idp_all_conf")

    # -------- @IDP -------------

    relay_state = "FOO"
    # -- dummy request ---
    orig_req = AuthnRequest(issuer=sp._issuer(),
                            name_id_policy=NameIDPolicy(allow_create="true",
                                                        format=NAMEID_FORMAT_TRANSIENT))

    # == Create an AuthnRequest response

    name_id = idp.ident.transient_nameid(sp.config.entityid, "id12")
    binding, destination = idp.pick_binding("assertion_consumer_service",
                                            entity_id=sp.config.entityid)
    resp = idp.create_authn_response({"eduPersonEntitlement": "Short stop",
                                      "surName": "Jeter",
                                      "givenName": "Derek",
                                      "mail": "derek.jeter@nyy.mlb.com",
                                      "title": "The man"},
                                     "id-123456789",
                                     destination,
                                     sp.config.entityid,
                                     name_id=name_id,
                                     authn=(AUTHN_PASSWORD,
                                            "http://www.example.com/login"))

    hinfo = idp.apply_binding(binding, "%s" % resp, destination, relay_state)

    # --------- @SP -------------

    xmlstr = get_msg(hinfo, binding)

    aresp = sp.parse_authn_request_response(xmlstr, binding,
                                            {resp.in_response_to :"/"})

    # == Look for assertion X

    asid = aresp.assertion.id

    binding, destination = sp.pick_binding("assertion_id_request_service",
                                           entity_id=idp.config.entityid)

    _req = sp.create_assertion_id_request([asid], destination)

    hinfo = sp.apply_binding(binding, "%s" % _req, destination,
                             "realy_stat")

    # ---------- @IDP ------------

    xmlstr = get_msg(hinfo, binding)

    rr = idp.parse_assertion_id_request(xmlstr, binding)

    print rr

    # == construct response

    aids = [x.text for x in rr.message.assertion_id_ref]
    resp_args = idp.response_args(rr.message)

    resp = idp.create_assertion_id_request_response(aids, **resp_args)

    hinfo = idp.apply_binding(binding, "%s" % resp, None, "", "SAMLResponse")

    # ----------- @SP -------------

    xmlstr = get_msg(hinfo, binding)

    final = sp.parse_assertion_id_request_response(xmlstr, binding)

    print final