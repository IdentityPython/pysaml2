from saml2.saml import AUTHN_PASSWORD
from saml2.httpbase import set_list2dict
from saml2.profile.ecp import RelayState
from saml2.profile.paos import Request
from saml2.server import Server
from saml2.samlp import Response
from saml2.samlp import STATUS_SUCCESS
from saml2.samlp import AuthnRequest
from saml2 import ecp_client
from saml2 import BINDING_SOAP
from saml2 import BINDING_PAOS
from saml2 import create_class_from_xml_string

from saml2.profile import ecp as ecp_prof
from saml2.client import Saml2Client

__author__ = 'rolandh'


def _eq(l1, l2):
    if len(l1) == len(l2):
        return set(l1) == set(l2)
    else:
        return len(l1) == len(l2)

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

class DummyResponse(object):
    def __init__(self, headers):
        self.headers = headers

def test_complete_flow():
    client = ecp_client.Client("user", "password", metadata_file="idp_all.xml",
                               xmlsec_binary=xmlsec_path)

    sp = Saml2Client(config_file="servera_conf")
    idp = Server(config_file="idp_all_conf")

    IDP_ENTITY_ID = idp.config.entityid
    #SP_ENTITY_ID = sp.config.entityid

    # ------------ @Client -----------------------------

    headers = client.add_paos_headers([])

    assert len(headers) == 2

    # ------------ @SP -----------------------------

    response = DummyResponse(set_list2dict(headers))

    assert sp.can_handle_ecp_response(response)

    id, message = sp.create_ecp_authn_request(IDP_ENTITY_ID, relay_state="XYZ")

    # ------------ @Client -----------------------------

    respdict = client.parse_soap_message(message)

    cargs = client.parse_sp_ecp_response(respdict)

    assert isinstance(respdict["body"], AuthnRequest)
    assert len(respdict["header"]) == 2
    item0 = respdict["header"][0]
    assert isinstance(item0, Request) or isinstance(item0, RelayState)

    destination = respdict["body"].destination

    ht_args = client.apply_binding(BINDING_SOAP, respdict["body"], destination)

    # Time to send to the IDP
    # ----------- @IDP -------------------------------

    req = idp.parse_authn_request(ht_args["data"], BINDING_SOAP)

    assert isinstance(req.message, AuthnRequest)

    # create Response and return in the SOAP response
    sp_entity_id = req.sender()

    name_id = idp.ident.transient_nameid( "id12", sp.config.entityid)
    binding, destination = idp.pick_binding("assertion_consumer_service",
                                            [BINDING_PAOS],
                                            entity_id=sp_entity_id)

    resp = idp.create_ecp_authn_request_response(destination,
                                 {
                                     "eduPersonEntitlement": "Short stop",
                                     "surName": "Jeter",
                                     "givenName": "Derek",
                                     "mail": "derek.jeter@nyy.mlb.com",
                                     "title": "The man"
                                 },
                                 req.message.id, destination, sp_entity_id,
                                 name_id=name_id, authn=(AUTHN_PASSWORD,
                                                         "http://www.example.com/login"))

    # ------------ @Client -----------------------------
    # The client got the response from the IDP repackage and send it to the SP

    respdict = client.parse_soap_message(resp)
    idp_response = respdict["body"]

    assert isinstance(idp_response, Response)
    assert len(respdict["header"]) == 1

    _ecp_response = None
    for item in respdict["header"]:
        if item.c_tag == "Response" and item.c_namespace == ecp_prof.NAMESPACE:
            _ecp_response = item

    #_acs_url = _ecp_response.assertion_consumer_service_url

    # done phase2 at the client

    ht_args = client.use_soap(idp_response, cargs["rc_url"],
                              [cargs["relay_state"]])

    print ht_args

    # ------------ @SP -----------------------------

    respdict = sp.unpack_soap_message(ht_args["data"])

    # verify the relay_state

    for header in respdict["header"]:
        inst = create_class_from_xml_string(RelayState, header)
        if isinstance(inst, RelayState):
            assert inst.text == "XYZ"

    # parse the response

    resp = sp.parse_authn_request_response(respdict["body"], None, {id: "/"})

    print resp.response

    assert resp.response.destination == "http://lingon.catalogix.se:8087/paos"
    assert resp.response.status.status_code.value == STATUS_SUCCESS
