__author__ = 'rolandh'

from saml2 import soap
from saml2 import samlp
from saml2 import config
from saml2 import ecp

from saml2.profile import ecp as ecp_prof
from saml2.profile import paos
from saml2.client import Saml2Client

def _eq(l1, l2):
    if len(l1) == len(l2):
        return set(l1) == set(l2)
    else:
        return len(l1) == len(l2)

def test_multiple_soap_headers():
    xml_str = open("ecp_soap.xml").read()
    res = soap.class_instances_from_soap_enveloped_saml_thingies(xml_str,
                                                                 [ecp_prof,
                                                                  paos,
                                                                  samlp])

    assert res["body"].c_tag == "AuthnRequest"

    assert len(res["header"]) == 3
    headers = ["{%s}%s" % (i.c_namespace, i.c_tag) for i in res["header"]]
    print headers
    assert _eq(headers,['{urn:liberty:paos:2003-08}Request',
                        '{urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp}Request',
                        '{urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp}RelayState'])

    _relay_state = None

    for item in res["header"]:
        if item.c_tag == "RelayState" and item.c_namespace == ecp_prof.NAMESPACE:
            _relay_state = item

    assert _relay_state
    assert _relay_state.actor == "http://schemas.xmlsoap.org/soap/actor/next"

class TestECPClient(object):
    def setup_class(self):
        conf = config.SPConfig()
        conf.load_file("server_conf")
        self.client = Saml2Client(conf)

    def test_ecp_authn(self):
        ssid, soap_req = ecp.ecp_auth_request(self.client,
                                            "urn:mace:example.com:saml:roland:idp",
                                            "id1")
        print soap_req
        response = soap.class_instances_from_soap_enveloped_saml_thingies(
                                                                    soap_req,
                                                                    [paos,
                                                                     ecp_prof,
                                                                     samlp])
        print response
        assert len(response["header"]) == 2
        assert response["body"].c_tag == "AuthnRequest"
        assert response["body"].c_namespace == samlp.NAMESPACE
        headers = ["{%s}%s" % (i.c_namespace,
                               i.c_tag) for i in response["header"]]
        print headers
        assert _eq(headers,['{urn:liberty:paos:2003-08}Request',
                    #'{urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp}Request',
                    '{urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp}RelayState'])
