
__author__ = 'rolandh'

from saml2.samlp import RequestedAuthnContext
from saml2.samlp import AuthnQuery
from saml2.client import Saml2Client
from saml2.saml import AUTHN_PASSWORD
from saml2.saml import AuthnContextClassRef
from saml2.saml import Subject
from saml2.saml import NameID
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.server import Server

def test_basic():
    sp = Saml2Client(config_file="servera_conf")
    idp = Server(config_file="idp_all_conf")

    srvs = sp.metadata.authn_query_service(idp.config.entityid)

    destination = srvs[0]["location"]
    authn_context = [RequestedAuthnContext(
        authn_context_class_ref=AuthnContextClassRef(
            text=AUTHN_PASSWORD))]

    subject = Subject(text="abc", name_id=NameID(format=NAMEID_FORMAT_TRANSIENT))

    aq = sp.create_authn_query(subject, destination, authn_context)

    print aq

    assert isinstance(aq, AuthnQuery)
