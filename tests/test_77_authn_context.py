
__author__ = 'rolandh'

ex1 = """<AuthenticationContextDeclaration
  xmlns="urn:oasis:names:tc:SAML:2.0:ac:classes:Password">
  <AuthnMethod>
    <Authenticator>
      <RestrictedPassword>
        <Length min="4"/>
      </RestrictedPassword>
    </Authenticator>
  </AuthnMethod>
</AuthenticationContextDeclaration>"""

from saml2.saml import AuthnContext
from saml2.saml import authn_context_from_string
from saml2.saml import AuthnContextClassRef
from saml2.authn_context import pword, PASSWORDPROTECTEDTRANSPORT
from saml2.authn_context import AuthnBroker
from saml2.authn_context import authn_context_decl_from_extension_elements
from saml2.authn_context import authn_context_factory

length = pword.Length(min="4")
restricted_password = pword.RestrictedPassword(length=length)
authenticator = pword.Authenticator(restricted_password=restricted_password)
authn_method = pword.AuthnMethod(authenticator=authenticator)
ACD = pword.AuthenticationContextDeclaration(authn_method=authn_method)

AUTHNCTXT = AuthnContext(authn_context_decl=ACD)


def test_passwd():
    inst = ACD
    inst2 = pword.authentication_context_declaration_from_string(ex1)

    assert inst == inst2


def test_factory():
    inst_pw = pword.authentication_context_declaration_from_string(ex1)
    inst = authn_context_factory(ex1)

    assert inst_pw == inst


def test_authn_decl_in_authn_context():
    authnctxt = AuthnContext(authn_context_decl=ACD)

    acs = authn_context_from_string("%s" % authnctxt)
    if acs.extension_elements:
        cacd = authn_context_decl_from_extension_elements(
            acs.extension_elements)
        if cacd:
            acs.authn_context_decl = cacd

    assert acs.authn_context_decl == ACD


def test_authn_1():
    accr = AuthnContextClassRef(text=PASSWORDPROTECTEDTRANSPORT)
    ac = AuthnContext(authn_context_class_ref=accr)
    authn = AuthnBroker()
    target = "https://example.org/login"
    authn.add(ac, target)

    assert target == authn.pick(ac)


def test_authn_2():
    authn = AuthnBroker()
    target = "https://example.org/login"
    endpoint = "https://example.com/sso/redirect"
    authn.add(AUTHNCTXT, target)

    assert target == authn.pick(AUTHNCTXT)

if __name__ == "__main__":
    test_authn_2()