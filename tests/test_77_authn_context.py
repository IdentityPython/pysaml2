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

from saml2.authn_context import pword


def test_passwd():
    length = pword.Length(min="4")
    restricted_password = pword.RestrictedPassword(length=length)
    authenticator = pword.Authenticator(restricted_password=restricted_password)
    authn_method = pword.AuthnMethod(authenticator=authenticator)
    inst = pword.AuthenticationContextDeclaration(authn_method=authn_method)

    inst2 = pword.authentication_context_declaration_from_string(ex1)

    assert inst == inst2

if __name__ == "__main__":
    test_passwd()