from idp_test import CheckSaml2IntMetaData
from idp_test.check import CheckSaml2IntAttributes
from saml2 import SamlBase, ExtensionContainer

__author__ = 'rolandh'

from idp_test.saml2base import AuthnRequest

class DummyExtension(SamlBase):
    """The urn:mace:umu.se:SAML:2.0:extension:foo element """

    c_tag = 'DummyExtension'
    c_namespace = "urn:mace:umu.se:SAML:2.0:extension:foo"
    c_value_type = {'base': 'NCName'}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

class AuthnRequest_UnknownIssuer(AuthnRequest):
    def pre_processing(self, message, args):
        _issuer = message.issuer
        _issuer.text = "https://www.example.com/foobar.xml"
        return message

class AuthnRequest_UnknownExtension(AuthnRequest):
    def pre_processing(self, message, args):
        message.extension = ExtensionContainer()
        message.extension.add_extension_element(DummyExtension(text="foo"))
        return message

OPERATIONS = {
    'authn_unkown-issuer': {
        "name": 'AuthnRequest with unknown issuer',
        "descr": 'AuthnRequest with unknown issuer',
        "sequence": [AuthnRequest_UnknownIssuer],
        "depends": ['authn'],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": [CheckSaml2IntAttributes]}
    },
    'authn_unkown-extension': {
        "name": 'AuthnRequest with unknown extension',
        "descr": 'AuthnRequest with unknown extension',
        "sequence": [AuthnRequest_UnknownExtension],
        "depends": ['authn'],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": [CheckSaml2IntAttributes]}
    },
}