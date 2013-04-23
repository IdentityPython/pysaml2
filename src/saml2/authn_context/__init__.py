__author__ = 'rolandh'

from saml2 import extension_elements_to_elements

INTERNETPROTOCOLPASSWORD = \
    'urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword'
MOBILETWOFACTORCONTRACT = \
    'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract'
PASSWORDPROTECTEDTRANSPORT = \
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
TLSCLIENT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient'

from saml2.authn_context import ippword
from saml2.authn_context import mobiletwofactor
from saml2.authn_context import ppt
from saml2.authn_context import pword
from saml2.authn_context import sslcert


class AuthnBroker(object):
    def __init__(self):
        self.db = {}

    def add(self, spec, target):
        """
        Adds a new authentication method.

        :param spec: What the authentication endpoint offers in the form
            of an AuthnContext
        :param target: The URL of the authentication service
        :return:
        """

        if spec.authn_context_class_ref:
            self.db[spec.authn_context_class_ref.text] = target
        elif spec.authn_context_decl:
            key = spec.authn_context_decl.c_namespace
            try:
                self.db[key].append((spec.authn_context_decl, target))
            except KeyError:
                self.db[key] = [(spec.authn_context_decl, target)]

    def pick(self, req_authn_context):
        """
        Given the authentication context find out where to send the user next.

        :param req_authn_context: The requested context as an AuthnContext
            instance
        :return: An URL
        """

        if req_authn_context.authn_context_class_ref:
            return self.db[req_authn_context.authn_context_class_ref.text]
        elif req_authn_context.authn_context_decl:
            key = req_authn_context.authn_context_decl.c_namespace
            for acd, target in self.db[key]:
                if self.match(req_authn_context.authn_context_decl, acd):
                    return target

    def match(self, requested, provided):
        if requested == provided:
            return True
        else:
            return False


def authn_context_factory(text):
    # brute force
    for mod in [ippword, mobiletwofactor, ppt, pword, sslcert]:
        inst = mod.authentication_context_declaration_from_string(text)
        if inst:
            return inst

    return None

def authn_context_decl_from_extension_elements(extelems):
    res = extension_elements_to_elements(extelems, [ippword, mobiletwofactor,
                                                    ppt, pword, sslcert])
    try:
        return res[0]
    except IndexError:
        return None