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

AL1 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel1"
AL2 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel2"
AL3 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel3"
AL4 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel4"

from saml2.authn_context import ippword
from saml2.authn_context import mobiletwofactor
from saml2.authn_context import ppt
from saml2.authn_context import pword
from saml2.authn_context import sslcert


class AuthnBroker(object):
    def __init__(self):
        self.db = {}

    def add(self, spec, method, level=0, authn_authority=""):
        """
        Adds a new authentication method.
        Assumes not more than one authentication method per AuthnContext
        specification.

        :param spec: What the authentication endpoint offers in the form
            of an AuthnContext
        :param method: A identifier of the authentication method.
        :param level: security level, positive integers, 0 is lowest
        :return:
        """

        if spec.authn_context_class_ref:
            _ref = spec.authn_context_class_ref.text
            self.db[_ref] = {
                "method": method,
                "level": level,
                "authn_auth": authn_authority
            }
        elif spec.authn_context_decl:
            key = spec.authn_context_decl.c_namespace
            _info = {
                "method": method,
                "decl": spec.authn_context_decl,
                "level": level,
                "authn_auth": authn_authority
            }
            try:
                self.db[key].append(_info)
            except KeyError:
                self.db[key] = [_info]

    def pick(self, req_authn_context):
        """
        Given the authentication context find zero or more places where
        the user could be sent next. Ordered according to security level.

        :param req_authn_context: The requested context as an AuthnContext
            instance
        :return: An URL
        """

        if req_authn_context.authn_context_class_ref:
            _ref = req_authn_context.authn_context_class_ref.text
            try:
                _info = self.db[_ref]
            except KeyError:
                return []
            else:
                _level = _info["level"]
                res = []
                for key, _dic in self.db.items():
                    if key == _ref:
                        continue
                    elif _dic["level"] >= _level:
                        res.append(_dic["method"])
                res.insert(0, _info["method"])
                return res
        elif req_authn_context.authn_context_decl:
            key = req_authn_context.authn_context_decl.c_namespace
            _methods = []
            for _dic in self.db[key]:
                if self.match(req_authn_context.authn_context_decl,
                              _dic["decl"]):
                    _methods.append(_dic["method"])
            return _methods

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