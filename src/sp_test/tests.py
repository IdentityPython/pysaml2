from saml2 import samlp
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST

from saml2.saml import AUTHN_PASSWORD
from saml2.samlp import STATUS_AUTHN_FAILED
from sp_test.check import VerifyContent
from sp_test.check import MatchResult

__author__ = 'rolandh'

USER = {
    "adam": {
        "given_name": "Adam",
        "sn": "Andersson"
    },
    "eva": {
        "given_name": "Eva",
        "sn": "Svensson"
    }
}

AUTHN = (AUTHN_PASSWORD, "http://lingon.catalogix.se/login")


class Response(object):
    _args = {}
    _class = samlp.Response
    _sign = False
    tests = {"post": [], "pre": []}

    def __init__(self, conv):
        self.args = self._args.copy()
        self.conv = conv

    def setup(self):
        pass

    def pre_processing(self, message, args):
        return message

    def post_processing(self, message):
        return message


class Request(object):
    response = ""
    _class = None
    tests = {"post": [VerifyContent], "pre": []}

    def __init__(self):
        pass

    def __call__(self, conv, response):
        pass


class Operation(object):
    pass


class AuthnResponse(Response):
    _response_args = {
        "identity": USER["adam"],
        "userid": "adam",
        #"name_id": None,
        "authn": AUTHN
    }
    _binding = BINDING_HTTP_POST


class AuthnResponse_redirect(AuthnResponse):
    _binding = BINDING_HTTP_REDIRECT


class ErrorResponse(Response):
    _response_args = {
        "info": (STATUS_AUTHN_FAILED, "Unknown user")
    }
    _binding = BINDING_HTTP_POST


class LogoutResponse(Response):
    _class = samlp.LogoutRequest
    pass


class Login(Operation):
    _interaction = ["wayf"]


class AuthnRequest(Request):
    _class = samlp.AuthnRequest



PHASES = {
    "login": (Login, AuthnRequest, AuthnResponse),
    "login_redirect": (Login, AuthnRequest, AuthnResponse_redirect),
    "login_error": (Login, AuthnRequest, ErrorResponse)
}

OPERATIONS = {
    'login': {
        "name": 'Basic Login test',
        "descr": 'Basic Login test',
        "sequence": ["login"],
        "tests": {"pre": [], "post": [MatchResult]}
    },
    'verify': {
        "name": 'Verify various aspects of the generated AuthnRequest message',
        "descr": 'Basic Login test',
        "sequence": [],
        "tests": {"pre": [], "post": []}
    },
    'sp-01':{
        "name": "SP should not accept a Response as valid, when the StatusCode is not success",
        "sequence": ["login_error"],
        "tests": {"pre": [], "post": []}
    },
    'sp-02':{
        "name": "SP should accept a NameID with Format: persistent"
    },
    'sp-03':{
        "name": "SP should accept a NameID with Format: e-mail"
    },
    'sp-04':{
        "name": "Do SP work with unknown NameID Format, such as : foo"
    },
    'sp-05':{
        "name": "SP should accept a Response without a SubjectConfirmationData element"
    },
    'sp-06':{
        "name": "SP should accept unsolicited response (no in_response_to attribute)"
    },
}