from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2.saml import NAMEID_FORMAT_PERSISTENT
#from idp_test.check import CheckSubjectNameIDFormat
from idp_test.check import CheckSaml2IntMetaData
from idp_test.check import CheckSaml2IntAttributes
from idp_test.check import CheckLogoutSupport
from idp_test.check import VerifyLogout
from idp_test.check import VerifyContent
from idp_test.check import VerifySuccessStatus

__author__ = 'rolandh'

class Request(object):
    _args = {}
    tests = {"post":[VerifyContent], "pre":[]}

    def __init__(self):
        self.args = self._args.copy()

    def setup(self, environ):
        pass

class Saml2IntRequest(Request):
    tests = {"pre": [CheckSaml2IntMetaData],
             "post": [CheckSaml2IntAttributes, VerifyContent
                      #  CheckSubjectNameIDFormat,
             ]}

class AuthnRequest(Saml2IntRequest):
    request = "authn_request"
    _args = {"binding": BINDING_HTTP_REDIRECT,
             "nameid_format": NAMEID_FORMAT_PERSISTENT,
             "allow_create": True}

class AuthnRequestPost(AuthnRequest):
    def __init__(self):
        AuthnRequest.__init__(self)
        self.args["binding"] = BINDING_HTTP_POST


class AuthnRequest_using_Artifact(AuthnRequest):
    def __init__(self):
        AuthnRequest.__init__(self)
        self.use_artifact = True

class LogOutRequest(Saml2IntRequest):
    request = "logout_request"
    _args = {"binding": BINDING_SOAP,
            # "sign": True
            }

    def __init__(self):
        Saml2IntRequest.__init__(self)
        self.tests["pre"].append(CheckLogoutSupport)
        self.tests["post"].remove(CheckSaml2IntAttributes)
        self.tests["post"].append(VerifyLogout)

    def setup(self, environ):
        resp = environ["response"][-1].response
        assertion = resp.assertion[0]
        subj = assertion.subject
        self.args["name_id"] = subj.name_id
        self.args["issuer_entity_id"] = assertion.issuer.text

class AssertionIDRequest(Request):
    request = "assertion_id_request"
    _args = {"binding": BINDING_SOAP}

    def __init__(self):
        Request.__init__(self)
        self.tests["post"].append(VerifySuccessStatus)

    def setup(self, environ):
        resp = environ["response"][-1].response
        assertion = resp.assertion[0]
        self.args["assertion_id_refs"] = [assertion.id]

class AuthnQuery(Request):
    request = "authn_query"
    _args = {"binding": BINDING_SOAP}

    def __init__(self):
        Request.__init__(self)
        self.tests["post"].append(VerifySuccessStatus)

    def setup(self, environ):
        resp = environ["response"][-1].response
        assertion = resp.assertion[0]
        self.args["subject"] = assertion.subject

class NameIDMappeingRequest(Request):
    request = "name_id_mapping_request"
    _args = {"binding": BINDING_HTTP_REDIRECT}

    def __init__(self):
        Request.__init__(self)
        self.tests["post"].append(VerifySuccessStatus)

    def setup(self, environ):
        resp = environ["response"][-1].response
        assertion = resp.assertion[0]
        self.args["subject"] = assertion.subject

# -----------------------------------------------------------------------------

OPERATIONS = {
    'basic-authn': {
        "name": 'Absolute basic SAML2 AuthnRequest',
        "descr": ('AuthnRequest using HTTP-redirect'),
        "sequence": [AuthnRequest],
    },
    'basic-authn-post': {
        "name": 'Basic SAML2 AuthnRequest using HTTP POST',
        "descr": ('AuthnRequest using HTTP-POST'),
        "sequence": [AuthnRequestPost],
    },
    'log-in-out': {
        "name": 'Absolute basic SAML2 AuthnRequest',
        "descr": ('AuthnRequest using HTTP-redirect followed by a logout'),
        "sequence": [AuthnRequest, LogOutRequest],
    },
#    'authn-artifact':{
#        "name": "SAML2 AuthnRequest using an artifact",
#        "descr": ('AuthnRequest using HTTP-redirect and artifact'),
#        "sequence": [AuthnRequest_using_Artifact]
#    }
    'authn-authn_query': {
        "name": 'AuthnRequest and then an AuthnQuery',
        "descr": ('AuthnRequest followed by an AuthnQuery'),
        "sequence": [AuthnRequest, AuthnQuery],
    },
    'authn-assertion_id_request': {
        "name": 'AuthnRequest and then an AssertionIDRequest',
        "descr": ('AuthnRequest followed by an AssertionIDRequest'),
        "sequence": [AuthnRequest, AssertionIDRequest],
        }
}