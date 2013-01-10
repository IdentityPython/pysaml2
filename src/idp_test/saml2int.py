from saml2 import BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2.saml import NAMEID_FORMAT_PERSISTENT
#from idp_test.check import CheckSubjectNameIDFormat
from idp_test.check import CheckSaml2IntMetaData
from idp_test.check import CheckSaml2IntAttributes
from idp_test.check import CheckLogoutSupport
from idp_test.check import VerifyLogout
from idp_test.check import VerifyContent

__author__ = 'rolandh'

class Request(object):
    _args = {}

    def __init__(self):
        self.args = self._args.copy()

    def setup(self, environ):
        pass

class AuthnRequest(Request):
    request = "authn_request"
    _args = {"binding": BINDING_HTTP_REDIRECT,
             "nameid_format": NAMEID_FORMAT_PERSISTENT,
             "allow_create": True}
    tests = {"pre": [CheckSaml2IntMetaData],
             "post": [CheckSaml2IntAttributes, VerifyContent
                    #  CheckSubjectNameIDFormat,
                    ]}

class AuthnRequestPost(AuthnRequest):
    def __init__(self):
        AuthnRequest.__init__(self)
        self.args["binding"] = BINDING_HTTP_POST


class AuthnRequest_using_Artifact(AuthnRequest):
    def __init__(self):
        AuthnRequest.__init__(self)
        self.use_artifact = True

class LogOutRequest(Request):
    request = "logout_request"
    tests = {"pre": [CheckLogoutSupport],
             "post": [VerifyLogout]}
    _args = {"binding": BINDING_SOAP,
            # "sign": True
            }

    def setup(self, environ):
        resp = environ["response"][-1].response
        assertion = resp.assertion[0]
        subj = assertion.subject
        self.args["subject_id"] = subj.name_id.text
        #self.args["name_id"] = subj.name_id
        self.args["issuer_entity_id"] = assertion.issuer.text

OPERATIONS = {
    'basic-authn': {
        "name": 'Absolute basic SAML2 AuthnRequest',
        "descr": ('AuthnRequest using HTTP-redirect'),
        "sequence": [AuthnRequest],
        #"endpoints": ["authorization_endpoint"],
        #"block": ["key_export"]
    },
    'basic-authn-post': {
        "name": 'Basic SAML2 AuthnRequest using HTTP POST',
        "descr": ('AuthnRequest using HTTP-POST'),
        "sequence": [AuthnRequestPost],
        #"endpoints": ["authorization_endpoint"],
        #"block": ["key_export"]
    },
    'log-in-out': {
        "name": 'Absolute basic SAML2 AuthnRequest',
        "descr": ('AuthnRequest using HTTP-redirect followed by a logout'),
        "sequence": [AuthnRequest, LogOutRequest],
    }
}