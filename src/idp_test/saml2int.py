from saml2 import BINDING_HTTP_REDIRECT, BINDING_URI, samlp, BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2.saml import NAMEID_FORMAT_PERSISTENT
#from idp_test.check import CheckSubjectNameIDFormat
from idp_test.check import CheckSaml2IntMetaData
from idp_test.check import VerifyNameIDPolicyUsage
from idp_test.check import CheckSaml2IntAttributes
from idp_test.check import CheckLogoutSupport
from idp_test.check import VerifyLogout
from idp_test.check import VerifyContent
from idp_test.check import VerifySuccessStatus
from idp_test.check import VerifyNameIDMapping

from saml2.samlp import NameIDPolicy

__author__ = 'rolandh'

class Request(object):
    _args = {}
    _class = None
    tests = {"post":[VerifyContent], "pre":[]}

    def __init__(self):
        self.args = self._args.copy()

    def setup(self, environ):
        pass

    def pre_processing(self, environ, message, args):
        return message

    def post_processing(self, environ, message):
        return message

#class Saml2IntRequest(Request):
#    tests = {"pre": [],
#             "post": [CheckSaml2IntAttributes, VerifyContent
#                      #  CheckSubjectNameIDFormat,
#             ]}

class AuthnRequest(Request):
    _class = samlp.AuthnRequest
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

class LogOutRequest(Request):
    request = "logout_request"
    _args = {"binding": BINDING_SOAP,
            # "sign": True
            }

    def __init__(self):
        Request.__init__(self)
        self.tests["pre"].append(CheckLogoutSupport)
        self.tests["post"].append(VerifyLogout)

    def setup(self, environ):
        resp = environ["response"][-1].response
        assertion = resp.assertion[0]
        subj = assertion.subject
        self.args["name_id"] = subj.name_id
        self.args["issuer_entity_id"] = assertion.issuer.text

class AssertionIDRequest(Request):
    request = "assertion_id_request"
    _args = {"binding": BINDING_URI}

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

class NameIDMappingRequest(Request):
    request = "name_id_mapping_request"
    _args = {"binding": BINDING_SOAP,
             "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_PERSISTENT,
                                            sp_name_qualifier="GroupOn",
                                            allow_create="true")}

    def __init__(self):
        Request.__init__(self)
        self.tests["post"].append(VerifyNameIDMapping)

    def setup(self, environ):
        resp = environ["response"][-1].response
        assertion = resp.assertion[0]
        self.args["name_id"] = assertion.subject.name_id

class AuthnRequest_NameIDPolicy1(AuthnRequest):
    request = "authn_request"
    _args = {"binding": BINDING_HTTP_REDIRECT,
             "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_PERSISTENT,
                                            sp_name_qualifier="Group1",
                                            allow_create="true"),
             "allow_create": True}

    def __init__(self):
        AuthnRequest.__init__(self)
        self.tests["post"].append(VerifyNameIDPolicyUsage)

class ECP_AuthnRequest(AuthnRequest):
    def __init__(self):
        AuthnRequest.__init__(self)
        self.args["binding"] = BINDING_SOAP
        self.args["service_url_binding"] = BINDING_PAOS

    def setup(self, environ):
        _client = environ["client"]
        _client.user = "babs"
        _client.passwd = "howes"

#    def pre_processing(self, environ, message, args):
#        # first act as the SP
#        self._orig_binding = args["binding"]
#        args["binding"] = BINDING_SOAP
#        return
#
#    def post_processing(self, environ, message):
#        _client = environ["client"]
#        rdict = _client.parse_soap_message(message)
#        relay_state = rdict["header"][0].text
#        return {"SAMLRequest": message, "RelayState": relay_state}

# -----------------------------------------------------------------------------

OPERATIONS = {
    'basic-authn': {
        "name": 'Absolute basic SAML2 AuthnRequest',
        "descr": ('AuthnRequest using HTTP-redirect'),
        "sequence": [AuthnRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": [CheckSaml2IntAttributes]}
    },
    'basic-authn-post': {
        "name": 'Basic SAML2 AuthnRequest using HTTP POST',
        "descr": ('AuthnRequest using HTTP-POST'),
        "sequence": [AuthnRequestPost],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": [CheckSaml2IntAttributes]}
    },
    'log-in-out': {
        "name": 'Absolute basic SAML2 log in and out',
        "descr": ('AuthnRequest using HTTP-redirect followed by a logout'),
        "sequence": [AuthnRequest, LogOutRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []}
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
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []}
    },
    'authn-assertion_id_request': {
        "name": 'AuthnRequest and then an AssertionIDRequest',
        "descr": ('AuthnRequest followed by an AssertionIDRequest'),
        "sequence": [AuthnRequest, AssertionIDRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []}
        },
    'authn-with-name_id_policy': {
        "name": 'SAML2 AuthnRequest with specific NameIDPolicy',
        "descr": ('AuthnRequest with specific NameIDPolicy'),
        "sequence": [AuthnRequest_NameIDPolicy1],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []}
        },
    'ecp_authn': {
        "name": "SAML2 AuthnRequest using ECP and PAOS",
        "descr": "SAML2 AuthnRequest using ECP and PAOS",
        "sequence":[ECP_AuthnRequest]
    },
    'nameid-mapping':{
        "name": "Simple NameIDMapping request",
        "sequence":[AuthnRequest, NameIDMappingRequest]
    }
}