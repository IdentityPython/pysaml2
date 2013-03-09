from saml2 import samlp
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_URI
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_TRANSIENT

from idp_test.check import CheckLogoutSupport
from idp_test.check import CheckSaml2IntAttributes
from idp_test.check import CheckSaml2IntMetaData
from idp_test.check import VerifyAttributeNameFormat
from idp_test.check import VerifyFunctionality
from idp_test.check import VerifyContent
from idp_test.check import VerifyLogout
from idp_test.check import VerifyNameIDMapping
from idp_test.check import VerifyNameIDPolicyUsage
from idp_test.check import VerifySuccessStatus
from idp_test.check import VerifySignatureAlgorithm
from idp_test.check import VerifySignedPart
from idp_test.check import VerifyEndpoint

from saml2.samlp import NameIDPolicy

__author__ = 'rolandh'


class Request(object):
    _args = {}
    _class = None
    tests = {"post": [VerifyContent], "pre": []}

    def __init__(self, conv):
        self.args = self._args.copy()
        self.conv = conv

    def setup(self):
        pass

    def pre_processing(self, message, args):
        return message

    def post_processing(self, message):
        return message

#class Saml2IntRequest(Request):
#    tests = {"pre": [],
#             "post": [CheckSaml2IntAttributes, VerifyContent
#                      #  CheckSubjectNameIDFormat,
#             ]}


class AuthnRequest(Request):
    _class = samlp.AuthnRequest
    request = "authn_request"
    _args = {"response_binding": BINDING_HTTP_POST,
             "request_binding": BINDING_HTTP_REDIRECT,
             "nameid_format": NAMEID_FORMAT_PERSISTENT,
             "allow_create": True}
    tests = {"pre": [VerifyFunctionality],
             "post": [CheckSaml2IntAttributes,
                      VerifyAttributeNameFormat,
                      VerifySignedPart,
                      VerifySignatureAlgorithm]}


class AuthnRequestTransient(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["nameid_format"] = NAMEID_FORMAT_TRANSIENT

    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        url = ""
        for url, binding in endps["assertion_consumer_service"]:
            if binding == BINDING_HTTP_POST:
                self.args["assertion_consumer_service_url"] = url
                break

        self.tests["post"].append((VerifyEndpoint, url))


class AuthnRequestEndpointIndex(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["attribute_consuming_service_index"] = 3

    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        acs3 = endps["assertion_consumer_service"][3]
        self.tests["post"].append((VerifyEndpoint, acs3[0]))


class AuthnRequestSpecEndpoint(AuthnRequest):
    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        acs3 = endps["assertion_consumer_service"][3]
        self.args["assertion_consumer_service_url"] = acs3[0]
        self.tests["post"].append((VerifyEndpoint, acs3[0]))


class DynAuthnRequest(Request):
    _class = samlp.AuthnRequest
    request = "authn_request"
    _args = {"response_binding": BINDING_HTTP_POST}
    tests = {}
    name_id_formats = [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT]
    bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]

    def setup(self):
        metadata = self.conv.client.metadata
        entity = metadata[self.conv.entity_id]
        self.args.update({"nameid_format": "", "request_binding": ""})
        for idp in entity["idpsso_descriptor"]:
            for nformat in self.name_id_formats:
                if self.args["nameid_format"]:
                    break
                for nif in idp["name_id_format"]:
                    if nif["text"] == nformat:
                        self.args["nameid_format"] = nformat
                        break
            for bind in self.bindings:
                if self.args["request_binding"]:
                    break
                for sso in idp["single_sign_on_service"]:
                    if sso["binding"] == bind:
                        self.args["request_binding"] = bind
                        break


class AuthnRequestPost(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["request_binding"] = BINDING_HTTP_POST


class AuthnRequest_using_Artifact(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.use_artifact = True


class AuthnRequestTransient(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["nameid_format"] = NAMEID_FORMAT_TRANSIENT


class AuthnRequestPostTransient(AuthnRequestPost):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["nameid_format"] = NAMEID_FORMAT_TRANSIENT


class LogOutRequest(Request):
    request = "logout_request"
    _args = {"request_binding": BINDING_SOAP}
    tests = {"pre": [VerifyFunctionality], "post": []}

    def __init__(self, conv):
        Request.__init__(self, conv)
        self.tests["pre"].append(CheckLogoutSupport)
        self.tests["post"].append(VerifyLogout)

    def setup(self):
        resp = self.conv.saml_response[-1].response
        assertion = resp.assertion[0]
        subj = assertion.subject
        self.args["name_id"] = subj.name_id
        self.args["issuer_entity_id"] = assertion.issuer.text


class AssertionIDRequest(Request):
    request = "assertion_id_request"
    _args = {"request_binding": BINDING_URI}
    tests = {"pre": [VerifyFunctionality]}

    def setup(self):
        resp = self.conv.saml_response[-1].response
        assertion = resp.assertion[0]
        self.args["assertion_id_refs"] = [assertion.id]


class AuthnQuery(Request):
    request = "authn_query"
    _args = {"request_binding": BINDING_SOAP}
    tests = {"pre": [VerifyFunctionality], "post": []}

    def __init__(self, conv):
        Request.__init__(self, conv)
        self.tests["post"].append(VerifySuccessStatus)

    def setup(self):
        resp = self.conv.saml_response[-1].response
        assertion = resp.assertion[0]
        self.args["subject"] = assertion.subject


class NameIDMappingRequest(Request):
    request = "name_id_mapping_request"
    _args = {"request_binding": BINDING_SOAP,
             "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_PERSISTENT,
                                            sp_name_qualifier="GroupOn",
                                            allow_create="true")}

    def __init__(self, conv):
        Request.__init__(self, conv)
        self.tests["post"].append(VerifyNameIDMapping)

    def setup(self):
        resp = self.conv.saml_response[-1].response
        assertion = resp.assertion[0]
        self.args["name_id"] = assertion.subject.name_id


class AuthnRequest_NameIDPolicy1(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["name_id_policy"] = NameIDPolicy(
            format=NAMEID_FORMAT_PERSISTENT, sp_name_qualifier="Group1",
            allow_create="true")
        self.tests["post"].append(VerifyNameIDPolicyUsage)


class AuthnRequest_TransientNameID(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["name_id_policy"] = NameIDPolicy(
            format=NAMEID_FORMAT_TRANSIENT, sp_name_qualifier="Group",
            allow_create="true")
        self.tests["post"].append(VerifyNameIDPolicyUsage)


class ECP_AuthnRequest(AuthnRequest):

    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["request_binding"] = BINDING_SOAP
        self.args["service_url_binding"] = BINDING_PAOS

    def setup(self):
        _client = self.conv.client
        _client.user = "babs"
        _client.passwd = "howes"


class ManageNameIDRequest(Request):
    request = "manage_name_id_request"
    _args = {"request_binding": BINDING_SOAP,
             "new_id": samlp.NewID("New identifier")}

    def __init__(self, conv):
        Request.__init__(self, conv)
        self.tests["post"].append(VerifySuccessStatus)

    def setup(self):
        resp = self.conv.saml_response[-1].response
        assertion = resp.assertion[0]
        self.args["name_id"] = assertion.subject.name_id


class AttributeQuery(Request):
    request = "attribute_query"
    _args = {"request_binding": BINDING_SOAP}
    tests = {"pre": [VerifyFunctionality],
             "post": [CheckSaml2IntAttributes, VerifyAttributeNameFormat]}

    def setup(self):
        resp = self.conv.saml_response[-1].response
        assertion = resp.assertion[0]
        self.args["name_id"] = assertion.subject.name_id

# -----------------------------------------------------------------------------

OPERATIONS = {
    'verify': {
        "name": 'Verify connectivity',
        "descr": 'Uses AuthnRequest to check connectivity',
        "sequence": [DynAuthnRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []}
    },
    'authn': {
        "name": 'Absolute basic SAML2 AuthnRequest',
        "descr": 'AuthnRequest using HTTP-redirect',
        "sequence": [AuthnRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []}
    },
    'authn-transient': {
        "name": 'Basic SAML2 AuthnRequest, transient name ID',
        "descr": 'AuthnRequest using HTTP-redirect',
        "sequence": [AuthnRequestTransient],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []}
    },
    'authn-post': {
        "name": 'Basic SAML2 AuthnRequest using HTTP POST',
        "descr": 'AuthnRequest using HTTP-POST',
        "sequence": [AuthnRequestPost],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []}
    },
    'authn-post-transient': {
        "name": 'AuthnRequest using HTTP POST expecting transient NameID',
        "descr": 'AuthnRequest using HTTP-POST',
        "sequence": [AuthnRequestPostTransient],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []}
    },
    'authn_endpoint_index': {
        "name": '',
        "descr": '',
        "sequence": [AuthnRequestEndpointIndex],
        "depend":["authn"]
    },
    'authn_specified_endpoint': {
        "name": '',
        "descr": '',
        "sequence": [AuthnRequestSpecEndpoint],
        "depend":["authn"]
    },
    'log-in-out': {
        "name": 'Absolute basic SAML2 log in and out',
        "descr": 'AuthnRequest using HTTP-redirect followed by a logout',
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
        "descr": 'AuthnRequest followed by an AuthnQuery',
        "sequence": [AuthnRequest, AuthnQuery],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []}
    },
    'authn-assertion_id_request': {
        "name": 'AuthnRequest and then an AssertionIDRequest',
        "descr": 'AuthnRequest followed by an AssertionIDRequest',
        "sequence": [AuthnRequest, AssertionIDRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []}
        },
    'authn-with-name_id_policy': {
        "name": 'SAML2 AuthnRequest with specific NameIDPolicy',
        "descr": 'AuthnRequest with specific NameIDPolicy',
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
    },
    'manage_nameid':{
        "name": "Setting the SP provided ID by using ManageNameID",
        "sequence":[AuthnRequest, ManageNameIDRequest]
    },
    'attribute-query':{
        "name": "Setting the SP provided ID by using ManageNameID",
        "sequence":[AuthnRequest, AttributeQuery]
    }
}