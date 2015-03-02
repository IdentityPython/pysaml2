from saml2 import samlp
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_URI
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS

from idp_test.check import CheckLogoutSupport
from idp_test.check import CheckSaml2IntAttributes
from idp_test.check import CheckSaml2IntMetaData
from idp_test.check import VerifyAttributeNameFormat
from idp_test.check import VerifyFunctionality
from idp_test.check import VerifyContent
from idp_test.check import VerifyNameIDMapping
from idp_test.check import VerifyNameIDPolicyUsage
from idp_test.check import VerifySuccessStatus
from idp_test.check import VerifyDigestAlgorithm
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
                      VerifyDigestAlgorithm,
                      VerifySignatureAlgorithm]}


class AuthnRequestNID_Transient(AuthnRequest):
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

        self.tests["post"].append((VerifyEndpoint, {"endpoint": url}))


class AuthnRequestNID_Email(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["nameid_format"] = NAMEID_FORMAT_EMAILADDRESS

    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        url = ""
        for url, binding in endps["assertion_consumer_service"]:
            if binding == BINDING_HTTP_POST:
                self.args["assertion_consumer_service_url"] = url
                break

        self.tests["post"].append((VerifyEndpoint, {"endpoint": url}))


class AuthnRequestNID_Unspecified(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["nameid_format"] = NAMEID_FORMAT_UNSPECIFIED

    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        url = ""
        for url, binding in endps["assertion_consumer_service"]:
            if binding == BINDING_HTTP_POST:
                self.args["assertion_consumer_service_url"] = url
                break

        self.tests["post"].append((VerifyEndpoint, {"endpoint": url}))


class AuthnRequestNID_no(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["nameid_format"] = ""

    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        url = ""
        for url, binding in endps["assertion_consumer_service"]:
            if binding == BINDING_HTTP_POST:
                self.args["assertion_consumer_service_url"] = url
                break

        self.tests["post"].append((VerifyEndpoint, {"endpoint": url}))


class AuthnRequestEndpointIndex(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["attribute_consuming_service_index"] = 3

    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        acs3 = endps["assertion_consumer_service"][3]
        self.tests["post"].append((VerifyEndpoint, {"endpoint": acs3[0]}))


class AuthnRequestEndpointIndexNIDTransient(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["attribute_consuming_service_index"] = 3
        self.args["nameid_format"] = NAMEID_FORMAT_TRANSIENT

    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        acs3 = endps["assertion_consumer_service"][3]
        self.tests["post"].append((VerifyEndpoint, {"endpoint": acs3[0]}))


class AuthnRequestSpecEndpoint(AuthnRequest):
    def setup(self):
        cnf = self.conv.client.config
        endps = cnf.getattr("endpoints", "sp")
        acs3 = endps["assertion_consumer_service"][3]
        self.args["assertion_consumer_service_url"] = acs3[0]
        self.tests["post"].append((VerifyEndpoint, {"endpoint": acs3[0]}))


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
        self.args["response_binding"] = BINDING_HTTP_ARTIFACT
        self.args["binding"] = BINDING_HTTP_ARTIFACT


class AuthnRequest_using_ArtifactNID_Transient(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["nameid_format"] = NAMEID_FORMAT_TRANSIENT
        self.args["response_binding"] = BINDING_HTTP_ARTIFACT
        self.args["binding"] = BINDING_HTTP_ARTIFACT


class AuthnRequestPostNID_Transient(AuthnRequestPost):
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
        #self.tests["post"].append(VerifyLogout)

    def setup(self):
        resp = self.conv.saml_response[-1].response
        assertion = resp.assertion[0]
        subj = assertion.subject
        self.args["name_id"] = subj.name_id
        self.args["issuer_entity_id"] = assertion.issuer.text


class AssertionIDRequest(Request):
    request = "assertion_id_request"
    _args = {"request_binding": BINDING_URI,
             "response_binding": None}
    tests = {"pre": [VerifyFunctionality]}

    def setup(self):
        assertion = self.conv.saml_response[-1].assertion
        self.args["assertion_id_refs"] = [assertion.id]


class AuthnQuery(Request):
    request = "authn_query"
    _args = {"request_binding": BINDING_SOAP}
    tests = {"pre": [VerifyFunctionality], "post": []}

    def __init__(self, conv):
        Request.__init__(self, conv)
        self.tests["post"].append(VerifySuccessStatus)

    def setup(self):
        assertion = self.conv.saml_response[-1].assertion
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
        assertion = self.conv.saml_response[-1].assertion
        self.args["name_id"] = assertion.subject.name_id


class AuthnRequest_NameIDPolicy1(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["name_id_policy"] = NameIDPolicy(
            format=NAMEID_FORMAT_PERSISTENT, sp_name_qualifier="Group1",
            allow_create="true")
        self.tests["post"].append(VerifyNameIDPolicyUsage)


class AuthnRequest_NameIDPolicy1Transient(AuthnRequest):
    def __init__(self, conv):
        AuthnRequest.__init__(self, conv)
        self.args["name_id_policy"] = NameIDPolicy(
            format=NAMEID_FORMAT_TRANSIENT, sp_name_qualifier="Group1",
            allow_create="true")
        self.args["nameid_format"] = NAMEID_FORMAT_TRANSIENT
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

    # def post_processing(self, message):
    #     # Unpacking SOAP message
    #     return parse_soap_enveloped_saml_response(message)


class ManageNameIDRequest(Request):
    request = "manage_name_id_request"
    _args = {"request_binding": BINDING_SOAP,
             "new_id": samlp.NewID("New identifier")}

    def __init__(self, conv):
        Request.__init__(self, conv)
        self.tests["post"].append(VerifySuccessStatus)

    def setup(self):
        assertion = self.conv.saml_response[-1].assertion
        self.args["name_id"] = assertion.subject.name_id


class AttributeQuery(Request):
    request = "attribute_query"
    _args = {"request_binding": BINDING_SOAP}
    tests = {"pre": [VerifyFunctionality],
             "post": [CheckSaml2IntAttributes, VerifyAttributeNameFormat]}

    def setup(self):
        assertion = self.conv.saml_response[-1].assertion
        self.args["name_id"] = assertion.subject.name_id

# -----------------------------------------------------------------------------

OPERATIONS = {
    'verify': {
        'tc_id': "S2c-16",
        "name": 'Verify SAML connectivity',
        "descr": 'Uses AuthnRequest to check connectivity',
        "sequence": [DynAuthnRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []}
    },
    'authn': {
        "tc_id": "S2c-02",
        "name": 'Absolute basic AuthnRequest',
        "descr": 'AuthnRequest using HTTP-Redirect',
        "sequence": [AuthnRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []},
        "depend":["verify"]
    },
    'authn-nid_transient': {
        "tc_id": "S2c-10",
        "name": 'AuthnRequest, NameID-trans',
        "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, '
                 'transient name ID',
        "sequence": [AuthnRequestNID_Transient],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []},
        "depend":["authn"]
    },
    'authn-nid_email': {
        "tc_id": "S2c-20",
        "name": 'AuthnRequest email nameID',
        "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, NameID-email'
                 'specified',
        "sequence": [AuthnRequestNID_Email],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []},
        "depend":["authn"]
    },
    'authn-nid_no': {
        "tc_id": "S2c-21",
        "name": 'AuthnRequest no NameID format',
        "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, no NameID format '
                 'specified',
        "sequence": [AuthnRequestNID_no],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []},
        "depend":["authn"]
    },
    'authn-nid_unspecified': {
        "tc_id": "S2c-21",
        "name": 'AuthnRequest using unspecified NameID format',
        "descr": 'Basic SAML2 AuthnRequest, HTTP-Redirect, NameID-unspec',
        "sequence": [AuthnRequestNID_Unspecified],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []},
        "depend":["authn"]
    },
    'authn-post': {
        "tc_id": "S2c-08",
        "name": 'Basic SAML2 AuthnRequest using HTTP POST',
        "descr": 'AuthnRequest using HTTP-POST',
        "sequence": [AuthnRequestPost],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []},
        "depend":["authn"]
    },
    'authn-post-transient': {
        "tc_id": "S2c-09",
        "name": 'AuthnRequest HTTP-POST, transient NameID fmt',
        "descr": 'AuthnRequest using HTTP-POST expecting transient NameID',
        "sequence": [AuthnRequestPostNID_Transient],
        "tests": {"pre": [CheckSaml2IntMetaData],
                  "post": []},
        "depend":["authn-post"]
    },
    'attribute-query':{
        "tc_id": "S2c-01",
        "name": "Attribute query",
        "sequence":[AuthnRequest, AttributeQuery],
        "depend":["authn"]
    },
    'attribute-query-transient':{
        "tc_id": "S2c-20",
        "name": "Attribute query, NameID transient",
        "sequence":[AuthnRequestNID_Transient, AttributeQuery],
        "depend":["authn"]
    },
    'authn_endpoint_index': {
        "tc_id": "S2c-03",
        "name": 'AuthnRequest, endpoint index',
        "descr": '',
        "sequence": [AuthnRequestEndpointIndex],
        "depend":["authn"]
    },
    'authn_endpoint_index-transient': {
        "tc_id": "S2c-03",
        "name": 'AuthnRequest, endpoint index, NameID-trans',
        "descr": '',
        "sequence": [AuthnRequestEndpointIndexNIDTransient],
        "depend":["authn"]
    },
    'authn_specified_endpoint': {
        "tc_id": "S2c-04",
        "name": 'AuthnRequest, specified endpoint',
        "descr": '',
        "sequence": [AuthnRequestSpecEndpoint],
        "depend":["authn"]
    },
    'authn-artifact':{
       'tc_id': "S2c-05",
       "name": "SAML2 AuthnRequest using an artifact",
       "descr": ('AuthnRequest using HTTP-Redirect and artifact'),
       "sequence": [AuthnRequest_using_Artifact]
    },
    'authn-artifact_nid-transient':{
       'tc_id': "S2c-05",
       "name": "SAML2 AuthnRequest expecting artifact response",
       "descr": ('AuthnRequest using HTTP-Redirect and artifact'),
       "sequence": [AuthnRequest_using_ArtifactNID_Transient]
    },
    'authn-assertion_id_request': {
        "tc_id": "S2c-06",
        "name": 'AuthnRequest then AssertionIDRequest',
        "descr": 'AuthnRequest followed by an AssertionIDRequest',
        "sequence": [AuthnRequest, AssertionIDRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []},
        "depend":["authn"]
    },
    'authn-nid_transient-assertion_id_request': {
        "tc_id": "S2c-26",
        "name": 'AuthnRequest then AssertionIDRequest, NameID-trans',
        "descr": 'AuthnRequest followed by an AssertionIDRequest',
        "sequence": [AuthnRequestNID_Transient, AssertionIDRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []},
        "depend":["authn"]
    },
    'authn-with-name_id_policy': {
        "tc_id": "S2c-11",
        "name": 'SAML2 AuthnRequest with specific NameIDPolicy',
        "descr": 'AuthnRequest with specific NameIDPolicy',
        "sequence": [AuthnRequest_NameIDPolicy1],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []},
        "depend":["authn"]
    },
    'authn-with-name_id_policy_nid-transient': {
        "tc_id": "S2c-31",
        "name": 'AuthnRequest NameIDPolicy transient',
        "descr": 'AuthnRequest with specific NameIDPolicy',
        "sequence": [AuthnRequest_NameIDPolicy1Transient],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []},
        "depend":["authn"]
    },
    'ecp_authn': {
        'tc_id': "S2c-12",
        "name": "AuthnRequest using ECP and PAOS",
        "descr": "SAML2 AuthnRequest using ECP and PAOS",
        "sequence":[ECP_AuthnRequest]
    },
    'log-in-out': {
        "tc_id": "S2c-13",
        "name": 'Basic SAML2 log in and out',
        "descr": 'AuthnRequest using HTTP-Redirect followed by a logout',
        "sequence": [AuthnRequest, LogOutRequest],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []},
        "depend":["authn"]
    },
    'manage_nameid':{
        "tc_id": "S2c-14",
        "name":  "ManageNameID; set NameID",
        "descr": "Setting the SP provided ID by using ManageNameID",
        "sequence":[AuthnRequest, ManageNameIDRequest],
        "depend":["authn"]
    },
    'nameid-mapping':{
        "tc_id": "S2c-15",
        "name": "Simple NameIDMapping request",
        "sequence":[AuthnRequest, NameIDMappingRequest],
        "depend":["authn"]
    },
    'manage_nameid_nid-transient':{
        "tc_id": "S2c-16",
        "name": "ManageNameID; set NameID; AuthRequ/NameID-trans",
        "descr": "Setting the SP provided ID by using ManageNameID",
        "sequence":[AuthnRequestNID_Transient, ManageNameIDRequest],
        "depend":["authn"]
    },
    'authn-authn_query': {
        "tc_id": "S2c-17",
        "name": 'AuthnRequest then AuthnQuery',
        "descr": 'AuthnRequest followed by an AuthnQuery',
        "sequence": [AuthnRequest, AuthnQuery],
        "tests": {"pre": [CheckSaml2IntMetaData],  "post": []},
        "depend":["authn"]
    },
}