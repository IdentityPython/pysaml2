from saml2 import samlp
from saml2 import NAMEID_FORMAT_EMAILADDRESS
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.s_utils import rndstr

from saml2.saml import AUTHN_PASSWORD, SCM_BEARER
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import SCM_SENDER_VOUCHES
from saml2.samlp import STATUS_AUTHN_FAILED
from sp_test.check import VerifyContent
from sp_test import check

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

    def pre_processing(self, message, *kwargs):
        return message

    def post_processing(self, message, *kwargs):
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


class AuthnResponse_NameIDformat_persistent(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        name_id = message.assertion.subject.name_id
        name_id.name_format = NAMEID_FORMAT_PERSISTENT
        return message


class AuthnResponse_NameIDformat_email(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        name_id = message.assertion.subject.name_id
        name_id.name_format = NAMEID_FORMAT_EMAILADDRESS
        name_id.text = "adam@example.com"
        return message


class AuthnResponse_NameIDformat_foo(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        name_id = message.assertion.subject.name_id
        name_id.name_format = "foo"
        name_id.text = "fruit basket"
        return message


class AuthnResponse_without_SubjectConfirmationData_1(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation.subject_confirmation_data = None
        _confirmation.method = SCM_SENDER_VOUCHES
        return message


class AuthnResponse_without_SubjectConfirmationData_2(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation.subject_confirmation_data = None
        _confirmation.method = SCM_BEARER
        return message


class AuthnResponse_rnd_Response_inresponseto(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.in_response_to = rndstr(16)
        return message


class AuthnResponse_rnd_Response_assertion_inresponseto(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.assertion.in_response_to = rndstr(16)
        return message


class AuthnResponse_SubjectConfirmationData_no_inresponse(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation.subject_confirmation_data.in_response_to = None
        return message


class AuthnResponse_broken_destination(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.destination = "NotAUrl"
        return message


PHASES = {
    "login_redirect": (Login, AuthnRequest, AuthnResponse_redirect),
}

OPERATIONS = {
    'sp-00': {
        "name": 'Basic Login test',
        "descr": 'Basic Login test',
        "sequence": [(Login, AuthnRequest, AuthnResponse, None)],
        "tests": {"pre": [], "post": []}
    },
    'verify': {
        "name": 'Verify various aspects of the generated AuthnRequest message',
        "descr": 'Basic Login test',
        "sequence": [],
        "tests": {"pre": [], "post": []}
    },
    'sp-01': {
        "name": """SP should not accept a Response as valid, when the
StatusCode is not success""",
        "sequence": [(Login, AuthnRequest, ErrorResponse, check.ErrorResponse)],
        "tests": {"pre": [], "post": []}
    },
    'sp-02': {
        "name": "SP should accept a NameID with Format: persistent",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_NameIDformat_persistent, None)],
        "tests": {"pre": [], "post": []}
    },
    'sp-03': {
        "name": "SP should accept a NameID with Format: e-mail",
        "sequence": [(Login, AuthnRequest, AuthnResponse_NameIDformat_email,
                      None)],
        "tests": {"pre": [], "post": []}
    },
    'sp-04': {
        "name": "Do SP work with unknown NameID Format, such as : foo",
        "sequence": [(Login, AuthnRequest, AuthnResponse_NameIDformat_foo,
                      None)],
        "tests": {"pre": [], "post": []}
    },
    'sp-05': {
        "name": ("SP should accept a Response without a ",
                 "SubjectConfirmationData element. If confirmation method",
                 "is SCM_SENDER_VOUCHES"),
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_without_SubjectConfirmationData_1, None)],
        "tests": {"pre": [], "post": []}
    },
    'sp-06': {
        "name": ("SP should not accept a response InResponseTo ",
                 "which is chosen randomly"),
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_rnd_Response_inresponseto,
                      check.ErrorResponse)],
        "tests": {"pre": [], "post": []}
    },
    'sp-07': {
        "name": ("SP should not accept an assertion InResponseTo ",
                 "which is chosen randomly"),
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_rnd_Response_assertion_inresponseto,
                      check.ErrorResponse)],
        "tests": {"pre": [], "post": []}
    },
    'sp-08': {
        "name": ("SP should accept a Response without a ",
                 "SubjectConfirmationData element. If confirmation method",
                 "is SCM_SENDER_VOUCHES"),
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_without_SubjectConfirmationData_2,
                      check.ErrorResponse)],
        "tests": {"pre": [], "post": []}
    },
    'sp-09': {
        "name": ("Do the SP allow the InResponseTo attribute to be missing",
                 "from the SubjectConfirmationData element?"),
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_SubjectConfirmationData_no_inresponse,
                      check.ErrorResponse)],
        "tests": {"pre": [], "post": []}
    },
    'sp-10': {
        "name": "SP should not accept a broken DestinationURL attribute",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_broken_destination,
                      check.ErrorResponse)],
        "tests": {"pre": [], "post": []}
    },
}

#￼
# ￼SP should not accept a broken Recipient attribute in assertion SubjectConfirmationData/@Recipient
# ￼SP should not accept a broken DestinationURL attribute in response
# ￼SP should accept a Response with two SubjectConfirmationData elements representing two recipients (test 1 of 2, correct one last)
# ￼SP should accept a Response with two SubjectConfirmationData elements representing two recipients (test 1 of 2, correct one first)
# ￼SP should accept a Response with two SubjectConfirmation elements representing two recipients (test 1 of 2, correct one last)
# ￼SP should accept a Response with two SubjectConfirmation elements representing two recipients (test 1 of 2, correct one first)
# ￼SP should accept a Response with a SubjectConfirmationData elements with a correct @Address attribute
# ￼SP should nnot accept a Response with a SubjectConfirmationData elements with a incorrect @Address attribute
# ￼SP should accept a Response with multiple SubjectConfirmation elements with /SubjectConfirmationData/@Address-es, where one is correct (test 1 of 2, correct o last)
# ￼SP should accept a Response with multiple SubjectConfirmationData elements with /SubjectConfirmationData/@Address-es, where one is correct (test 1 of 2, corr one last)
# ￼SP should accept a Response with multiple SubjectConfirmationData elements with /SubjectConfirmationData/@Address-es, where one is correct (test 1 of 2, corr one first)
# ￼SP Should not accept an assertion containing an uknown Condition
# ￼SP should not accept a Response with a Condition with a NotBefore in the future.
# ￼SP should not accept a Response with a Condition with a NotOnOrAfter in the past.
# ￼SP should not accept a Response with a SubjectConfirmationData@NotOnOrAfter in the past
# ￼SP should not accept a Response with a AuthnStatement where SessionNotOnOrAfter is set in the past
# ￼SP should not accept a Response with a AuthnStatement missing
# ￼SP should not accept an IssueInstant far (24 hours) into the future
# ￼SP should not accept an IssueInstant far (24 hours) into the past
# ￼SP should accept xs:datetime with millisecond precision http://www.w3.org/TR/xmlschema-2/#dateTime
# ￼SP should accept xs:datetime with microsecond precision http://www.w3.org/TR/xmlschema-2/#dateTime
# ￼SP should not accept a Response with a Condition with a empty set of Audience.
# ￼SP should not accept a Response with a Condition with a wrong Audience.
# ￼SP should accept a Response with a Condition with an addition Audience prepended.
# ￼SP should accept a Response with a Condition with an addition Audience appended.
# ￼SP should not accept multiple AudienceRestrictions where the intersection is zero. (test 1 of 2)
# ￼SP should not accept multiple AudienceRestrictions where the intersection is zero. (test 2 of 2)
# ￼SP should accept multiple AudienceRestrictions where the intersection includes the correct audience.
# ￼SP should accept that only the Assertion is signed instead of the Response.
# ￼SP should accept that both the Response and the Assertion is signed.
# ￼Do SP work when RelayState information is lost?
# ￼Do SP accept an unknown Extensions element in the Response?
# ￼SP MUST not accept response when the saml-namespace is invalid
# ￼SP MUST NOT re-use the same ID in subsequent requests.
# ￼SP MUST NOT accept a replayed Response. An identical Response/Assertion used a second time. [Profiles]: 4.1.4.5 POST-Specific Processing Rules (test 1 of 2: s inresponseto)
# ￼SP MUST NOT accept a replayed Response. An identical Response/Assertion used a second time. [Profiles]: 4.1.4.5 POST-Specific Processing Rules (test 2 of 2: unsolicited response)
# ￼SP SHOULD find attributes in a second AttributeStatement, not only in the first.
# ￼SP SHOULD NOT accept an signed assertion embedded in an AttributeValue inside an unsigned assertion.
# ￼SP SHOULD NOT accept an signed assertion embedded in an AttributeValue inside an unsigned assertion. (Signature moved out...)
# ￼SP SHOULD NOT accept an signed assertion, where the signature is referring to another assertion.
# ￼SP SHOULD find attributes in a second Assertion/AttributeStatement, not only in one of them (test 1 of 2 - attributes in first).
# ￼SP SHOULD find attributes in a second Assertion/AttributeStatement, not only in one of them (test 2 of 2 - attributes in last).
# ￼SP SHOULD NOT accept attributes in unsigned 2nd assertion. (test 1 of 2)
# ￼SP SHOULD NOT accept attributes in unsigned 2nd assertion. (test 2 of 2)
# ￼SP SHOULD NOT accept authnstatement in unsigned 2nd assertion. (test 1 of 2)
# ￼SP SHOULD NOT accept authnstatement in unsigned 2nd assertion. (test 2 of 2)
# ￼Basic SP-initated Logout Test
# ￼Basic IdP-initated Logout Test
# ￼SP MUST NOT accept LogoutRequest when NameID content is wrong
# ￼SP MUST NOT accept LogoutRequest when NameID@Format is wrong
# ￼SP MUST NOT accept LogoutRequest when NameID@SPNameQualifier is wrong
# ￼SP MUST NOT logout user when invalid SessionIndex is sent
# ￼SP MUST NOT accept LogoutRequest when Issuer is wrong
# ￼SP MUST NOT accept LogoutRequest when Destination is wrong
# ￼SP MUST NOT accept unsigned LogoutRequest
# ￼SP MUST accept LogoutRequest with sessionindex in a separate session, not relying on the session-cookie.
# ￼SP MUST accept an LogoutRequest with no sessionindex (sent in separate session, no session-cookies)
# ￼SP MUST accept an LogoutRequest with two sesionindexes (first valid) (sent in separate session, no session-cookies)
# ￼SP MUST accept an LogoutRequest with two sesionindexes (second valid) (sent in separate session, no session-cookies)
# ￼Session fixtation check