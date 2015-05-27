import copy
from saml2 import samlp, SamlBase
from saml2 import NAMEID_FORMAT_EMAILADDRESS
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.s_utils import rndstr

from saml2.saml import SCM_BEARER, Condition, XSI_TYPE, Audience
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import SCM_SENDER_VOUCHES
from saml2.saml import ConditionAbstractType_
from saml2.samlp import STATUS_AUTHN_FAILED
from saml2.time_util import in_a_while, a_while_ago
from sp_test import check
from sp_test.check import VerifyAuthnRequest, VerifyDigestAlgorithm
from sp_test.check import VerifySignatureAlgorithm, VerifyIfRequestIsSigned
from sp_test.check import SetResponseAndAssertionSignaturesFalse
from saml2test.check import CheckSpHttpResponseOK, CheckSpHttpResponse500
from saml2test import ip_addresses

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


# Extension class - extra condition
class TimeRestriction(ConditionAbstractType_):
    """ """

    c_tag = 'TimeRestriction'
    c_namespace = "urn:mace:umu.se:sso"
    c_children = ConditionAbstractType_.c_children.copy()
    c_attributes = ConditionAbstractType_.c_attributes.copy()
    c_child_order = ConditionAbstractType_.c_child_order[:]
    c_cardinality = ConditionAbstractType_.c_cardinality.copy()
    c_attributes['StartTime'] = ('start_time', 'time', False)
    c_attributes['EndTime'] = ('end_time', 'time', False)

    def __init__(self,
                 start_time=None,
                 end_time=None,
                 text=None,
                 extension_elements=None,
                 extension_attributes=None):
        ConditionAbstractType_.__init__(
            self, text=text, extension_elements=extension_elements,
            extension_attributes=extension_attributes)
        self.start_time = start_time
        self.end_time = end_time


# =============================================================================


class Response(object):
    _args = {}
    _class = samlp.Response
    _sign = False
    tests = {"pre": [], "post": []}

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
    tests = {"pre": [],
             "mid": [VerifyAuthnRequest],
             "post": []}

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
        message.in_response_to = "invalid_rand_" + rndstr(6)
        return message


class AuthnResponse_rnd_Response_assertion_inresponseto(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.assertion.in_response_to = "invalid_rand_" + rndstr(6)
        return message


class AuthnResponse_Response_no_inresponse(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.in_response_to = None
        return message


class AuthnResponse_SubjectConfirmationData_no_inresponse(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation[0].subject_confirmation_data.in_response_to = None
        return message


class AuthnResponse_wrong_Recipient(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation[0].subject_confirmation_data.recipient = rndstr(16)
        return message


class AuthnResponse_missing_Recipient(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation[0].subject_confirmation_data.recipient = None
        return message


class AuthnResponse_missing_Recipient(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation[0].subject_confirmation_data.recipient = None
        return message


class AuthnResponse_broken_destination(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.destination = "NotAUrl"
        return message


class AuthnResponse_correct_recipient_address(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        if "localhost" in self.conv.entity_id:
            addr = "127.0.0.1"
        else:
            addr = ip_addresses()[0]
        _confirmation[0].subject_confirmation_data.address = addr
        return message


class AuthnResponse_incorrect_recipient_address(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        _confirmation[0].subject_confirmation_data.address = "10.0.0.1"
        return message


class AuthnResponse_2_recipients_me_last(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        sc = copy.copy(_confirmation[0])
        if "localhost" in self.conv.entity_id:
            addr = "127.0.0.1"
        else:
            addr = ip_addresses()[0]
        sc.subject_confirmation_data.address = addr
        _confirmation.insert(0, sc)
        return message


class AuthnResponse_2_recipients_me_first(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation
        sc = copy.copy(_confirmation[0])
        if "localhost" in self.conv.entity_id:
            addr = "127.0.0.1"
        else:
            addr = ip_addresses()[0]
        sc.subject_confirmation_data.address = addr
        _confirmation.append(sc)
        return message


class AuthnResponse_unknown_condition(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        conditions = message.assertion.conditions
        conditions.condition = [Condition(
            extension_elements=[TimeRestriction(start_time="08:00:00",
                                                end_time="17:00:00")],
            extension_attributes={XSI_TYPE: "foo:bas"})]
        return message


class AuthnResponse_future_NotBefore(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        conditions = message.assertion.conditions
        # Valid starting five hours from now
        conditions.not_before = in_a_while(hours=5)
        return message


class AuthnResponse_past_NotOnOrAfter(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        conditions = message.assertion.conditions
        # Valid up until five hours ago
        conditions.not_on_or_after = a_while_ago(hours=5)
        return message


class AuthnResponse_past_SubjectConfirmationData_NotOnOrAfter(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation[0]
        _confirmation.subject_confirmation_data.not_on_or_after = a_while_ago(
            hours=5)
        return message


class AuthnResponse_future_SubjectConfirmationData_NotBefore(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _confirmation = message.assertion.subject.subject_confirmation[0]
        _confirmation.subject_confirmation_data.not_before = in_a_while(
            hours=5)
        return message


class AuthnResponse_past_AuthnStatement_SessionNotOnOrAfter(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        _statement = message.assertion.authn_statement[0]
        _statement.session_not_on_or_after = a_while_ago(hours=5)
        return message


class AuthnResponse_missing_AuthnStatement(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.assertion.authn_statement = []
        return message


class AuthnResponse_future_24h_IssueInstant(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.assertion.issue_instant = in_a_while(hours=24)
        return message


class AuthnResponse_past_24h_IssueInstant(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.assertion.issue_instant = a_while_ago(hours=24)
        return message


class AuthnResponse_datetime_millisecond(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        message.assertion.issue_instant = in_a_while(milliseconds=123)
        return message


class AuthnResponse_AudienceRestriction_no_audience(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        conditions = message.assertion.conditions
        conditions.audience_restriction[0].audience = None
        return message


class AuthnResponse_AudienceRestriction_wrong_audience(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        conditions = message.assertion.conditions
        conditions.audience_restriction[0].audience = [
            Audience("http://saml.example.com")]
        return message


class AuthnResponse_AudienceRestriction_prepended_audience(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        conditions = message.assertion.conditions
        extra = Audience("http://saml.example.com")
        conditions.audience_restriction[0].audience.insert(0, extra)
        return message


class AuthnResponse_AudienceRestriction_appended_audience(AuthnResponse):
    def pre_processing(self, message, **kwargs):
        conditions = message.assertion.conditions
        extra = Audience("http://saml.example.com")
        conditions.audience_restriction[0].audience.append(extra)
        return message


PHASES = {
    "login_redirect": (Login, AuthnRequest, AuthnResponse_redirect),
}

# Each operation defines 4 flows and 3 sets of tests, in chronological order:
# test "pre": executes before anything is sent to the SP
# flow 0: Start conversation flow
# flow 1: SAML request flow
# test "mid": executes after receiving the SAML request
# flow 2: SAML response flow
# flow 3: check SP response after authentication
# test "post": executes after finals response has been received from SP

OPERATIONS = {
    'sp-00': {
        "name": 'Basic Login test expect HTTP 200 result',
        "descr": 'WebSSO verify authentication request, verify '
                 'HTTP-Response after sending the SAML response',
        "sequence": [(Login, AuthnRequest, AuthnResponse, CheckSpHttpResponseOK)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'sp-01': {
        "name": 'Login OK & echo page verification test',
        "descr": 'Same as SP-00, then check if result page is displayed',
        "sequence": [(Login, AuthnRequest, AuthnResponse, check.VerifyEchopageContents)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'sp-02': {
        "name": 'Require AuthnRequest to be signed',
        "descr": 'Same as SP-00, and check if a request signature can be found',
        "sequence": [(Login, AuthnRequest, AuthnResponse, None)],
        "tests": {"pre": [], "mid": [VerifyIfRequestIsSigned], "post": []}
    },
    'sp-03': {
        "name": 'Reject unsigned reponse/assertion',
        "descr": 'Check if SP flags missing signature with HTTP 500',
        "sequence": [(Login, AuthnRequest, AuthnResponse, CheckSpHttpResponse500)],
        "tests": {"pre": [SetResponseAndAssertionSignaturesFalse], "mid": [], "post": []}
    },
    'sp-04': {  # test-case specific code in sp_test/__init__
        "name": 'Reject siganture with invalid IDP key',
        "descr": 'IDP-key for otherwise valid signature not in metadata - expect HTTP 500 result',
        "sequence": [(Login, AuthnRequest, AuthnResponse, CheckSpHttpResponse500)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'sp-05': {
        "name": 'Verify digest algorithm',
        "descr": 'Trigger WebSSO AuthnRequest and verify that the used '
                 'digest algorithm was one from the approved set.',
        "sequence": [(Login, AuthnRequest, AuthnResponse, None)],
        "tests": {"pre": [], "mid": [VerifyDigestAlgorithm], "post": []}
    },
    'sp-06': {
        "name": 'Verify signature algorithm',
        "descr": 'Trigger WebSSO AuthnRequest and verify that the used '
                 'signature algorithm was one from the approved set.',
        "sequence": [(Login, AuthnRequest, AuthnResponse, None)],
        "tests": {"pre": [], "mid": [VerifySignatureAlgorithm], "post": []}
    },
    'sp-08': {
        "name": "SP should accept a Response without a "
                 "SubjectConfirmationData element. If confirmation method"
                 "is SCM_SENDER_VOUCHES",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_without_SubjectConfirmationData_2,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL02': {
        "name": 'Verify various aspects of the generated AuthnRequest message',
        "descr": 'Basic Login test',
        "sequence": [],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL03': {
        "name": "SP should not accept a Response as valid, when the StatusCode"
                " is not success",
        "sequence": [(Login, AuthnRequest, ErrorResponse, check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL04': {
        "name": "SP should accept a NameID with Format: persistent",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_NameIDformat_persistent, None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL05': {
        "name": "SP should accept a NameID with Format: e-mail",
        "sequence": [(Login, AuthnRequest, AuthnResponse_NameIDformat_email,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL06': {
        "name": "Do SP work with unknown NameID Format, such as : foo",
        "sequence": [(Login, AuthnRequest, AuthnResponse_NameIDformat_foo,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL07': {
        "name": "SP should accept a Response without a "
                 "SubjectConfirmationData element. If confirmation method "
                 "is SCM_SENDER_VOUCHES",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_without_SubjectConfirmationData_1, None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL09': {
        "name": "SP should not accept a response InResponseTo "
                "which is chosen randomly",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_rnd_Response_inresponseto,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL10': {
        "name": "SP should not accept an assertion InResponseTo "
                 "which is chosen randomly",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_rnd_Response_assertion_inresponseto,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL11': {
        "name": "Does the SP allow the InResponseTo attribute to be missing"
                "from the Response element?",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_Response_no_inresponse,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL12': {
        "name": "Does the SP allow the InResponseTo attribute to be missing"
                "from the SubjectConfirmationData element?"
                "(Test is questionable - review)",  # TODO
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_SubjectConfirmationData_no_inresponse,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL13': {
        "name": "SP should not accept a broken DestinationURL attribute",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_broken_destination,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    # New untested
    'FL14a': {
        "name": "SP should not accept wrong Recipient attribute",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_broken_destination,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL14b': {
        "name": "SP should not accept missing Recipient attribute",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_missing_Recipient,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL20': {
        "name": "Accept a Response with a SubjectConfirmationData elements "
                "with a correct @Address attribute",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_correct_recipient_address,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL21': {
        "name": "Accept a Response with a SubjectConfirmationData elements "
                "with a incorrect @Address attribute",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_incorrect_recipient_address,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL22': {
        "name": "Accept a Response with two SubjectConfirmationData elements"
                "representing two recipients (test 1 of 2, correct one last)",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_2_recipients_me_last,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL23': {
        "name": "Accept a Response with two SubjectConfirmationData elements"
                "representing two recipients (test 1 of 2, correct one last)",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_2_recipients_me_first,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL26': {
        "name": "Reject an assertion containing an unknown Condition.",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_unknown_condition,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL27': {
        "name": "Reject a Response with a Condition with a NotBefore in the "
                "future.",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_future_NotBefore,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL28': {
        "name": "Reject a Response with a Condition with a NotOnOrAfter in "
                "the past.",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_future_NotBefore,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL29': {
        "name": "Reject a Response with a SubjectConfirmationData@NotOnOrAfter "
                "in the past",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_past_SubjectConfirmationData_NotOnOrAfter,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL24': {
        "name": "Reject a Response with a SubjectConfirmationData@NotBefore "
                "in the future",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_future_SubjectConfirmationData_NotBefore,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL30': {
        "name": "Reject a Response with an AuthnStatement where "
                "SessionNotOnOrAfter is set in the past.",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_past_AuthnStatement_SessionNotOnOrAfter,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL31': {
        "name": "Reject a Response with an AuthnStatement missing",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_missing_AuthnStatement,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL32': {
        "name": "Reject an IssueInstant far (24 hours) into the future",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_future_24h_IssueInstant,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL33': {
        "name": "Reject an IssueInstant far (24 hours) into the past",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_past_24h_IssueInstant,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL34': {
        "name": "Accept xs:datetime with millisecond precision "
                "http://www.w3.org/TR/xmlschema-2/#dateTime",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_datetime_millisecond,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL36': {
        "name": "Reject a Response with a Condition with a empty set of "
                "Audience.",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_AudienceRestriction_no_audience,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL37': {
        "name": "Reject a Response with a Condition with a wrong Audience.",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_AudienceRestriction_wrong_audience,
                      check.ErrorResponse)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL38': {
        "name": "Accept a Response with a Condition with an additional "
                "Audience prepended",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_AudienceRestriction_prepended_audience,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
    'FL39': {
        "name": "Accept a Response with a Condition with an additional "
                "Audience appended",
        "sequence": [(Login, AuthnRequest,
                      AuthnResponse_AudienceRestriction_appended_audience,
                      None)],
        "tests": {"pre": [], "mid": [], "post": []}
    },
}

#
# SP should not accept a broken Recipient attribute in assertion
# SubjectConfirmationData/@Recipient
# SP should not accept a broken DestinationURL attribute in response
# SP should accept a Response with two SubjectConfirmationData elements
# representing two recipients (test 1 of 2, correct one last)
# SP should accept a Response with two SubjectConfirmationData elements
# representing two recipients (test 1 of 2, correct one first)
# SP should accept a Response with two SubjectConfirmation elements
# representing two recipients (test 1 of 2, correct one last)
# SP should accept a Response with two SubjectConfirmation elements
# representing two recipients (test 1 of 2, correct one first)
# SP should accept a Response with a SubjectConfirmationData elements with a
#  correct @Address attribute
# SP should nnot accept a Response with a SubjectConfirmationData elements
# with a incorrect @Address attribute
# SP should accept a Response with multiple SubjectConfirmation elements
# with /SubjectConfirmationData/@Address-es, where one is correct (test 1 of
# 2, correct o last)
# SP should accept a Response with multiple SubjectConfirmationData elements
#  with /SubjectConfirmationData/@Address-es, where one is correct (test 1 of
#  2, corr one last)
# SP should accept a Response with multiple SubjectConfirmationData elements
#  with /SubjectConfirmationData/@Address-es, where one is correct (test 1 of
#  2, corr one first)
# SP Should not accept an assertion containing an uknown Condition
# SP should not accept a Response with a Condition with a NotBefore in the
# future.
# SP should not accept a Response with a Condition with a NotOnOrAfter in
# the past.
# SP should not accept a Response with a
# SubjectConfirmationData@NotOnOrAfter in the past
# SP should not accept a Response with a AuthnStatement where
# SessionNotOnOrAfter is set in the past
# SP should not accept a Response with a AuthnStatement missing
# SP should not accept an IssueInstant far (24 hours) into the future
# SP should not accept an IssueInstant far (24 hours) into the past
# SP should accept xs:datetime with millisecond precision http://www.w3
# .org/TR/xmlschema-2/#dateTime
# SP should accept xs:datetime with microsecond precision http://www.w3
# .org/TR/xmlschema-2/#dateTime
# SP should not accept a Response with a Condition with a empty set of
# Audience.
# SP should not accept a Response with a Condition with a wrong Audience.
# SP should accept a Response with a Condition with an addition Audience
# prepended.
# SP should accept a Response with a Condition with an addition Audience
# appended.
# SP should not accept multiple AudienceRestrictions where the intersection
# is zero. (test 1 of 2)
# SP should not accept multiple AudienceRestrictions where the intersection
# is zero. (test 2 of 2)
# SP should accept multiple AudienceRestrictions where the intersection
# includes the correct audience.
# SP should accept that only the Assertion is signed instead of the Response.
# SP should accept that both the Response and the Assertion is signed.
# Do SP work when RelayState information is lost?
# Do SP accept an unknown Extensions element in the Response?
# SP MUST not accept response when the saml-namespace is invalid
# SP MUST NOT re-use the same ID in subsequent requests.
# SP MUST NOT accept a replayed Response. An identical Response/Assertion
# used a second time. [Profiles]: 4.1.4.5 POST-Specific Processing Rules (
# test 1 of 2: s inresponseto)
# SP MUST NOT accept a replayed Response. An identical Response/Assertion
# used a second time. [Profiles]: 4.1.4.5 POST-Specific Processing Rules (
# test 2 of 2: unsolicited response)
# SP SHOULD find attributes in a second AttributeStatement, not only in the
# first.
# SP SHOULD NOT accept an signed assertion embedded in an AttributeValue
# inside an unsigned assertion.
# SP SHOULD NOT accept an signed assertion embedded in an AttributeValue
# inside an unsigned assertion. (Signature moved out...)
# SP SHOULD NOT accept an signed assertion, where the signature is referring
#  to another assertion.
# SP SHOULD find attributes in a second Assertion/AttributeStatement,
# not only in one of them (test 1 of 2 - attributes in first).
# SP SHOULD find attributes in a second Assertion/AttributeStatement,
# not only in one of them (test 2 of 2 - attributes in last).
# SP SHOULD NOT accept attributes in unsigned 2nd assertion. (test 1 of 2)
# SP SHOULD NOT accept attributes in unsigned 2nd assertion. (test 2 of 2)
# SP SHOULD NOT accept authnstatement in unsigned 2nd assertion. (test 1 of 2)
# SP SHOULD NOT accept authnstatement in unsigned 2nd assertion. (test 2 of 2)
# Basic SP-initated Logout Test
# Basic IdP-initated Logout Test
# SP MUST NOT accept LogoutRequest when NameID content is wrong
# SP MUST NOT accept LogoutRequest when NameID@Format is wrong
# SP MUST NOT accept LogoutRequest when NameID@SPNameQualifier is wrong
# SP MUST NOT logout user when invalid SessionIndex is sent
# SP MUST NOT accept LogoutRequest when Issuer is wrong
# SP MUST NOT accept LogoutRequest when Destination is wrong
# SP MUST NOT accept unsigned LogoutRequest
# SP MUST accept LogoutRequest with sessionindex in a separate session,
# ot relying on the session-cookie.
# SP MUST accept an LogoutRequest with no sessionindex (sent in separate
# session, no session-cookies)
# SP MUST accept an LogoutRequest with two sesionindexes (first valid) (sent
#  in separate session, no session-cookies)
# SP MUST accept an LogoutRequest with two sesionindexes (second valid) (
# sent in separate session, no session-cookies)
# Session fixtation check