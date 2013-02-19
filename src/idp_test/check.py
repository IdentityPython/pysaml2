import inspect
import sys
import traceback

from rrtest.check import CriticalError
from rrtest.check import Check

from saml2.mdstore import REQ2SRV
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAME_FORMAT_UNSPECIFIED
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAME_FORMAT_URI
from saml2.samlp import STATUS_SUCCESS
from saml2.samlp import Response
from saml2.sigver import cert_from_key_info_dict
from saml2.sigver import key_from_key_value_dict

__author__ = 'rolandh'

INFORMATION = 0
OK = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
INTERACTION = 5

STATUSCODE = ["INFORMATION", "OK", "WARNING", "ERROR", "CRITICAL",
              "INTERACTION"]


class WrapException(CriticalError):
    """
    A runtime exception
    """
    cid = "exception"
    msg = "Test tool exception"

    def _func(self, conv=None):
        self._status = self.status
        self._message = traceback.format_exception(*sys.exc_info())
        return {}


class InteractionNeeded(CriticalError):
    """
    A Webpage was displayed for which no known interaction is defined.
    """
    cid = "interaction-needed"
    msg = "Unexpected page"

    def _func(self, conv=None):
        self._status = self.status
        self._message = None
        return {"url": conv.position}


class CheckHTTPResponse(CriticalError):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    cid = "check-http-response"
    msg = "IdP error"

    def _func(self, conv):
        _response = conv.response

        res = {}
        if _response.status_code >= 400:
            self._status = self.status
            self._message = self.msg
            res["url"] = conv.position
            res["http_status"] = _response.status_code
            res["content"] = _response.text

        return res


class CheckSaml2IntMetaData(Check):
    """
    Checks that the Metadata follows the Saml2Int profile
    """
    cid = "check-saml2int-metadata"
    msg = "Metadata error"

    def verify_key_info(self, ki):
        # key_info
        # one or more key_value and/or x509_data.X509Certificate

        xkeys = cert_from_key_info_dict(ki)
        vkeys = key_from_key_value_dict(ki)

        if xkeys or vkeys:
            pass
        else:
            self._message = "Missing KeyValue or X509Data.X509Certificate"
            self._status = CRITICAL
            return False

        if xkeys and vkeys:
            # verify that it's the same keys TODO
            pass

        return True

    def verify_key_descriptor(self, kd):
        # key_info
        if not self.verify_key_info(kd["key_info"]):
            return False

        # use
        if "use" in kd:
            try:
                assert kd["use"] in ["encryption", "signing"]
            except AssertionError:
                self._message = "Unknown use specification: '%s'" % kd.use.text
                self._status = CRITICAL
                return False

        return True

    def _func(self, conv):
        mds = conv.client.metadata.metadata[0]
        # Should only be one
        ed = mds.entity.values()[0]
        res = {}

        assert len(ed["idpsso_descriptor"])
        idpsso = ed["idpsso_descriptor"][0]
        for kd in idpsso["key_descriptor"]:
            if not self.verify_key_descriptor(kd):
                return res

        # contact person
        if "contact_person" not in idpsso and "contact_person" not in ed:
            self._message = "Metadata should contain contact person information"
            self._status = WARNING
            return res
        else:
            item = {"support": False, "technical": False}
            if "contact_person" in idpsso:
                for contact in idpsso["contact_person"]:
                    try:
                        item[contact["contact_type"]] = True
                    except KeyError:
                        pass
            if "contact_person" in ed:
                for contact in ed["contact_person"]:
                    try:
                        item[contact["contact_type"]] = True
                    except KeyError:
                        pass

            if "support" in item and "technical" in item:
                pass
            elif "support" not in item and "technical" not in item:
                self._message = \
                    "Missing technical and support contact information"
                self._status = WARNING
            elif "technical" not in item:
                self._message = "Missing technical contact information"
                self._status = WARNING
            elif "support" not in item:
                self._message = "Missing support contact information"
                self._status = WARNING

            if self._message:
                return res

        # NameID format
        if "name_id_format" not in idpsso:
            self._message = "Metadata should specify NameID format support"
            self._status = WARNING
            return res
        else:
            # should support Transient
            item = {NAMEID_FORMAT_TRANSIENT: False}
            for nformat in idpsso["name_id_format"]:
                try:
                    item[nformat["text"]] = True
                except KeyError:
                    pass

            if not item[NAMEID_FORMAT_TRANSIENT]:
                self._message = "IdP should support Transient NameID Format"
                self._status = WARNING
                return res

        return res


class CheckSaml2IntAttributes(Check):
    """
    Any <saml2:Attribute> elements exchanged via any SAML 2.0 messages,
    assertions, or metadata MUST contain a NameFormat of
    urn:oasis:names:tc:SAML:2.0:attrname-format:uri.
    """
    cid = "check-saml2int-attributes"
    msg = "Attribute error"

    def _func(self, conv):
        response = conv.saml_response[-1]
        try:
            opaque_identifier = conv.opaque_identifier
        except AttributeError:
            opaque_identifier = False
        try:
            name_format_not_specified = conv.name_format_not_specified
        except AttributeError:
            name_format_not_specified = False

        res = {}

        # should be a list but isn't
        #assert len(response.assertion) == 1
        assertion = response.assertion
        assert len(assertion.authn_statement) == 1
        assert len(assertion.attribute_statement) < 2

        if assertion.attribute_statement:
            atrstat = assertion.attribute_statement[0]
            for attr in atrstat.attribute:
                try:
                    assert attr.name_format == NAME_FORMAT_URI
                except AssertionError:
                    self._message = "Attribute name format error"
                    self._status = CRITICAL
                    return res
                try:
                    assert attr.name.startswith("urn:oid")
                except AssertionError:
                    self._message = "Attribute name should be an OID"
                    self._status = CRITICAL
                    return res

        assert not assertion.subject.encrypted_id
        assert not assertion.subject.base_id

        if opaque_identifier:
            try:
                assert assertion.subject.name_id.format == \
                    NAMEID_FORMAT_PERSISTENT
            except AssertionError:
                self._message = "NameID format should be PERSISTENT"
                self._status = WARNING

        if name_format_not_specified:
            try:
                assert assertion.subject.name_id.format == \
                    NAMEID_FORMAT_TRANSIENT
            except AssertionError:
                self._message = "NameID format should be TRANSIENT"
                self._status = WARNING

        return res


class CheckSubjectNameIDFormat(Check):
    """
    The <NameIDPolicy> element tailors the name identifier in the subjects of
    assertions resulting from an <AuthnRequest>.
    When this element is used, if the content is not understood by or acceptable
    to the identity provider, then a <Response> message element MUST be
    returned with an error <Status>, and MAY contain a second-level
    <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy.
    If the Format value is omitted or set to urn:oasis:names:tc:SAML:2.0:nameid-
    format:unspecified, then the identity provider is free to return any kind
    of identifier, subject to any additional constraints due to the content of
    this element or the policies of the identity provider or principal.
    """
    cid = "check-saml2int-nameid-format"
    msg = "Attribute error"

    def _func(self, conv):
        response = conv.saml_response[-1].response
        request = conv.request

        res = {}
        if request.name_id_policy:
            nformat = request.name_id_policy.format
            sp_name_qualifier = request.name_id_policy.sp_name_qualifier

            subj = response.assertion.subject
            try:
                assert subj.name_id.format == nformat
                if sp_name_qualifier:
                    assert subj.name_id.sp_name_qualifier == sp_name_qualifier
            except AssertionError:
                self._message = "The IdP returns wrong NameID format"
                self._status = CRITICAL

        return res


class CheckLogoutSupport(Check):
    """
    Verifies that the tested entity supports single log out
    """
    cid = "check-logout-support"
    msg = "Does not support logout"

    def _func(self, conv):
        mds = conv.client.metadata.metadata[0]
        # Should only be one
        ed = mds.entity.values()[0]

        assert len(ed["idpsso_descriptor"])

        idpsso = ed["idpsso_descriptor"][0]
        try:
            assert idpsso["single_logout_service"]
        except AssertionError:
            self._message = self.msg
            self._status = CRITICAL

        return {}


class VerifyLogout(Check):
    cid = "verify-logout"
    msg = "Logout failed"

    def _func(self, conv):
        # Check that the logout response says it was a success
        resp = conv.saml_response[-1]
        status = resp.response.status
        try:
            assert status.status_code.value == STATUS_SUCCESS
        except AssertionError:
            self._message = self.msg
            self._status = CRITICAL

        # Check that there are no valid cookies
        # should only result in a warning
        httpc = conv.client
        try:
            assert httpc.cookies(conv.destination) == {}
        except AssertionError:
            self._message = "Remaining cookie ?"
            self._status = WARNING

        return {}


class VerifyContent(Check):
    """ Basic content verification class, does required and max/min checks
    """
    cid = "verify-content"

    def _func(self, conv):
        try:
            conv.saml_response[-1].response.verify()
        except ValueError:
            self._status = CRITICAL

        return {}


class VerifySuccessStatus(Check):
    """ Verifies that the response was a success response """
    cid = "verify-success-status"

    def _func(self, conv):
        response = conv.saml_response[-1].response

        try:
            assert response.status.status_code.value == STATUS_SUCCESS
        except AssertionError:
            self._message = self.msg
            self._status = CRITICAL

        return {}


class VerifyNameIDPolicyUsage(Check):
    """
    Verify the nameID in the response is according to the provided
    NameIDPolicy
    """
    cid = "verify-name-id-policy-usage"

    def _func(self, conv):
        response = conv.saml_response[-1].response
        nip = conv.oper.args["name_id_policy"]
        for assertion in response.assertion:
            nid = assertion.subject.name_id
            if nip.format:
                try:
                    assert nid.format == nip.format
                except AssertionError:
                    self._message = "Wrong NameID Format"
                    self._status = WARNING
            if nip.sp_name_qualifier:
                try:
                    assert nid.sp_name_qualifier == nip.sp_name_qualifier
                except AssertionError:
                    self._message = "Wrong SPNameQualifier"
                    self._status = WARNING
        return {}


class VerifyNameIDMapping(Check):
    """
    Verify that a new NameID is issued and that it follows the
    given policy.
    """
    cid = "verify-name-id-mapping"

    def _func(self, conv):
        response = conv.saml_response[-1].response
        nip = conv.oper.args["name_id_policy"]
        nid = response.name_id
        if nip.format:
            try:
                assert nid.format == nip.format
            except AssertionError:
                self._message = "Wrong NameID Format"
                self._status = WARNING
        if nip.sp_name_qualifier:
            try:
                assert nid.sp_name_qualifier == nip.sp_name_qualifier
            except AssertionError:
                self._message = "Wrong SPNameQualifier"
                self._status = WARNING

        return {}


class VerifySPProvidedID(Check):
    """
    Verify that the IdP allows the SP so set a SP provided ID
    """
    cid = "verify-sp-provided-id"

    def _func(self, conv):
        response = conv.saml_response[-1].response
        nip = conv.oper.args["new_id"]
        nid = response.name_id
        try:
            assert nid.sp_provided_id == nip.new_id
        except AssertionError:
            self._message = "SP provided id not properly set"
            self._status = WARNING

        return {}


class VerifyFunctionality(Check):
    """
    Verifies that the IdP supports the needed functionality
    """

    def _nameid_format_support(self, conv, nameid_format):
        md = conv.client.metadata
        entity = md[conv.entity_id]
        for idp in entity["idpsso_descriptor"]:
            for nformat in idp["name_id_format"]:
                if nameid_format == nformat["text"]:
                    return {}

        self._message = "No support for NameIDFormat '%s'" % nameid_format
        self._status = CRITICAL

        return {}

    def _srv_support(self, conv, service):
        md = conv.client.metadata
        entity = md[conv.entity_id]
        for desc in ["idpsso_descriptor", "attribute_authority_descriptor",
                     "auth_authority_descriptor"]:
            for srvgrp in entity[desc]:
                if service in srvgrp:
                    return {}

        self._message = "No support for '%s'" % service
        self._status = CRITICAL
        return {}

    def _binding_support(self, conv, service, binding):
        md = conv.client.metadata
        entity_id = conv.entity_id
        func = getattr(md, service, None)
        try:
            func(entity_id, binding)
        except UnknownPrincipal:
            self._message = "Unknown principal"
            self._status = CRITICAL
        except UnsupportedBinding:
            self._message = "Unsupported binding"
            self._status = CRITICAL

        return {}

    def _func(self, conv):
        oper = conv.oper
        args = conv.oper.args
        res = self._srv_support(conv, REQ2SRV[oper.request])
        if self._status != "OK":
            return res

        res = self._binding_support(conv, oper.request, args["binding"])
        if self._status != "OK":
            return res

        if "nameid_format" in args:
            res = self._nameid_format_support(conv, args["nameid_format"])

        if "name_id_policy" in args:
            res = self._nameid_format_support(conv,
                                              args["name_id_policy"].format)

        return res


class VerifyAttributeProfile(Check):
    """
    Verify that the correct attribute profile is used.
    """
    cid = "verify-attribute-profile"

    def _func(self, conv):
        # Should be a AuthnResponse or Response instance
        response = conv.saml_response[-1]
        assert isinstance(response.response, Response)

        assertion = response.assertion

        if assertion:
            if assertion.attribute_statement:
                atrstat = assertion.attribute_statement[0]
                for attr in atrstat.attribute:
                    try:
                        assert attr.name_format == conv.idp_constraints[
                            "name_format"]
                    except AssertionError:
                        if conv.idp_constraints[
                                "name_format"] != NAME_FORMAT_UNSPECIFIED:
                            self._message = \
                                "Wrong name format: '%s'" % attr.name_format
                            self._status = CRITICAL
                            break
        return {}

# =============================================================================


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
