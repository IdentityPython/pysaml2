import inspect
import logging
import sys
from time import mktime
from saml2.response import AttributeResponse

from saml2test import check
from saml2test.check import Check

from saml2.mdstore import REQ2SRV
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAME_FORMAT_UNSPECIFIED
from saml2.saml import NAME_FORMAT_URI
from saml2.samlp import STATUS_SUCCESS
from saml2.samlp import Response
from saml2.sigver import cert_from_key_info_dict
from saml2.sigver import key_from_key_value_dict

from saml2.time_util import str_to_time

__author__ = 'rolandh'

INFORMATION = 0
OK = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
INTERACTION = 5

STATUSCODE = ["INFORMATION", "OK", "WARNING", "ERROR", "CRITICAL",
              "INTERACTION"]

PREFIX = "-----BEGIN CERTIFICATE-----"
POSTFIX = "-----END CERTIFICATE-----"

M2_TIME_FORMAT = "%b %d %H:%M:%S %Y"

logger = logging.getLogger(__name__)

def to_time(_time):
    assert _time.endswith(" GMT")
    _time = _time[:-4]
    return mktime(str_to_time(_time, M2_TIME_FORMAT))


class CheckSaml2IntMetaData(Check):
    """
    Checks that the Metadata follows the Saml2Int profile
    """
    cid = "check-saml2int-metadata"
    msg = "Metadata error"

    def _func(self, conv):
        mds = conv.client.metadata.metadata[0]
        # Should only be one
        ed = mds.entity.values()[0]
        res = {}

        assert len(ed["idpsso_descriptor"])
        idpsso = ed["idpsso_descriptor"][0]

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


class CheckATMetaData(CheckSaml2IntMetaData):
    cid = "check-at-metadata"

    def verify_key_info(self, ki):
        # key_info
        # one or more key_value and/or x509_data.X509Certificate

        verified_x509_keys = []

        xkeys = cert_from_key_info_dict(ki)
        vkeys = key_from_key_value_dict(ki)

        if xkeys or vkeys:
            if xkeys:
                # time validity is checked in cert_from_key_info_dict
                verified_x509_keys.append(xkeys)
            if vkeys:  # don't expect this to happen
                pass

        if not verified_x509_keys:
            if cert_from_key_info_dict(ki, ignore_age=True):
                self._message = "Keys too old"
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

        return CheckSaml2IntMetaData._func(self, conv)


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
        if isinstance(response, AttributeResponse):
            pass
        else:
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
            try:
                srvgrps = entity[desc]
            except KeyError:
                pass
            else:
                for srvgrp in srvgrps:
                    if service in srvgrp:
                        return {}

        self._message = "No support for '%s'" % service
        self._status = CRITICAL
        return {}

    def _binding_support(self, conv, request, binding, typ):
        service = REQ2SRV[request]
        md = conv.client.metadata
        entity_id = conv.entity_id
        func = getattr(md, service, None)
        try:
            func(entity_id, binding, typ)
        except UnknownPrincipal:
            self._message = "Unknown principal: %s" % entity_id
            self._status = CRITICAL
        except UnsupportedBinding:
            self._message = "Unsupported binding at the IdP: %s" % binding
            self._status = CRITICAL

        return {}

    def _func(self, conv):
        oper = conv.oper
        args = conv.oper.args
        res = self._srv_support(conv, REQ2SRV[oper.request])
        if self._status != OK:
            return res

        res = self._binding_support(conv, oper.request, args["request_binding"],
                                    "idpsso")
        if self._status != OK:
            return res

        if "nameid_format" in args and args["nameid_format"]:
            if args["nameid_format"] == NAMEID_FORMAT_UNSPECIFIED:
                pass
            else:
                res = self._nameid_format_support(conv, args["nameid_format"])

        if "name_id_policy" in args and args["name_id_policy"]:
            if args["name_id_policy"].format == NAMEID_FORMAT_UNSPECIFIED:
                pass
            else:
                res = self._nameid_format_support(conv,
                                                  args["name_id_policy"].format)

        return res


class VerifyAttributeNameFormat(Check):
    """
    Verify that the correct attribute name format is used.
    """
    cid = "verify-attribute-name-format"

    def _func(self, conv):
        if "name_format" not in conv.msg_constraints:
            return {}

        # Should be a AuthnResponse or Response instance
        response = conv.saml_response[-1]
        assert isinstance(response.response, Response)

        assertion = response.assertion

        if assertion:
            if assertion.attribute_statement:
                atrstat = assertion.attribute_statement[0]
                for attr in atrstat.attribute:
                    try:
                        assert attr.name_format == conv.msg_constraints[
                            "name_format"]
                        logger.debug("Attribute name format valid: " +
                                     attr.name_format)
                    except AssertionError:
                        if NAME_FORMAT_UNSPECIFIED != conv.msg_constraints[
                                "name_format"]:
                            self._message = \
                                "Wrong name format: '%s', should be %s" % \
                                (attr.name_format, \
                                conv.msg_constraints["name_format"])
                            self._status = CRITICAL
                            break
                        else:
                            logger.debug("Accepting any attribute name format")

        return {}


class VerifyDigestAlgorithm(Check):
    """
    verify that the used digest algorithm was one from the approved set.
    """

    def _digest_algo(self, signature, allowed):
        try:
            assert signature.signed_info.reference[0].digest_method.algorithm in allowed
        except AssertionError:
            self._message = "signature digest algorithm not allowed: '%s'" % \
                            signature.signed_info.reference[0].digest_method.algorithm
            self._status = CRITICAL
            return False
        return True

    def _func(self, conv):
        if "digest_algorithm" not in conv.msg_constraints:
            logger.info("Not verifying digest_algorithm (not configured)")
            return {}
        else:
            try:
                assert len(conv.msg_constraints["digest_algorithm"]) > 0
            except AssertionError:
                self._message = "List of allowed digest algorithm must not be empty"
                self._status = CRITICAL
                return {}
            _algs = conv.msg_constraints["digest_algorithm"]

        response = conv.saml_response[-1].response

        if response.signature:
            if not self._digest_algo(response.signature, _algs):
                return {}

        for assertion in response.assertion:
            if not self._digest_algo(assertion.signature, _algs):
                return {}

        return {}


class VerifySignatureAlgorithm(Check):
    """
    verify that the used signature algorithm was one from an approved set.
    """

    def _sig_algo(self, signature, allowed):
        try:
            assert signature.signed_info.signature_method.algorithm in allowed
        except AssertionError:
            self._message = "Wrong algorithm used for signing: '%s'" % \
                            signature.signed_info.signature_method.algorithm
            self._status = CRITICAL
            return False

        return True

    def _func(self, conv):
        if "signature_algorithm" not in conv.msg_constraints:
            logger.info("Not verifying signature_algorithm (not configured)")
            return {}
        else:
            try:
                assert len(conv.msg_constraints["signature_algorithm"]) > 0
            except AssertionError:
                self._message = "List of allowed signature algorithm must not be empty"
                self._status = CRITICAL
                return {}
            _algs = conv.msg_constraints["signature_algorithm"]

        response = conv.saml_response[-1].response

        if response.signature:
            if not self._sig_algo(response.signature, _algs):
                return {}

        for assertion in response.assertion:
            if not self._sig_algo(assertion.signature, _algs):
                return {}

        return {}


class VerifySignedPart(Check):
    """
    verify that the correct part was signed.
    """

    def _func(self, conv):

        if "signed_part" not in conv.msg_constraints:
            return {}

        response = conv.saml_response[-1].response
        if "response" in conv.msg_constraints["signed_part"]:
            if response.signature:
                pass
            else:
                self._message = "Response not signed"
                self._status = CRITICAL

        if self._status == OK:
            if "assertion" in conv.msg_constraints["signed_part"]:
                for assertion in response.assertion:
                    if assertion.signature:
                        pass
                    else:
                        self._message = "Assertion not signed"
                        self._status = CRITICAL
                        break

        return {}


class VerifyEndpoint(Check):
    def _func(self, conv):
        _ = conv.last_response
        return {}


# =============================================================================


CLASS_CACHE = {}


def factory(cid, classes=CLASS_CACHE):
    if len(classes) == 0:
        check.factory(cid, classes)
        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if inspect.isclass(obj):
                try:
                    classes[obj.cid] = obj
                except AttributeError:
                    pass

    if cid in classes:
        return classes[cid]
    else:
        return None
