import inspect
import logging
import re
import sys

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2test.check import Check
from saml2test.check import ERROR, INFORMATION, WARNING
from saml2test import check
from saml2test.interaction import Interaction

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class VerifyAuthnRequest(Check):
    """ Basic AuthnRequest verification as provided by pysaml2
    """
    cid = "verify-authnrequest"

    def _func(self, conv):
        try:
            conv.saml_request.message.verify()
        except ValueError:
            self._status = ERROR

        return {}


class MatchResult(Check):
    cid = "match-result"

    def _func(self, conv):
        interaction = Interaction(conv.instance, [conv.json_config["result"]])
        _int = interaction.pick_interaction(content=conv.last_response.content)

        return {}


class ErrorResponse(Check):
    cid = "saml-error"
    msg = "Expected error message, but test target returned OK"

    def _func(self, conv):
        try:
            assert conv.last_response.status_code >= 400
        except AssertionError:
            self._message = self.msg
            self._status = ERROR
        return {}


class VerifyDigestAlgorithm(Check):
    """
    verify that the used digest algorithm was one from the approved set.
    """
    cid = "verify-digest-algorithm"


    def _digest_algo(self, signature, allowed):
        _alg = signature.signed_info.reference[0].digest_method.algorithm
        try:
            assert alg in allowed
        except AssertionError:
            self._message = "signature digest algorithm not allowed: " + alg
            self._status = ERROR
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
                self._status = ERROR
                return {}
            _algs = conv.msg_constraints["digest_algorithm"]

        request = conv.saml_request.message

        if request.signature:
            if not self._digest_algo(request.signature, _algs):
                return {}
        elif conv._binding == BINDING_HTTP_REDIRECT:
            self._message = "no digest with redirect binding"
            self._status = INFORMATION
            return {}
        elif conv._binding == BINDING_HTTP_POST:
            self._message = "cannot verify digest algorithm: request not signed"
            self._status = WARNING
            return {}


        return {}


class VerifyIfRequestIsSigned(Check):
    """
    verify that the request has been signed
    """
    cid = "verify-if-request-is-signed"

    def _func(self, conv):
        try:
            check_sig = conv.msg_constraints["authnRequest_signature_required"]
        except KeyError:
            check_sig = False
        if check_sig:
            if conv._binding == BINDING_HTTP_REDIRECT:
                try:
                    assert conv.http_parameters.signature is not None
                except AssertionError:
                    self._message = "No AuthnRequest simple signature found"
                    self._status = ERROR
                    return {}
            else:
                try:
                    assert conv.saml_request.message.signature is not None
                except AssertionError:
                    self._message = "No AuthnRequest XML signature found"
                    self._status = ERROR
                    return {}
        else:
            logger.debug("AuthnRequest signature is optional")
            return {}
        return {}


class VerifySignatureAlgorithm(Check):
    """
    verify that the used signature algorithm was one from an approved set.
    """
    cid = "verify-signature-algorithm"

    def _func(self, conv):
        if "signature_algorithm" not in conv.msg_constraints:
            logger.info("Not verifying signature_algorithm (not configured)")
            return {}
        else:
            try:
                assert len(conv.msg_constraints["signature_algorithm"]) > 0
            except AssertionError:
                self._message = "List of allowed signature algorithm must " \
                                "not be empty"
                self._status = ERROR
                return {}

        allowed_algs = [a[1] for a in conv.msg_constraints["signature_algorithm"]]
        if conv._binding == BINDING_HTTP_REDIRECT:
            if getattr(conv.http_parameters, "signature", None):
                _alg = conv.http_parameters.sigalg
                try:
                    assert _alg in allowed_algs
                except AssertionError:
                    self._message = "Algorithm not in white list for " \
                                    "redirect signing: " + _alg
                    self._status = ERROR
        else:
            signature = getattr(conv.saml_request.message, "signature", None)
            if signature:
                try:
                    assert signature.signed_info.signature_method.algorithm in \
                           allowed_algs
                except AssertionError:
                    self._message = "Wrong algorithm used for signing: '%s'" % \
                                    signature.signed_info.signature_method.algorithm
                    self._status = ERROR
            else:
                self._message = "cannot verify signature algorithm: request not signed"
                self._status = WARNING
                return {}
        return {}


class VerifyEchopageContents(Check):
    """ Verify that the last success response (HTTP code 200) from the SP
        contains static text and SAML response values
    """
    cid = "verify-echopage-contents"
    msg = "Cannot match expected contents on SP echo page"

    def _func(self, conv):
        if conv.last_response.status_code < 300:
            try:
                pattern = conv.json_config["echopageIdPattern"]
                m = re.search(pattern, conv.last_response.content)
                try:
                    assert m is not None
                except AssertionError:
                    self._message = "Cannot match expected static contents " \
                                    "in SP echo page"
                    self._status = ERROR
                for pattern in conv.json_config["echopageContentPattern"]:
                    m = re.search(pattern, conv.last_response.content)
                    try:
                        assert m is not None
                    except AssertionError:
                        self._message = 'Cannot match expected response value' \
                                        ', pattern="' + pattern + '"'
                        self._status = ERROR
            except KeyError:
                self._message = 'Configuration error: missing key ' \
                                '"echopageIdString" in test target config'
                self._status = ERROR
        return {}

    def call_on_redirect(self):
        return False


class SetResponseAndAssertionSignaturesFalse(Check):
    """ Prepare config to suppress signatures of both response and assertion"""
    cid = "set-response-and-assertion-signature-false"
    msg = "Prepare config to suppress signatures of both response and assertion"

    def _func(self, conv):
        conv.json_config['args']['AuthnResponse']['sign_assertion'] = 'never'
        conv.json_config['args']['AuthnResponse']['sign_response'] = 'never'
        self._status = INFORMATION
        return {}


#class SetInvalidIdpKey(Check):
#    """ Prepare config to set IDP signing key to some useless key"""
#    cid = "set-idp-key-invalid"
#    msg = "Prepare config to set IDP signing key invalid"
#
#    def _func(self, conv):
#        conv.instance.sec.cert_file = conv.instance.config.invalid_idp_cert_file
#        conv.instance.sec.key_file = conv.instance.config.invalid_idp_key_file
#        return {}


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
