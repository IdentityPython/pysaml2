import inspect
import re
import sys

from saml2test.check import Check
from saml2test.check import CRITICAL
from saml2test import check
from saml2test.interaction import Interaction

__author__ = 'rolandh'


class VerifyContent(Check):
    """ Basic content verification class, does required and max/min checks
    """
    cid = "verify-content"

    def _func(self, conv):
        try:
            conv.saml_request.message.verify()
        except ValueError:
            self._status = CRITICAL

        return {}


class VerifyAuthnRequest(VerifyContent):
    """ Basic AuthnRequest verification as provided by pysaml2
    """
    cid = "verify-authnrequest"


class MatchResult(Check):
    cid = "match-result"

    def _func(self, conv):
        interaction = Interaction(conv.instance, [conv.json_config["result"]])
        _int = interaction.pick_interaction(content=conv.last_response.content)

        return {}


class ErrorResponse(Check):
    cid = "saml-error"
    msg = "Expected error message"

    def _func(self, conv):
        try:
            assert conv.last_response.status_code >= 400
        except AssertionError:
            self._message = self.msg
            self._status = CRITICAL
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
                    self._status = CRITICAL
                for pattern in conv.json_config["echopageContentPattern"]:
                    m = re.search(pattern, conv.last_response.content)
                    try:
                        assert m is not None
                    except AssertionError:
                        self._message = 'Cannot match expected response value' \
                                        ', pattern="' + pattern + '"'
                        self._status = CRITICAL
            except KeyError:
                self._message = 'Configuration error: missing key ' \
                                '"echopageIdString" in test target config'
                self._status = CRITICAL
        return {}

    def call_on_redirect(self):
        return False


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
