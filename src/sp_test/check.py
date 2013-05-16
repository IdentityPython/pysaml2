import inspect
import sys

from srtest.check import Check
from srtest.check import CRITICAL
from srtest import check
from srtest.interaction import Interaction

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
