__author__ = 'rolandh'

from oic.oauth2.message import ErrorResponse

import traceback
import sys

INFORMATION = 0
OK = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
INTERACTION = 5

STATUSCODE = ["INFORMATION", "OK", "WARNING", "ERROR", "CRITICAL",
              "INTERACTION"]

CONT_JSON = "application/json"
CONT_JWT = "application/jwt"


class Check(object):
    """ General test
    """

    cid = "check"
    msg = "OK"

    def __init__(self, **kwargs):
        self._status = OK
        self._message = ""
        self.content = None
        self.url = ""
        self._kwargs = kwargs

    def _func(self, conv):
        return {}

    def __call__(self, conv=None, output=None):
        _stat = self.response(**self._func(conv))
        if output is not None:
            output.append(_stat)
        return _stat

    def response(self, **kwargs):
        try:
            name = " ".join(
                [s.strip() for s in self.__doc__.strip().split("\n")])
        except AttributeError:
            name = ""

        res = {
            "id": self.cid,
            "status": self._status,
            "name": name
        }

        if self._message:
            res["message"] = self._message

        if kwargs:
            res.update(kwargs)

        return res


class ExpectedError(Check):
    pass


class CriticalError(Check):
    status = CRITICAL


class Error(Check):
    status = ERROR


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


class Other(CriticalError):
    """ Other error """
    msg = "Other error"


class CheckHTTPResponse(CriticalError):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    cid = "check-http-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response
        _content = conv.last_content

        res = {}
        if _response.status_code >= 400:
            self._status = self.status
            self._message = self.msg
            if CONT_JSON in _response.headers["content-type"]:
                try:
                    err = ErrorResponse().deserialize(_content, "json")
                    self._message = err.to_json()
                except Exception:
                    res["content"] = _content
            else:
                res["content"] = _content
            res["url"] = conv.position
            res["http_status"] = _response.status_code
        else:
            # might still be an error message
            try:
                err = ErrorResponse().deserialize(_content, "json")
                err.verify()
                self._message = err.to_json()
                self._status = self.status
            except Exception:
                pass

            res["url"] = conv.position

        return res

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
