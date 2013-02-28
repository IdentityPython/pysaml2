import inspect
import json

__author__ = 'rolandh'

from oic.oauth2.message import ErrorResponse, MissingRequiredAttribute

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


class Information(Check):
    status = INFORMATION


class Error(Check):
    status = ERROR


class ResponseInfo(Information):
    """Response information"""

    def _func(self, conv=None):
        self._status = self.status
        _msg = conv.last_content

        if isinstance(_msg, basestring):
            self._message = _msg
        else:
            self._message = _msg.to_dict()

        return {}


class CheckErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an JSON encoded error message has been received
    """
    cid = "check-error-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response
        _content = conv.last_content

        res = {}
        if _response.status_code >= 400:
            content_type = _response.headers["content-type"]
            if content_type is None:
                res["content"] = _content
            elif CONT_JSON in content_type:
                try:
                    self.err = ErrorResponse().deserialize(_content, "json")
                    self.err.verify()
                    res["content"] = self.err.to_json()
                    #res["temp"] = err
                except Exception:
                    res["content"] = _content
            else:
                res["content"] = _content
        else:
            # might still be an error message
            try:
                self.err = ErrorResponse().deserialize(_content, "json")
                self.err.verify()
                res["content"] = self.err.to_json()
            except Exception:
                self._message = "Expected error message"
                self._status = CRITICAL

            res["url"] = conv.position

        return res


class CheckRedirectErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an error message has been received urlencoded in the form of a
    redirection.
    """
    cid = "check-redirect-error-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response

        res = {}
        try:
            _loc = _response.headers["location"]
            if "?" in _loc:
                query = _loc.split("?")[1]
            elif "#" in _loc:
                query = _loc.split("#")[1]
            else:  # ???
                self._message = "Expected redirect"
                self._status = CRITICAL
                return res
        except (KeyError, AttributeError):
            self._message = "Expected redirect"
            self._status = CRITICAL
            return res

        if _response.status_code == 302:
            err = ErrorResponse().deserialize(query, "urlencoded")
            try:
                err.verify()
                res["content"] = err.to_json()
                conv.protocol_response.append((err, query))
            except MissingRequiredAttribute:
                self._message = "Expected error message"
                self._status = CRITICAL
        else:
            self._message = "Expected error message"
            self._status = CRITICAL

        return res


class VerifyBadRequestResponse(ExpectedError):
    """
    Verifies that the OP returned a 400 Bad Request response containing a
    Error message.
    """
    cid = "verify-bad-request-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response
        _content = conv.last_content
        res = {}
        if _response.status_code == 400:
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            res["content"] = err.to_json()
            conv.protocol_response.append((err, _content))
        else:
            self._message = "Expected a 400 error message"
            self._status = CRITICAL

        return res


class VerifyErrorResponse(ExpectedError):
    """
    Verifies that the response received by the client via redirect was an Error
    response.
    """
    cid = "verify-err-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}

        response = conv.last_response
        if response.status_code == 302:
            _loc = response.headers["location"]
            if "?" in _loc:
                _query = _loc.split("?")[1]
            elif "#" in _loc:
                _query = _loc.split("#")[1]
            else:
                self._message = "Faulty error message"
                self._status = ERROR
                return

            try:
                err = ErrorResponse().deserialize(_query, "urlencoded")
                err.verify()
                #res["temp"] = err
                res["message"] = err.to_dict()
            except Exception:
                self._message = "Faulty error message"
                self._status = ERROR
        else:
            self._message = "Expected a redirect with an error message"
            self._status = ERROR

        return res


class VerifyError(Error):
    cid = "verify-error"

    def _func(self, conv):
        response = conv.last_response
        if response.status_code == 400:
            try:
                resp = json.loads(response.text)
                if "error" in resp:
                    return {}
            except Exception:
                pass

        item, msg = conv.protocol_response[-1]
        try:
            assert item.type().endswith("ErrorResponse")
        except AssertionError:
            self._message = "Expected an error response"
            self._status = self.status
            return {}

        try:
            assert item["error"] in self._kwargs["error"]
        except AssertionError:
            self._message = "Wrong type of error, got %s" % item["error"]
            self._status = self.status

        return {}


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


class MissingRedirect(CriticalError):
    """ At this point in the flow a redirect back to the client was expected.
    """
    cid = "missing-redirect"
    msg = "Expected redirect to the RP, got something else"

    def _func(self, conv=None):
        self._status = self.status
        return {"url": conv.position}


class Parse(CriticalError):
    """ Parsing the response """
    cid = "response-parse"
    errmsg = "Parse error"

    def _func(self, conv=None):
        if conv.exception:
            self._status = self.status
            err = conv.exception
            self._message = "%s: %s" % (err.__class__.__name__, err)
        else:
            _rmsg = conv.response_message
            cname = _rmsg.type()
            if conv.response_type != cname:
                self._status = self.status
                self._message = (
                    "Didn't get a response of the type I expected:",
                    " '%s' instead of '%s', content:'%s'" % (
                        cname, conv.response_type, _rmsg))
                return {
                    "response_type": conv.response_type,
                    "url": conv.position
                }

        return {}

def factory(cid, classes):
    if len(classes) == 0:
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
