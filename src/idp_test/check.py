import inspect
import sys

__author__ = 'rolandh'

INFORMATION = 0
OK = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
INTERACTION = 5

STATUSCODE = ["INFORMATION", "OK", "WARNING", "ERROR", "CRITICAL",
              "INTERACTION"]

class Check():
    """ General test
    """
    id = "check"
    msg = "OK"

    def __init__(self, **kwargs):
        self._status = OK
        self._message = ""
        self.content = None
        self.url = ""
        self._kwargs = kwargs

    def _func(self, environ):
        return {}

    def __call__(self, environ=None, output=None):
        _stat =  self.response(**self._func(environ))
        output.append(_stat)
        return _stat

    def response(self, **kwargs):
        try:
            name = " ".join([s.strip() for s in self.__doc__.strip().split("\n")])
        except AttributeError:
            name = ""

        res = {
            "id": self.id,
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

class Other(CriticalError):
    """ Other error """
    msg  = "Other error"

class CheckHTTPResponse(CriticalError):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    id = "check-http-response"
    msg = "IdP error"

    def _func(self, environ):
        _response = environ["response"]
        _content = environ["content"]

        res = {}
        if _response.status_code >= 400 :
            self._status = self.status
            self._message = self.msg
#            if CONT_JSON in _response.headers["content-type"]:
#                try:
#                    err = ErrorResponse().deserialize(_content, "json")
#                    self._message = err.to_json()
#                except Exception:
#                    res["content"] = _content
#            else:
#                res["content"] = _content
            res["url"] = environ["url"]
            res["http_status"] = _response.status_code
        else:
            # might still be an error message
            try:
#                err = ErrorResponse().deserialize(_content, "json")
#                err.verify()
#                self._message = err.to_json()
                self._status = self.status
            except Exception:
                pass

            res["url"] = environ["url"]

        return res

def factory(id):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            try:
                if obj.id == id:
                    return obj
            except AttributeError:
                pass

    return None
