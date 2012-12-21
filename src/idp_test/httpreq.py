from Cookie import SimpleCookie
import cookielib
import copy
import logging
import time
import requests

logger = logging.getLogger(__name__)

__author__ = 'rolandh'

# =============================================================================

ATTRS = {"version":None,
         "name":"",
         "value": None,
         "port": None,
         "port_specified": False,
         "domain": "",
         "domain_specified": False,
         "domain_initial_dot": False,
         "path": "",
         "path_specified": False,
         "secure": False,
         "expires": None,
         "discard": True,
         "comment": None,
         "comment_url": None,
         "rest": "",
         "rfc2109": True}

PAIRS = {
    "port": "port_specified",
    "domain": "domain_specified",
    "path": "path_specified"
}

def _since_epoch(cdate):
    # date format 'Wed, 06-Jun-2012 01:34:34 GMT'
    if len(cdate) <= 5:
        return 0

    cdate = cdate[5:-4]
    try:
        t = time.strptime(cdate, "%d-%b-%Y %H:%M:%S")
    except ValueError:
        t = time.strptime(cdate, "%d-%b-%y %H:%M:%S")
    return int(time.mktime(t))

class HTTPC(object):
    def __init__(self, ca_certs=None):

        self.request_args = {"allow_redirects": False,}
        #self.cookies = cookielib.CookieJar()
        self.cookies = {}
        self.cookiejar = cookielib.CookieJar()

        if ca_certs:
            self.request_args["verify"] = True
        else:
            self.request_args["verify"] = False

    def _cookies(self):
        cookie_dict = {}

        for _, a in list(self.cookiejar._cookies.items()):
            for _, b in list(a.items()):
                for cookie in list(b.values()):
                    # print cookie
                    cookie_dict[cookie.name] = cookie.value

        return cookie_dict

    def set_cookie(self, kaka, request):
        """sets a cookie in a Cookie jar based on a set-cookie header line"""

        # default rfc2109=False
        # max-age, httponly
        for cookie_name, morsel in kaka.items():
            std_attr = ATTRS.copy()
            std_attr["name"] = cookie_name
            _tmp = morsel.coded_value
            if _tmp.startswith('"') and _tmp.endswith('"'):
                std_attr["value"] = _tmp[1:-1]
            else:
                std_attr["value"] = _tmp

            std_attr["version"] = 0
            # copy attributes that have values
            for attr in morsel.keys():
                if attr in ATTRS:
                    if morsel[attr]:
                        if attr == "expires":
                            std_attr[attr]=_since_epoch(morsel[attr])
                        else:
                            std_attr[attr]=morsel[attr]
                elif attr == "max-age":
                    if morsel["max-age"]:
                        std_attr["expires"] = _since_epoch(morsel["max-age"])

            for att, set in PAIRS.items():
                if std_attr[att]:
                    std_attr[set] = True

            if std_attr["domain"] and std_attr["domain"].startswith("."):
                std_attr["domain_initial_dot"] = True

            if morsel["max-age"] is 0:
                try:
                    self.cookiejar.clear(domain=std_attr["domain"],
                                         path=std_attr["path"],
                                         name=std_attr["name"])
                except ValueError:
                    pass
            else:
                new_cookie = cookielib.Cookie(**std_attr)

                self.cookiejar.set_cookie(new_cookie)

    def request(self, url, method="GET", trace=None, **kwargs):
        _kwargs = copy.copy(self.request_args)
        if kwargs:
            _kwargs.update(kwargs)

        if self.cookiejar:
            _kwargs["cookies"] = self._cookies()
            if trace:
                trace.info("SENT COOKIEs: %s" % (_kwargs["cookies"],))
        r = requests.request(method, url, **_kwargs)
        try:
            if trace:
                trace.info("RECEIVED COOKIEs: %s" % (r.headers["set-cookie"],))
            self.set_cookie(SimpleCookie(r.headers["set-cookie"]), r)
        except AttributeError, err:
            pass

        return r
