from check import CheckHTTPResponse

__author__ = 'rolandh'

class Request():
    request = ""
    method = ""
    lax = False
    _request_args= {}
    kw_args = {}
    tests = {"post": [CheckHTTPResponse], "pre":[]}

    def __init__(self, cconf=None):
        self.cconf = cconf
        self.request_args = self._request_args.copy()

    #noinspection PyUnusedLocal
    def __call__(self, environ, trace, location, response, content, features):
        _client = environ["client"]
        try:
            kwargs = self.kw_args.copy()
        except KeyError:
            kwargs = {}

        func = getattr(_client, "do_%s" % self.request)

        ht_add = None

        if "authn_method" in kwargs:
            h_arg = _client.init_authentication_method(cis, **kwargs)
        else:
            h_arg = None

        url, body, ht_args, cis = _client.uri_and_body(request, cis,
                                                       method=self.method,
                                                       request_args=_req)

        environ["cis"].append(cis)
        if h_arg:
            ht_args.update(h_arg)
        if ht_add:
            ht_args.update({"headers": ht_add})

        if trace:
            try:
                oro = unpack(cis["request"])[1]
                trace.request("OpenID Request Object: %s" % oro)
            except KeyError:
                pass
            trace.request("URL: %s" % url)
            trace.request("BODY: %s" % body)
            try:
                trace.request("HEADERS: %s" % ht_args["headers"])
            except KeyError:
                pass

        response = _client.http_request(url, method=self.method, data=body,
                                        **ht_args)

        if trace:
            trace.reply("RESPONSE: %s" % response)
            trace.reply("CONTENT: %s" % response.text)
            if response.status_code in [301, 302]:
                trace.reply("LOCATION: %s" % response.headers["location"])
            trace.reply("COOKIES: %s" % response.cookies)
        #            try:
        #                trace.reply("HeaderCookies: %s" % response.headers["set-cookie"])
        #            except KeyError:
        #                pass

        return url, response, response.text

    def update(self, dic):
        _tmp = {"request": self.request_args.copy(), "kw": self.kw_args}
        for key, val in self.rec_update(_tmp, dic).items():
            setattr(self, "%s_args" % key, val)

    def rec_update(self, dic0, dic1):
        res = {}
        for key, val in dic0.items():
            if key not in dic1:
                res[key] = val
            else:
                if isinstance(val, dict):
                    res[key] = self.rec_update(val, dic1[key])
                else:
                    res[key] = dic1[key]

        for key, val in dic1.items():
            if key in dic0:
                continue
            else:
                res[key] = val

        return res
