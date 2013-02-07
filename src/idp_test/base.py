#!/usr/bin/env python
import inspect
import urllib
from saml2 import BINDING_HTTP_REDIRECT, BINDING_URI
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.client import Saml2Client

#from idp_test.check import ExpectedError
from saml2.mdstore import REQ2SRV
from saml2.pack import http_redirect_message, http_form_post_message
from saml2.s_utils import rndstr
from idp_test.check import factory, ExpectedError
from idp_test.check import STATUSCODE
from idp_test.interaction import Operation
from idp_test.interaction import pick_interaction

__author__ = 'rohe0002'

import cookielib

class FatalError(Exception):
    pass

class HTTPError(Exception):
    pass

def unpack_form(_str, ver="SAMLRequest"):
    SR_STR = "name=\"%s\" value=\"" % ver
    RS_STR = 'name="RelayState" value="'

    i = _str.find(SR_STR)
    i += len(SR_STR)
    j = _str.find('"', i)

    sr = _str[i:j]

    k = _str.find(RS_STR, j)
    k += len(RS_STR)
    l = _str.find('"', k)

    rs = _str[k:l]

    return {ver:sr, "RelayState":rs}


def form_post(_dict):
    return urllib.urlencode(_dict)


def tuple_list2dict(tl):
    return dict(tl)

class Conversation():

    def __init__(self, config, trace, interaction, entity_id,
                 features=None):
        self.client = Saml2Client(config)
        self.trace = trace
        self.interaction = interaction
        self.entity_id = entity_id
        self.test_output = []
        self.features = features
        self.environ = {"metadata": self.client.metadata,
                        "client": self.client,
                        "entity_id": entity_id, "response": []}

        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}

    def check_severity(self, stat):
        if stat["status"] >= 4:
            self.trace.error("WHERE: %s"  % stat["id"])
            self.trace.error("STATUS:%s" % STATUSCODE[stat["status"]])
            try:
                self.trace.error("HTTP STATUS: %s"  % stat["http_status"])
            except KeyError:
                pass
            try:
                self.trace.error("INFO: %s"  % stat["message"])
            except KeyError:
                pass

            raise FatalError

    def do_check(self, test, **kwargs):
        if isinstance(test, basestring):
            chk = factory(test)(**kwargs)
        else:
            chk = test(**kwargs)
        stat = chk(self.environ, self.test_output)
        self.check_severity(stat)

    def err_check(self, test, err=None, bryt=True):
        if err:
            self.environ["exception"] = err
        chk = factory(test)()
        chk(self.environ, self.test_output)
        if bryt:
            raise FatalError(test)

    def test_sequence(self, sequence):
        for test in sequence:
            if isinstance(test, tuple):
                test, kwargs = test
            else:
                kwargs = {}
            self.do_check(test, **kwargs)
            if test == ExpectedError:
                return False
        return True

    def intermit(self, response):
        if response.status_code >= 400:
            done = True
        else:
            done = False

        url = response.url
        content = response.text

        while not done:
            while response.status_code in [302, 301, 303]:
                url = response.headers["location"]

                self.trace.reply("REDIRECT TO: %s" % url)
                # If back to me
                for_me = False
                acs = self.client.config.getattr("endpoints",
                                            "sp")["assertion_consumer_service"]
                for redirect_uri in acs:
                    if url.startswith(redirect_uri):
                        # Back at the RP
                        self.environ["client"].cookiejar = self.cjar["rp"]
                        for_me=True

                if for_me:
                    done = True
                    break
                else:
                    try:
                        response = self.client.send(url, "GET")
                    except Exception, err:
                        raise FatalError("%s" % err)

                    content = response.text
                    self.trace.reply("CONTENT: %s" % content)
                    self.environ.update({"url": url, "content":content})
                    self.environ["response"].append(response)

                    self.do_check("check-http-response")
            if done:
                break

            _base = url.split("?")[0]

            try:
                _spec = pick_interaction(self.interaction, _base, content)
            except KeyError:
                self.environ["url"] = url
                self.trace.error("Page Content: %s" % content)
                self.err_check("interaction-needed")

            if len(_spec) > 2:
                self.trace.info(">> %s <<" % _spec["page-type"])
                if _spec["page-type"] == "login":
                    self.environ["login"] = content

            _op = Operation(_spec["control"])

            try:
                response = _op(self.client, self.environ, self.trace, url,
                               response, content, self.features)
                if isinstance(response, dict):
                    return response
                content = response.text
                self.environ.update({"url": url, "content":content})
                self.environ["response"].append(response)

                self.do_check("check-http-response")
            except FatalError:
                raise
            except Exception, err:
                self.err_check("exception", err, False)

        return response


    def construct_and_send(self, srv, args, response_args, qargs, relay_state):
        _trace = self.trace
        _client = self.client

        loc = srv["location"]
        qargs["destination"] = loc
        self.environ["destination"] = loc
        use_artifact = getattr(self.oper, "use_artifact", False)

        try:
            req = self.oper.args["message"]
        except KeyError:
            req = self.qfunc(**qargs)

        req = self.oper.pre_processing(req, args)

        self.environ["request"] = req
        _req_str = "%s" % req

        if use_artifact:
            saml_art = _client.use_artifact(_req_str, args["entity_id"])
            _trace.info("SAML Artifact: %s" % saml_art)
            info_typ = "SAMLart"
        else:
            _trace.info("SAML Request: %s" % _req_str)
            info_typ = "SAMLRequest"
            # depending on binding send the query

        if args["binding"] is BINDING_SOAP:
            res = _client.send_using_soap(_req_str, loc)
            if res.status_code >= 400:
                _trace.info("Received a HTTP error (%d) '%s'" % (res.status_code,
                                                                res.text))
                raise HTTPError(res.text)
            else:
                response_args["binding"] = BINDING_SOAP
                response = res.text
        else:
            response_args["binding"] = BINDING_HTTP_POST
            if args["binding"] is BINDING_HTTP_REDIRECT:
                htargs = http_redirect_message(_req_str, loc, relay_state,
                                               info_typ)
                #
                res = _client.send(htargs["headers"][0][1], "GET")
            elif args["binding"] is BINDING_HTTP_POST:
                htargs = http_form_post_message(_req_str, loc, relay_state,
                                                info_typ)
                info = unpack_form(htargs["data"][3])
                data = form_post(info)
                htargs["data"] = data
                #htargs["headers"] = tuple_list2dict(htargs["headers"])
                htargs["headers"] = [("Content-type",
                                      'application/x-www-form-urlencoded')]
                res = _client.send(loc, "POST", **htargs)
            elif args["binding"] == BINDING_URI:
                response_args["binding"] = BINDING_URI
                htargs = _client.use_http_uri(_req_str, "SAMLRequest", loc)
                res = _client.send(htargs["url"], "GET")
            else:
                res = None

            if res.status_code >= 400:
                _trace.info("Received a HTTP error (%d) '%s'" % (res.status_code,
                                                                res.text))
                raise HTTPError(res.text)

            if res:
                if args["binding"] == BINDING_URI:
                    response = res.text
                else:

                    response_args["outstanding"] = {req.id: "/"}
                    # deal with redirect, should in the end give me a response
                    try:
                        response = self.intermit(res)
                    except FatalError:
                        self.environ["FatalError"] = True
                        raise

                    if isinstance(response, dict):
                        assert relay_state == response["RelayState"]
            else:
                response = None
        return response

    def do_query(self):
        """ """

        _oper = self.oper
        _oper.setup()
        query = _oper.request
        args = _oper.args
        self.environ["oper.args"] = _oper.args.copy()
        args["entity_id"] = self.entity_id
        test_output = []

        try:
            self.test_sequence(_oper.tests["pre"])
        except KeyError:
            pass

        #httpc = environ["client"]
        _client = self.client
        _client.cookiejar = self.cjar["browser"]

        srvs = getattr(_client.metadata, REQ2SRV[query])(args["entity_id"],
                                                        args["binding"],
                                                        "idpsso")

        _response_func = getattr(_client, "parse_%s_response" % query)
        response_args = {}
        qargs = args.copy()
        relay_state = rndstr()
        self.environ["relay_state"] = relay_state

        if "message" not in _oper.args:
            self.qfunc = getattr(_client, "create_%s" % query)
            # remove args the create function can't handle
            fargs = inspect.getargspec(self.qfunc).args
            if _oper._class:
                fargs.extend([p for p,c,r in _oper._class.c_attributes.values()])
                fargs.extend([p for p,c in _oper._class.c_children.values()])
            for arg in qargs.keys():
                if arg not in fargs:
                    del qargs[arg]

        response = None
        for srv in srvs:
            response = self.construct_and_send(srv, args, response_args, qargs,
                                               relay_state)
            if response:
                break

        if not response:
            return None

        try:
            response = self.oper.post_processing(response)
            if isinstance(response, dict):
                try:
                    assert relay_state == response["RelayState"]
                except KeyError:
                    pass
                response = response["SAMLResponse"]
            _resp = _response_func(response, **response_args)
            self.environ["response"].append(_resp)
            self.trace.info("SAML Response: %s" % _resp)
            try:
                self.test_sequence(_oper.tests["post"])
            except KeyError:
                pass
            except FatalError:
                self.environ["FatalError"] = True
        except Exception, err:
            self.trace.error("Exception %s" % err)
            self.err_check("exception", err)

    def do_sequence(self, oper):
        """

        :param oper: A dictionary describing the operations to perform
        """


        try:
            self.test_sequence(oper["tests"]["pre"])
        except KeyError:
            pass

        self.environ["FatalError"] = False
        for op in oper["sequence"]:
            self.environ["op"] = op
            self.oper = op(self.environ)

            self.do_query()

            if self.environ["FatalError"]:
                break

        try:
            self.test_sequence(oper["tests"]["post"])
        except KeyError:
            pass

