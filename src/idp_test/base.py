#!/usr/bin/env python
import inspect
import urllib
from saml2 import BINDING_HTTP_REDIRECT, BINDING_URI
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP

#from idp_test.check import ExpectedError
from saml2.mdstore import REQ2SRV
from saml2.pack import http_redirect_message, http_form_post_message
from saml2.s_utils import rndstr

from rrtest import tool
from rrtest import FatalError

__author__ = 'rohe0002'

import cookielib


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

    return {ver: sr, "RelayState": rs}


def form_post(_dict):
    return urllib.urlencode(_dict)


def tuple_list2dict(tl):
    return dict(tl)


class Conversation(tool.Conversation):
    def __init__(self, client, config, trace, interaction,
                 check_factory, entity_id, msg_factory=None,
                 features=None, verbose=False, constraints=None):
        tool.Conversation.__init__(self, client, config, trace,
                                   interaction, check_factory, msg_factory,
                                   features, verbose)
        self.entity_id = entity_id
        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}

        self.args = {}
        self.qargs = {}
        self.response_args = {}
        self.saml_response = []
        self.destination = ""
        self.request = None
        self.position = ""
        self.response = None
        self.oper = None
        self.idp_constraints = constraints

    def send(self):
        srvs = getattr(self.client.metadata, REQ2SRV[self.oper.request])(
            self.args["entity_id"], self.args["binding"], "idpsso")

        response = None
        for srv in srvs:
            response = self._send(srv)
            if response:
                break

        return response

    def _send(self, srv):
        _client = self.client
        loc = srv["location"]
        self.qargs["destination"] = loc
        self.response_args = {}
        use_artifact = getattr(self.oper, "use_artifact", False)

        try:
            req = self.oper.args["message"]
        except KeyError:
            req = self.qfunc(**self.qargs)

        self.request = self.oper.pre_processing(req, self.args)
        str_req = "%s" % self.request

        if use_artifact:
            saml_art = _client.use_artifact(str_req, self.args["entity_id"])
            self.trace.info("SAML Artifact: %s" % saml_art)
            info_typ = "SAMLart"
        else:
            self.trace.info("SAML Request: %s" % str_req)
            info_typ = "SAMLRequest"
            # depending on binding send the query

        if self.args["binding"] is BINDING_SOAP:
            res = _client.send_using_soap(str_req, loc)
            if res.status_code >= 400:
                self.trace.info("Received a HTTP error (%d) '%s'" % (
                    res.status_code, res.text))
                raise HTTPError(res.text)
            else:
                self.response_args["binding"] = BINDING_SOAP
        else:
            self.response_args["binding"] = BINDING_HTTP_POST
            if self.args["binding"] is BINDING_HTTP_REDIRECT:
                htargs = http_redirect_message(str_req, loc, self.relay_state,
                                               info_typ)
                self.response_args["outstanding"] = {self.request.id: "/"}
                #
                res = _client.send(htargs["headers"][0][1], "GET")
            elif self.args["binding"] is BINDING_HTTP_POST:
                htargs = http_form_post_message(str_req, loc, self.relay_state,
                                                info_typ)
                info = unpack_form(htargs["data"][3])
                data = form_post(info)
                self.response_args["outstanding"] = {self.request.id: "/"}
                htargs["data"] = data
                htargs["headers"] = [("Content-type",
                                      'application/x-www-form-urlencoded')]
                res = _client.send(loc, "POST", **htargs)
            elif self.args["binding"] == BINDING_URI:
                self.response_args["binding"] = BINDING_URI
                htargs = _client.use_http_uri(str_req, "SAMLRequest", loc)
                res = _client.send(htargs["url"], "GET")
            else:
                res = None

        self.last_response = res
        try:
            self.last_content = res.text
        except AttributeError:
            self.last_content = None

    def init(self, phase):
        self.phase = phase
        _oper = phase(self)
        _oper.setup()
        self.args = _oper.args
        #self.oper.args = _oper.args.copy()
        self.args["entity_id"] = self.entity_id
        self.oper = _oper
        self.client.cookiejar = self.cjar["browser"]
        try:
            self.test_sequence(self.oper.tests["pre"])
        except KeyError:
            pass

    def setup_request(self):
        query = self.oper.request
        _client = self.client
        _oper = self.oper

        self.response_func = getattr(_client, "parse_%s_response" % query)
        qargs = self.args.copy()
        self.relay_state = rndstr()

        if "message" not in _oper.args:
            self.qfunc = getattr(_client, "create_%s" % query)
            # remove args the create function can't handle
            fargs = inspect.getargspec(self.qfunc).args
            if _oper._class:
                fargs.extend([p for p, c, r in
                              _oper._class.c_attributes.values()])
                fargs.extend([p for p, c in _oper._class.c_children.values()])
            for arg in qargs.keys():
                if arg not in fargs:
                    del qargs[arg]

        self.qargs = qargs

    def my_endpoints(self):
        return [e for e, b in self.client.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"]]

    def handle_result(self):
        try:
            if self.last_response.status_code in [302, 303]:
                return False
        except AttributeError:
            pass

        _resp = None
        try:
            response = self.oper.post_processing(self.last_content)
            if isinstance(response, dict):
                try:
                    assert self.relay_state == response["RelayState"]
                except KeyError:
                    pass
                response = response["SAMLResponse"]
            _resp = self.response_func(response, **self.response_args)
            self.saml_response.append(_resp)
            try:
                self.test_sequence(self.oper.tests["post"])
            except KeyError:
                pass
            self.trace.info("SAML Response: %s" % _resp)
        except FatalError, ferr:
            if _resp:
                self.trace.info("Faulty response: %s" % _resp)
            self.trace.error("Exception %s" % ferr)
            raise
        except Exception, err:
            if _resp:
                self.trace.info("Faulty response: %s" % _resp)
            self.trace.error("Exception %s" % err)
            self.err_check("exception", err)

        return True