import cookielib
import inspect

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.binding import http_redirect_message
from saml2.binding import http_post_message
from saml2.binding import send_using_soap
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.s_utils import rndstr
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.metadata import REQ2SRV
import time

from idp_test.interaction import Operation
from idp_test.interaction import pick_interaction
from idp_test.check import factory

from idp_test import SAML2

__author__ = 'rolandh'

class FatalError(Exception):
    pass



ORDER = ["url", "response", "content"]

def check_severity(stat):
    if stat["status"] >= 4:
        raise FatalError

def intermit(client, response, httpc, environ, trace, cjar, interaction,
             test_output, features=None):
    if response.status_code >= 400:
        done = True
    else:
        done = False

    while not done:
        while response.status_code in [302, 301, 303]:
            url = response.headers["location"]

            trace.reply("REDIRECT TO: %s" % url)
            # If back to me
            for_me = False
            acs = client.config.getattr("endpoints",
                                        "sp")["assertion_consumer_service"]
            for redirect_uri in acs:
                if url.startswith(redirect_uri):
                    # Back at the RP
                    environ["client"].cookiejar = cjar["rp"]
                    for_me=True

            if for_me:
                done = True
                break
            else:
                try:
                    response = httpc.request(url, "GET", trace=trace)
                except Exception, err:
                    raise FatalError("%s" % err)

                content = response.text
                environ.update({"url": url, "response": response,
                                "content":content})

                check = factory("check-http-response")()
                stat = check(environ, test_output)
                check_severity(stat)

        if done:
            break

        _base = url.split("?")[0]

        try:
            _spec = pick_interaction(interaction, _base, content)
        except KeyError:
            chk = factory("interaction-needed")()
            chk(environ, test_output)
            raise FatalError()

        if len(_spec) > 2:
            trace.info(">> %s <<" % _spec["page-type"])
            if _spec["page-type"] == "login":
                environ["login"] = content

        _op = Operation(_spec["control"])

        try:
            response = _op(httpc, environ, trace, url, response, content,
                           features)
            if isinstance(response, dict):
                return response
            content = response.text
            environ.update({"url": url, "response": response,
                            "content":content})

            check = factory("check-http-response")()
            stat = check(environ, test_output)
            check_severity(stat)
        except FatalError:
            raise
        except Exception, err:
            environ["exception"] = err
            chk = factory("exception")()
            chk(environ, test_output)

    return response

def do_query(config, oper, httpc, trace, interaction):
    environ = {}
    test_output = []
    client = Saml2Client(config)
    query = oper.request
    args = oper.args

    cjar = {"browser": cookielib.CookieJar(),
            "rp": cookielib.CookieJar(),
            "service": cookielib.CookieJar()}

    httpc.cookiejar = cjar["browser"]

    locations = getattr(client.metadata, REQ2SRV[query])(args["entity_id"],
                                                         args["binding"])

    relay_state = rndstr()
    _response_func = getattr(client, "%s_response" % query)
    response_args = {}
    qargs = args.copy()

    qfunc = getattr(client, "create_%s" % query)
    # remove args the create function can't handle
    fargs = inspect.getargspec(qfunc).args
    for arg in qargs.keys():
        if arg not in fargs:
            del qargs[arg]

    resp = None
    for loc in locations:
        qargs["destination"] = loc

        req = qfunc(**qargs)
        _req_str = "%s" % req
        # depending on binding send the query

        if args["binding"] is BINDING_HTTP_REDIRECT:
            (head, _body) = http_redirect_message(_req_str, loc, relay_state)
            res = httpc.request(head[0][1], "GET")
            response_args["outstanding"] = {req.id: "/"}
            # head should contain a redirect
            # deal with redirect, should in the end give me a response
            response = intermit(client, res, httpc, environ, trace, cjar,
                                interaction, test_output, features)
            if isinstance(response, dict):
                assert relay_state == response["RelayState"]
        elif args["binding"] is BINDING_HTTP_POST:
            (head, response) = http_post_message(_req_str, loc, relay_state)
        elif args["binding"] is BINDING_SOAP:
            response = send_using_soap(_req_str, loc, client.config.key_file,
                                       client.config.cert_file,
                                       ca_certs=client.config.ca_certs)
        else:
            response = None

        if response:
            try:
                _ = _response_func(response, **response_args)
                break
            except Exception, err:
                environ["exception"] = err
                chk = factory("exception")()
                chk(environ, test_output)

    return test_output, "%s" % trace

# ========================================================================

class Request(object):
    _args = {}

    def __init__(self):
        self.args = self._args.copy()

class AuthnRequest(Request):
    request = "authn_request"
    _args = {"binding": BINDING_HTTP_REDIRECT,
             "nameid_format": NAMEID_FORMAT_PERSISTENT}

# ========================================================================


if __name__ == "__main__":
    s = SAML2()
    s.run()
