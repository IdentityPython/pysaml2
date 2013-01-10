#!/usr/bin/env python
import inspect
import urllib
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.client import Saml2Client

#from idp_test.check import ExpectedError
from saml2.mdstore import REQ2SRV
from saml2.pack import http_redirect_message, http_form_post_message
from saml2.s_utils import rndstr
from idp_test.check import factory
from idp_test.check import STATUSCODE
from idp_test.interaction import Operation
from idp_test.interaction import pick_interaction

__author__ = 'rohe0002'

import cookielib

class FatalError(Exception):
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


def check_severity(stat, trace):
    if stat["status"] >= 4:
        trace.error("WHERE: %s"  % stat["id"])
        trace.error("STATUS:%s" % STATUSCODE[stat["status"]])
        try:
            trace.error("HTTP STATUS: %s"  % stat["http_status"])
        except KeyError:
            pass
        try:
            trace.error("INFO: %s"  % stat["message"])
        except KeyError:
            pass

        raise FatalError


def intermit(client, response, httpc, environ, trace, cjar, interaction,
             test_output, features=None):
    if response.status_code >= 400:
        done = True
    else:
        done = False

    url = response.url
    content = response.text

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
                    response = httpc.send(url, "GET")
                except Exception, err:
                    raise FatalError("%s" % err)

                content = response.text
                trace.reply("CONTENT: %s" % content)
                environ.update({"url": url, "content":content})
                environ["response"].append(response)

                check = factory("check-http-response")()
                stat = check(environ, test_output)
                check_severity(stat, trace)

        if done:
            break

        _base = url.split("?")[0]

        try:
            _spec = pick_interaction(interaction, _base, content)
        except KeyError:
            environ["url"] = url
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
            environ.update({"url": url, "content":content})
            environ["response"].append(response)

            check = factory("check-http-response")()
            stat = check(environ, test_output)
            check_severity(stat, trace)
        except FatalError:
            raise
        except Exception, err:
            environ["exception"] = err
            chk = factory("exception")()
            chk(environ, test_output)

    return response


def do_sequence(config, oper, httpc, trace, interaction, entity_id,
                features=None):
    """

    :param config: SP configuration
    :param oper: A dictionary describing the operations to perform
    :param httpc: A HTTP Client instance
    :param trace: A Trace instance that keep all the trace information
    :param interaction: A list of interaction definitions
    :param entity_id: The entity_id of the IdP
    :param features: ?
    :returns: A 2-tuple (testoutput, tracelog)
    """

    client = Saml2Client(config)
    test_output = []
    environ = {"metadata": client.metadata,
               "client": client,
               "httpc": httpc,
               "response": []}

    cjar = {"browser": cookielib.CookieJar(),
            "rp": cookielib.CookieJar(),
            "service": cookielib.CookieJar()}

    environ["FatalError"] = False
    for op in oper["sequence"]:
        output = do_query(client, op(), httpc, trace, interaction, entity_id,
                          environ, cjar, features)
        test_output.extend(output)
        if environ["FatalError"]:
            break
    return test_output, "%s" % trace


def do_query(client, oper, httpc, trace, interaction, entity_id, environ, cjar,
             features=None):
    """

    :param client: A SAML2 client
    :param oper: A Request class instance
    :param httpc: A HTTP Client instance
    :param trace: A Trace instance that keep all the trace information
    :param interaction: A list of interaction definitions
    :param entity_id: The entity_id of the IdP
    :param environ: Local environment
    :param features: ?
    :returns: A 2-tuple (testoutput, tracelog)
    """

    oper.setup(environ)
    query = oper.request
    args = oper.args
    args["entity_id"] = entity_id
    test_output = []

    try:
        for test in oper.tests["pre"]:
            chk = test()
            stat = chk(environ, test_output)
            try:
                check_severity(stat, trace)
            except FatalError:
                environ["FatalError"] = True
                raise
    except KeyError:
        pass

    httpc.cookiejar = cjar["browser"]

    srvs = getattr(client.metadata, REQ2SRV[query])(args["entity_id"],
                                                    args["binding"],
                                                    "idpsso")

    relay_state = rndstr()
    _response_func = getattr(client, "parse_%s_response" % query)
    response_args = {}
    qargs = args.copy()

    use_artifact = getattr(oper, "use_artifact", False)

    qfunc = getattr(client, "create_%s" % query)
    # remove args the create function can't handle
    fargs = inspect.getargspec(qfunc).args
    for arg in qargs.keys():
        if arg not in fargs:
            del qargs[arg]

    for srv in srvs:
        loc = srv["location"]
        qargs["destination"] = loc
        environ["destination"] = loc

        req = qfunc(**qargs)
        environ["request"] = req
        _req_str = "%s" % req
        if use_artifact:
            saml_art = client.use_artifact(_req_str, args["entity_id"])
            trace.info("SAML Artifact: %s" % saml_art)
            info_typ = "SAMLart"
        else:
            trace.info("SAML Request: %s" % _req_str)
            info_typ = "SAMLRequest"
        # depending on binding send the query

        if args["binding"] is BINDING_SOAP:
            response = httpc.send_using_soap(_req_str, loc)
            response_args["binding"] = BINDING_SOAP
        else:
            response_args["binding"] = BINDING_HTTP_POST
            if args["binding"] is BINDING_HTTP_REDIRECT:
                htargs = http_redirect_message(_req_str, loc, relay_state,
                                               info_typ)
                #
                res = httpc.send(htargs["headers"][0][1], "GET")
            elif args["binding"] is BINDING_HTTP_POST:
                htargs = http_form_post_message(_req_str, loc, relay_state,
                                                info_typ)
                info = unpack_form(htargs["data"][3])
                data = form_post(info)
                htargs["data"] = data
                htargs["headers"] = tuple_list2dict(htargs["headers"])
                res = httpc.send(loc, "POST", **htargs)
            else:
                res = None

            if res:
                response_args["outstanding"] = {req.id: "/"}
                # deal with redirect, should in the end give me a response
                try:
                    response = intermit(client, res, httpc, environ, trace, cjar,
                                        interaction, test_output, features)
                except FatalError:
                    environ["FatalError"] = True
                    response = None

                if isinstance(response, dict):
                    assert relay_state == response["RelayState"]
            else:
                response = None

        if response:
            try:
                if isinstance(response, dict):
                    response = response["SAMLResponse"]
                _resp = _response_func(response, **response_args)
                environ["response"].append(_resp)
                trace.info("SAML Response: %s" % _resp)
                try:
                    for test in oper.tests["post"]:
                        chk = test()
                        stat = chk(environ, test_output)
                        check_severity(stat, trace)
                except KeyError:
                    pass
                except FatalError:
                    environ["FatalError"] = True
                break
            except Exception, err:
                environ["exception"] = err
                chk = factory("exception")()
                chk(environ, test_output)

    return test_output
