#!/usr/bin/env python
from check import ExpectedError
from check import factory

__author__ = 'rohe0002'

import time
import cookielib

from bs4 import BeautifulSoup

class FatalError(Exception):
    pass

class Trace(object):
    def __init__(self):
        self.trace = []
        self.start = time.time()

    def request(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f --> %s" % (delta, msg))

    def reply(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f <-- %s" % (delta, msg))

    def info(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f %s" % (delta, msg))

    def error(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f [ERROR] %s" % (delta, msg))

    def warning(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f [WARNING] %s" % (delta, msg))

    def __str__(self):
        return "\n". join([t.encode("utf-8") for t in self.trace])

    def clear(self):
        self.trace = []

    def __getitem__(self, item):
        return self.trace[item]

    def next(self):
        for line in self.trace:
            yield line

def flow2sequence(operations, item):
    flow = operations.FLOWS[item]
    return [operations.PHASES[phase] for phase in flow["sequence"]]

def endpoint(client, base):
    for _endp in client._endpoints:
        if getattr(client, _endp) == base:
            return True

    return False

def check_severity(stat):
    if stat["status"] >= 4:
        raise FatalError


def pick_interaction(interactions, _base="", content="", req=None):
    unic = content
    if content:
        _bs = BeautifulSoup(content)
    else:
        _bs = None

    for interaction in interactions:
        _match = 0
        for attr, val in interaction["matches"].items():
            if attr == "url":
                if val == _base:
                    _match += 1
            elif attr == "title":
                if _bs is None:
                    break
                if _bs.title is None:
                    break
                if val in _bs.title.contents:
                    _match += 1
            elif attr == "content":
                if unic and val in unic:
                    _match += 1
            elif attr == "class":
                if req and val == req:
                    _match += 1

        if _match == len(interaction["matches"]):
            return interaction

    raise KeyError("No interaction matched")

ORDER = ["url", "response", "content"]

def run_sequence(client, sequence, trace, interaction, msgfactory,
                 environ=None, tests=None, features=None, verbose=False,
                 cconf=None, except_exception=None):
    item = []
    response = None
    content = None
    url = ""
    test_output = []
    _keystore = client.keystore
    features = features or {}

    cjar = {"browser": cookielib.CookieJar(),
            "rp": cookielib.CookieJar(),
            "service": cookielib.CookieJar()}

    environ["sequence"] = sequence
    environ["cis"] = []
    environ["trace"] = trace
    environ["responses"] = []

    try:
        for creq in sequence:
            req = creq()
            cfunc = getattr(client, "create_%s" % req.request)
            if trace:
                trace.info(70*"=")

            try:
                _pretests = req.tests["pre"]
                for test in _pretests:
                    chk = test()
                    stat = chk(environ, test_output)
                    check_severity(stat)
            except KeyError:
                pass

            try:
                response = cfunc(**req.args)

                try:
                    for test in req.tests["post"]:
                        if isinstance(test, tuple):
                            test, kwargs = test
                        else:
                            kwargs = {}
                        chk = test(**kwargs)
                        stat = chk(environ, test_output)
                        check_severity(stat)
                        if isinstance(chk, ExpectedError):
                            item.append(stat["temp"])
                            del stat["temp"]
                            url = None
                            break
                except KeyError:
                    pass

            except FatalError:
                raise
            except Exception, err:
                environ["exception"] = err
                chk = factory("exception")()
                chk(environ, test_output)
                raise FatalError()

            if not response:
                continue

            if response.status_code >= 400:
                done = True
            elif url:
                done = False
            else:
                done = True

            while not done:
                while response.status_code in [302, 301, 303]:
                    url = response.headers["location"]

                    trace.reply("REDIRECT TO: %s" % url)
                    # If back to me
                    for_me = False
                    for redirect_uri in client.redirect_uris:
                        if url.startswith(redirect_uri):
                            # Back at the RP
                            environ["client"].cookiejar = cjar["rp"]
                            for_me=True

                    if for_me:
                        done = True
                        break
                    else:
                        try:
                            part = do_request(client, url, "GET", trace=trace)
                        except Exception, err:
                            raise FatalError("%s" % err)
                        environ.update(dict(zip(ORDER, part)))
                        (url, response, content) = part

                        check = factory("check-http-response")()
                        stat = check(environ, test_output)
                        check_severity(stat)

                if done:
                    break

                _base = url.split("?")[0]

                try:
                    _spec = pick_interaction(interaction, _base, content)
                except KeyError:
                    if creq.method == "POST":
                        break
                    elif not req.request in ["AuthorizationRequest",
                                             "OpenIDRequest"]:
                        break
                    else:
                        try:
                            _check = getattr(req, "interaction_check")
                        except AttributeError:
                            _check = None

                        if _check:
                            chk = factory("interaction-check")()
                            chk(environ, test_output)
                            raise FatalError()
                        else:
                            chk = factory("interaction-needed")()
                            chk(environ, test_output)
                            raise FatalError()

                if len(_spec) > 2:
                    trace.info(">> %s <<" % _spec["page-type"])
                    if _spec["page-type"] == "login":
                        environ["login"] = content

                _op = Operation(_spec["control"])

                try:
                    part = _op(environ, trace, url, response, content, features)
                    environ.update(dict(zip(ORDER, part)))
                    (url, response, content) = part

                    check = factory("check-http-response")()
                    stat = check(environ, test_output)
                    check_severity(stat)
                except FatalError:
                    raise
                except Exception, err:
                    environ["exception"] = err
                    chk = factory("exception")()
                    chk(environ, test_output)
                    raise FatalError

                #            if done:
                #                break

            info = None
            qresp = None
            resp_type = resp.type
            if response:
                try:
                    ctype = response.headers["content-type"]
                    if ctype == "application/jwt":
                        resp_type = "jwt"
                except (AttributeError, TypeError):
                    pass

            if response.status_code >= 400:
                pass
            elif not url:
                if isinstance(content, Message):
                    qresp = content
                elif response.status_code == 200:
                    info = content
            elif resp.where == "url" or response.status_code == 302:
                try:
                    info = response.headers["location"]
                    resp_type = "urlencoded"
                except KeyError:
                    try:
                        _check = getattr(req, "interaction_check", None)
                    except AttributeError:
                        _check = None

                    if _check:
                        chk = factory("interaction-check")()
                        chk(environ, test_output)
                        raise FatalError()
                    else:
                        chk = factory("missing-redirect")()
                        stat = chk(environ, test_output)
                        check_severity(stat)
            else:
                check = factory("check_content_type_header")()
                stat = check(environ, test_output)
                check_severity(stat)
                info = content

            if info and resp.response:
                if isinstance(resp.response, basestring):
                    response = msgfactory(resp.response)
                else:
                    response = resp.response

                chk = factory("response-parse")()
                environ["response_type"] = response.__name__
                environ["responses"].append((response, info))
                try:
                    qresp = client.parse_response(response, info, resp_type,
                                                  client.state,
                                                  keystore=_keystore,
                                                  client_id=client.client_id,
                                                  scope="openid")
                    if trace and qresp:
                        trace.info("[%s]: %s" % (qresp.type(),
                                                 qresp.to_dict()))
                    item.append(qresp)
                    environ["response_message"] = qresp
                    err = None
                except Exception, err:
                    environ["exception"] = "%s" % err
                    qresp = None
                if err and except_exception:
                    if isinstance(err, except_exception):
                        trace.info("Got expected exception: %s [%s]" % (err,
                                                                        err.__class__.__name__))
                    else:
                        raise
                else:
                    stat = chk(environ, test_output)
                    check_severity(stat)

            if qresp:
                try:
                    for test in resp.tests["post"]:
                        if isinstance(test, tuple):
                            test, kwargs = test
                        else:
                            kwargs = {}
                        chk = test(**kwargs)
                        stat = chk(environ, test_output)
                        check_severity(stat)
                except KeyError:
                    pass

                resp(environ, qresp)

        if tests is not None:
            environ["item"] = item
            for test, args in tests:
                if isinstance(test, basestring):
                    chk = factory(test)(**args)
                else:
                    chk = test(**args)
                try:
                    check_severity(chk(environ, test_output))
                except Exception, err:
                    raise FatalError("%s" % err)

    except FatalError:
        pass
    except Exception, err:
        environ["exception"] = err
        chk = factory("exception")()
        chk(environ, test_output)

    return test_output, "%s" % trace


def run_sequences(client, sequences, trace, interaction,
                  verbose=False):
    for sequence, endpoints, fid in sequences:
        # clear cookie cache
        client.grant.clear()
        try:
            client.http.cookiejar.clear()
        except AttributeError:
            pass

        err = run_sequence(client, sequence, trace, interaction, verbose)

        if err:
            print "%s - FAIL" % fid
            print
            if not verbose:
                print trace
        else:
            print "%s - OK" % fid

        trace.clear()
