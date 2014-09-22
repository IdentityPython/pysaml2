import base64
import cookielib
import re
import os
import traceback
import urllib
import sys

from urlparse import parse_qs
from saml2 import BINDING_HTTP_REDIRECT, class_name
from saml2 import BINDING_HTTP_POST
from saml2.request import SERVICE2REQUEST
from saml2.sigver import signed_instance_factory, pre_signature_part
from saml2.httputil import HttpParameters

from saml2test import CheckError, FatalError
from saml2test.check import Check
from saml2test.check import ExpectedError
from saml2test.check import INTERACTION
from saml2test.check import STATUSCODE
from saml2test.interaction import Action
from saml2test.interaction import Interaction
from saml2test.interaction import InteractionNeeded

import xmldsig as ds

from sp_test.tests import ErrorResponse
from sp_test.check import VerifyEchopageContents

__author__ = 'rolandh'

import logging

logger = logging.getLogger(__name__)

FILE_EXT = {"text/html": "html", "test/plain": "txt", "application/json": "json",
            "text/xml": "xml", "application/xml": "xml", }

camel2underscore = re.compile('((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')


class Conversation():
    def __init__(self, instance, config, interaction, json_config,
                 check_factory, entity_id, msg_factory=None,
                 features=None, constraints=None,  # verbose=False,
                 expect_exception=None, commandlineargs=None):
        self.instance = instance
        self._config = config
        self.test_output = []
        self.features = features
        #self.verbose = verbose  # removed (not used)
        self.check_factory = check_factory
        self.msg_factory = msg_factory
        self.expect_exception = expect_exception
        self.commandlineargs = commandlineargs

        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}

        self.protocol_response = []
        self.last_response = None
        self.last_content = None
        self.response = None
        self.interaction = Interaction(self.instance, interaction)
        self.exception = None

        self.entity_id = entity_id
        self.cjar = {"rp": cookielib.CookieJar()}
        self.args = {}
        self.qargs = {}
        self.response_args = {}
        self.saml_response = []
        self.destination = ""
        self.request = None
        self.position = ""
        self.response = None
        self.oper = None
        self.msg_constraints = constraints
        self.json_config = json_config
        self.start_page = json_config["start_page"]

    def check_severity(self, stat):
        if stat["status"] >= 3:
            logger.error("WHERE: %s" % stat["id"])
            logger.error("STATUS:%s" % STATUSCODE[stat["status"]])
            try:
                logger.error("HTTP STATUS: %s" % stat["http_status"])
            except KeyError:
                pass
            try:
                logger.error("INFO: %s" % stat["message"])
            except KeyError:
                pass

            raise CheckError

    def do_check(self, test, **kwargs):
        if isinstance(test, basestring):
            chk = self.check_factory(test)(**kwargs)
        else:
            chk = test(**kwargs)
        if not chk.call_on_redirect() and \
           300 < self.last_response.status_code <= 303:
            pass
        else:
            stat = chk(self, self.test_output)
            self.check_severity(stat)

    def err_check(self, test, err=None, bryt=True):
        if err:
            self.exception = err
        chk = self.check_factory(test)()
        chk(self, self.test_output)
        if bryt:
            e = FatalError("%s" % err)
            e.trace = "".join(traceback.format_exception(*sys.exc_info()))
            raise e

    def test_sequence(self, sequence):
        if sequence is None:
            return True

        for test in sequence:
            if isinstance(test, tuple):
                test, kwargs = test
            else:
                kwargs = {}
            self.do_check(test, **kwargs)
            if test == ExpectedError:
                return False  # TODO: return value is unused
        return True

    def my_endpoints(self):
        for serv in ["aa", "aq", "idp"]:
            endpoints = self._config.getattr("endpoints", serv)
            if endpoints:
                for typ, spec in endpoints.items():
                    for url, binding in spec:
                        yield url

    def which_endpoint(self, url):
        for serv in ["aa", "aq", "idp"]:
            endpoints = self._config.getattr("endpoints", serv)
            if endpoints:
                for typ, spec in endpoints.items():
                    for endp, binding in spec:
                        if url.startswith(endp):
                            return typ, binding
        return None

    def _log_response(self, response):
        """Depending on -k argument write content to either logger or extra file

        Create the <operation> directory; delete all possibly existing files
        Write response content into response_x.<ext> (with x incrementing from 0)
        """
        logger.info("<-- Status: %s" % response.status_code)
        if response.status_code in [302, 301, 303]:
            logger.info("<-- location: %s" %
                        response.headers._store['location'][1])
        else:
            if self.commandlineargs.content_log:
                self._content_log_fileno = getattr(self, '_content_log_fileno', 0) + 1
                if not getattr(self, 'logcontentpath', None):
                    try:
                        content_type_hdr = response.headers._store['content-type'][1]
                        l = content_type_hdr.split(';') + ['charset=ISO-8859-1',]
                        content_type = l[0]
                        encoding = l[1].split("=")
                        ext = "." + FILE_EXT[content_type]
                    except Exception as e:
                        ext = ""
                    self._logcontentpath = os.path.join(
                        self.commandlineargs.logpath,
                        self.commandlineargs.oper)
                    if not os.path.exists(self._logcontentpath):
                        os.makedirs(self._logcontentpath)
                    for fn in os.listdir(self._logcontentpath):
                        old_file = os.path.join(self._logcontentpath, fn)
                        if os.path.isfile(old_file):
                            os.unlink(old_file)
                fn = os.path.join(self._logcontentpath, "response_%d%s"
                                  % (self._content_log_fileno, ext ))
                f = open(fn, "w")
                f.write(response.content)
                f.close()
                logger.info("<-- Response content (encoding=%s) in file %s" %
                            (encoding, fn))
                pass
            else:
                logger.info("<-- Content: %s" % response.content)

    def wb_send_GET_startpage(self):
        """
        The action that starts the whole sequence, a HTTP GET on a web page
        """
        self.last_response = self.instance.send(self.start_page)
        self._log_response(self.last_response)

    def handle_result(self, check_response=None):
        if check_response:
            if isinstance(check_response(), Check):
                if 300 < self.last_response.status_code <= 303:
                    self._redirect(self.last_response)
                self.do_check(check_response)
            else:
                # A HTTP redirect or HTTP Post
                if 300 < self.last_response.status_code <= 303:
                    self._redirect(self.last_response)

                if self.last_response.status_code >= 400:
                    raise FatalError(self.last_response.reason)

                _txt = self.last_response.content
                assert _txt.startswith("<h2>")
        else:
            if 300 < self.last_response.status_code <= 303:
                self._redirect(self.last_response)

            _txt = self.last_response.content
            if self.last_response.status_code >= 400:
                raise FatalError("Did not expected error")

    def parse_saml_message(self):
        try:
            url, query = self.last_response.headers["location"].split("?")
        except KeyError:
            return

        _dict = parse_qs(query)
        try:
            self.relay_state = _dict["RelayState"][0]
        except KeyError:
            self.relay_state = ""
        _str = _dict["SAMLRequest"][0]
        self.saml_request = self.instance._parse_request(
            _str, SERVICE2REQUEST[self._endpoint], self._endpoint,
            self._binding)
        if self._binding == BINDING_HTTP_REDIRECT:
            self.http_parameters = HttpParameters(_dict)

    def _redirect(self, _response):
        rdseq = []
        url = None
        while _response.status_code in [302, 301, 303]:
            url = _response.headers["location"]
            if url in rdseq:
                raise FatalError("Loop detected in redirects")
            else:
                rdseq.append(url)
                if len(rdseq) > 8:
                    raise FatalError(
                        "Too long sequence of redirects: %s" % rdseq)

            logger.info("--> REDIRECT TO: %s" % url)
            # If back to me
            for_me = False
            try:
                self._endpoint, self._binding = self.which_endpoint(url)
                for_me = True
            except TypeError:
                pass

            if for_me:
                break
            else:
                try:
                    _response = self.instance.send(url, "GET")
                except Exception, err:
                    raise FatalError("%s" % err)

                self._log_response(_response)
                self.last_response = _response
                if _response.status_code >= 400:
                    break
        return url

    def send_idp_response(self, req_flow, resp_flow):
        """
        :param req_flow: The flow to check the request
        :param resp_flow: The flow to prepare the response
        :return: The SP's HTTP response on receiving the SAML response
        """

        # Pick information from the request that should be in the response
        args = self.instance.response_args(self.saml_request.message,
                                           [resp_flow._binding])
        _mods = list(resp_flow.__mro__[:])
        _mods.reverse()
        for m in _mods:
            try:
                args.update(self.json_config["args"][m.__name__])
            except KeyError:
                pass

        args.update(resp_flow._response_args)

        for param in ["identity", "userid"]:
            if param in self.json_config:
                args[param] = self.json_config[param]

        if resp_flow == ErrorResponse:
            func = getattr(self.instance, "create_error_response")
        else:
            _op = camel2underscore.sub(r'_\1', req_flow._class.c_tag).lower()
            func = getattr(self.instance, "create_%s_response" % _op)

        # get from config which parts shall be signed
        sign = []
        for styp in ["sign_assertion", "sign_response"]:
            if styp in args:
                try:
                    if args[styp].lower() == "always":
                        sign.append(styp)
                    del args[styp]
                except (AttributeError, TypeError):
                    raise AssertionError('config parameters "sign_assertion", '
                                         '"sign_response" must be of type string')

        response = func(**args)
        response = resp_flow(self).pre_processing(response)
        # and now for signing
        if sign:
            to_sign = []
            try:
                _digest_alg=args["sign_digest_alg"]
            except KeyError:
                _digest_alg=None
            try:
                _sign_alg=args["sign_signature_alg"]
            except KeyError:
                _sign_alg=None
            # Order is important, first assertion and then response if both
            if "sign_assertion" in sign:
                to_sign = [(class_name(response.assertion),
                            response.assertion.id)]
                response.assertion.signature = pre_signature_part(
                    response.assertion.id, self.instance.sec.my_cert, 1,
                    digest_alg=_digest_alg, sign_alg=_sign_alg)
            if "sign_response" in sign:
                to_sign = [(class_name(response), response.id)]
                response.signature = pre_signature_part(
                    response.id, self.instance.sec.my_cert, 1,
                    digest_alg=_digest_alg, sign_alg=_sign_alg)

            response = signed_instance_factory(response, self.instance.sec,
                                               to_sign)

        info = self.instance.apply_binding(resp_flow._binding, response,
                                           args["destination"],
                                           self.relay_state,
                                           "SAMLResponse", resp_flow._sign)

        if resp_flow._binding == BINDING_HTTP_REDIRECT:
            url = None
            for param, value in info["headers"]:
                if param == "Location":
                    url = value
                    break
            self.last_response = self.instance.send(url)
        elif resp_flow._binding == BINDING_HTTP_POST:
            resp_flow = base64.b64encode("%s" % response)
            info["data"] = urllib.urlencode({"SAMLResponse": resp_flow,
                                             "RelayState": self.relay_state})
            info["method"] = "POST"
            info["headers"] = {
                'Content-type': 'application/x-www-form-urlencoded'}
            self.last_response = self.instance.send(**info)
            try:
                self.last_content = self.last_response.content
            except AttributeError:
                self.last_content = None

        self._log_response(self.last_response)

    def do_flow(self, flow, mid_tests):
        """
        Solicited or 'un-solicited' flows.

        Solicited always starts with the Web client accessing a page.
        Un-solicited starts with the IDP sending a SAMl Response.
        """
        if len(flow) >= 3:
            self.wb_send_GET_startpage()
            self.intermit(flow[0]._interaction)
            self.parse_saml_message()
        # make sure I got the request I expected
        assert isinstance(self.saml_request.message, flow[1]._class)
        try:
            self.test_sequence(mid_tests)
        except KeyError:
            pass
        self.send_idp_response(flow[1], flow[2])
        if len(flow) == 4:
            self.handle_result(flow[3])
        else:
            self.handle_result()

    def do_sequence_and_tests(self, oper, tests=None):
        self.current_oper = oper
        try:
            self.test_sequence(tests["pre"])
        except KeyError:
            pass

        for flow in oper:
            try:
                self.do_flow(flow, tests["mid"])
            except InteractionNeeded:
                self.test_output.append({"status": INTERACTION,
                                         "message": "see detail log for response content",
                                         "id": "exception",
                                         "name": "interaction needed",
                                         "url": self.position})
                break
            except FatalError:
                raise
            except Exception as err:
                #self.err_check("exception", err)
                raise

        try:
            self.test_sequence(tests["post"])
        except KeyError:
            pass

    def intermit(self, page_types):
        """
        Currently handles only SP-issued redirects

        :param page_types: not used (could be used to implement wayf, disco)
        """
        _response = self.last_response
        _last_action = None
        _same_actions = 0
        if _response.status_code >= 400:
            try:
                self.last_content = _response.text
            except AttributeError:
                self.last_content = None
            raise FatalError(
                "HTTP response status code: %d" % _response.status_code)

        url = _response.url
        content = _response.text
        done = False
        while not done:
            rdseq = []
            while _response.status_code in [302, 301, 303]:
                url = _response.headers["location"]
                if url in rdseq:
                    raise FatalError("Loop detected in redirects")
                else:
                    rdseq.append(url)
                    if len(rdseq) > 8:
                        raise FatalError(
                            "Too long sequence of redirects: %s" % rdseq)

                # If back to me
                for_me = False
                try:
                    self._endpoint, self._binding = self.which_endpoint(url)
                    for_me = True
                except TypeError:
                    pass

                if for_me:
                    done = True
                    break
                else:
                    try:
                        _response = self.instance.send(url, "GET")
                    except Exception, err:
                        raise FatalError("%s" % err)

                    self._log_response(_response)
                    content = _response.text
                    self.position = url
                    self.last_content = content
                    self.response = _response

                    if _response.status_code >= 400:
                        done = True
                        break

            if done or url is None:
                break

            _base = url.split("?")[0]

            try:
                _spec = self.interaction.pick_interaction(_base, content)
            except InteractionNeeded:
                self.position = url
                logger.error("Page Content: %s" % content)
                raise
            except KeyError:
                self.position = url
                logger.error("Page Content: %s" % content)
                self.err_check("interaction-needed")

            if _spec == _last_action:
                _same_actions += 1
                if _same_actions >= 3:
                    raise InteractionNeeded("Interaction loop detection")
            else:
                _last_action = _spec

            if len(_spec) > 2:
                logger.info(">> %s <<" % _spec["page-type"])
                if _spec["page-type"] == "login":
                    self.login_page = content

            _op = Action(_spec["control"])

            try:
                _response = _op(self.instance, self, logger, url,
                                _response, content, self.features)
                if isinstance(_response, dict):
                    self.last_response = _response
                    self.last_content = _response
                    return _response
                content = _response.text
                self.position = url
                self.last_content = content
                self.response = _response

                if _response.status_code >= 400:
                    break
            except (FatalError, InteractionNeeded):
                raise
            except Exception, err:
                self.err_check("exception", err, False)

        self.last_response = _response
        try:
            self.last_content = _response.text
        except AttributeError:
            self.last_content = None
