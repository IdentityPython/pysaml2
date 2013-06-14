import logging
from urllib import urlencode
from urlparse import parse_qs
from urlparse import urlsplit
import time
from saml2 import SAMLError
from saml2.cipher import AES
from saml2.httputil import Response
from saml2.httputil import make_cookie
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.httputil import parse_cookie

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class AuthnFailure(SAMLError):
    pass


class EncodeError(SAMLError):
    pass


class UserAuthnMethod(object):
    def __init__(self, srv):
        self.srv = srv

    def __call__(self, *args, **kwargs):
        raise NotImplemented

    def authenticated_as(self, **kwargs):
        raise NotImplemented

    def verify(self, **kwargs):
        raise NotImplemented


def url_encode_params(params=None):
    if not isinstance(params, dict):
        raise EncodeError("You must pass in a dictionary!")
    params_list = []
    for k, v in params.items():
        if isinstance(v, list):
            params_list.extend([(k, x) for x in v])
        else:
            params_list.append((k, v))
    return urlencode(params_list)


def create_return_url(base, query, **kwargs):
    """
    Add a query string plus extra parameters to a base URL which may contain
    a query part already.

    :param base: redirect_uri may contain a query part, no fragment allowed.
    :param query: Old query part as a string
    :param kwargs: extra query parameters
    :return:
    """
    part = urlsplit(base)
    if part.fragment:
        raise ValueError("Base URL contained parts it shouldn't")

    for key, values in parse_qs(query).items():
        if key in kwargs:
            if isinstance(kwargs[key], basestring):
                kwargs[key] = [kwargs[key]]
            kwargs[key].extend(values)
        else:
            kwargs[key] = values

    if part.query:
        for key, values in parse_qs(part.query).items():
            if key in kwargs:
                if isinstance(kwargs[key], basestring):
                    kwargs[key] = [kwargs[key]]
                kwargs[key].extend(values)
            else:
                kwargs[key] = values

        _pre = base.split("?")[0]
    else:
        _pre = base

    logger.debug("kwargs: %s" % kwargs)

    return "%s?%s" % (_pre, url_encode_params(kwargs))


class UsernamePasswordMako(UserAuthnMethod):
    """Do user authentication using the normal username password form
    using Mako as template system"""
    cookie_name = "userpassmako"

    def __init__(self, srv, mako_template, template_lookup, pwd, return_to):
        """
        :param srv: The server instance
        :param mako_template: Which Mako template to use
        :param pwd: Username/password dictionary like database
        :param return_to: Where to send the user after authentication
        :return:
        """
        UserAuthnMethod.__init__(self, srv)
        self.mako_template = mako_template
        self.template_lookup = template_lookup
        self.passwd = pwd
        self.return_to = return_to
        self.active = {}
        self.query_param = "upm_answer"
        self.aes = AES(srv.iv)

    def __call__(self, cookie=None, policy_url=None, logo_url=None,
                 query="", **kwargs):
        """
        Put up the login form
        """
        if cookie:
            headers = [cookie]
        else:
            headers = []

        resp = Response(headers=headers)

        argv = {"login": "",
                "password": "",
                "action": "verify",
                "policy_url": policy_url,
                "logo_url": logo_url,
                "query": query}
        logger.info("do_authentication argv: %s" % argv)
        mte = self.template_lookup.get_template(self.mako_template)
        resp.message = mte.render(**argv)
        return resp

    def verify(self, request, **kwargs):
        """
        Verifies that the given username and password was correct
        :param request: Either the query part of a URL a urlencoded
            body of a HTTP message or a parse such.
        :param kwargs: Catch whatever else is sent.
        :return: redirect back to where ever the base applications
            wants the user after authentication.
        """

        logger.debug("verify(%s)" % request)
        if isinstance(request, basestring):
            _dict = parse_qs(request)
        elif isinstance(request, dict):
            _dict = request
        else:
            raise ValueError("Wrong type of input")

        logger.debug("dict: %s" % _dict)
        logger.debug("passwd: %s" % self.passwd)
        # verify username and password
        try:
            assert _dict["password"][0] == self.passwd[_dict["login"][0]]
            timestamp = str(int(time.mktime(time.gmtime())))
            info = self.aes.encrypt(self.srv.symkey,
                                    "::".join([_dict["login"][0], timestamp]))
            self.active[info] = timestamp
            cookie = make_cookie(self.cookie_name, info, self.srv.seed)
            return_to = create_return_url(self.return_to, _dict["query"][0],
                                          **{self.query_param: "true"})
            resp = Redirect(return_to, headers=[cookie])
        except (AssertionError, KeyError):
            resp = Unauthorized("Unknown user or wrong password")

        return resp

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie is None:
            return None
        else:
            logger.debug("kwargs: %s" % kwargs)
            try:
                info, timestamp = parse_cookie(self.cookie_name,
                                               self.srv.seed, cookie)
                if self.active[info] == timestamp:
                    uid, _ts = self.aes.decrypt(self.srv.symkey,
                                                info).split("::")
                    if timestamp == _ts:
                        return {"uid": uid}
            except Exception:
                pass

        return None

    def done(self, areq):
        try:
            _ = areq[self.query_param]
            return False
        except KeyError:
            return True


class SocialService(UserAuthnMethod):
    def __init__(self, social):
        self.social = social

    def __call__(self, server_env, cookie=None, sid="", query="", **kwargs):
        return self.social.begin(server_env, cookie, sid, query)

    def callback(self, server_env, cookie=None, sid="", query="", **kwargs):
        return self.social.callback(server_env, cookie, sid, query, **kwargs)


class AuthnMethodChooser(object):
    def __init__(self, methods=None):
        self.methods = methods

    def __call__(self, **kwargs):
        if not self.methods:
            raise SAMLError("No authentication methods defined")
        elif len(self.methods) == 1:
            return self.methods[0]
        else:
            pass  # TODO

