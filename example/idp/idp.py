#!/usr/bin/env python

import re
import logging

#from cgi import parse_qs
from urlparse import parse_qs
from saml2.httputil import Unauthorized, NotFound, BadRequest
from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.pack import http_form_post_message
from saml2.saml import AUTHN_PASSWORD
from saml2 import server
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2 import time_util
from Cookie import SimpleCookie

logger = logging.getLogger("saml2.IDP")

AUTHN = (AUTHN_PASSWORD, "http://www.example.com/login")

def _expiration(timeout, format=None):
    if timeout == "now":
        return time_util.instant(format)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, format=format)

# -----------------------------------------------------------------------------
def dict_to_table(ava, lev=0, width=1):
    txt = ['<table border=%s bordercolor="black">\n' % width]
    for prop, valarr in ava.items():
        txt.append("<tr>\n")
        if isinstance(valarr, basestring):
            txt.append("<th>%s</th>\n" % str(prop))
            try:
                txt.append("<td>%s</td>\n" % valarr.encode("utf8"))
            except AttributeError:
                txt.append("<td>%s</td>\n" % valarr)
        elif isinstance(valarr, list):
            index = 0
            num = len(valarr)       
            for val in valarr:
                if not index:
                    txt.append("<th rowspan=%d>%s</td>\n" % (len(valarr), prop))
                else:
                    txt.append("<tr>\n")
                if isinstance(val, dict):
                    txt.append("<td>\n")
                    txt.extend(dict_to_table(val, lev+1, width-1))
                    txt.append("</td>\n")
                else:
                    try:
                        txt.append("<td>%s</td>\n" % val.encode("utf8"))
                    except AttributeError:
                        txt.append("<td>%s</td>\n" % val)
                if num > 1:
                    txt.append("</tr>\n")
                num -= 1
                index += 1
        elif isinstance(valarr, dict):
            txt.append("<th>%s</th>\n" % prop)
            txt.append("<td>\n")
            txt.extend(dict_to_table(valarr, lev+1, width-1))
            txt.append("</td>\n")
        txt.append("</tr>\n")
    txt.append('</table>\n')
    return txt
    
REPOZE_ID_EQUIVALENT = "uid"
FORM_SPEC = """<form name="myform" method="post" action="%s">
   <input type="hidden" name="SAMLResponse" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
</form>"""


def sso(environ, start_response, user):
    """ Supposed to return a self issuing Form POST """
    #edict = dict_to_table(environ)
    #if logger: logger.info("Environ keys: %s" % environ.keys())
    logger.info("--- In SSO ---")
    query = None
    if "QUERY_STRING" in environ:
        if logger:
            logger.info("Query string: %s" % environ["QUERY_STRING"])
        query = parse_qs(environ["QUERY_STRING"])
    elif "s2repoze.qinfo" in environ:
        query = environ["s2repoze.qinfo"]

    if not query:
        resp = Unauthorized('Unknown user')
        return resp(environ, start_response)
        
    # base 64 encoded request
    # Assume default binding, that is HTTP-redirect
    req = IDP.parse_authn_request(query["SAMLRequest"][0])

    if req is None:
        resp = ServiceError("Failed to parse the SAML request")
        return resp(environ, start_response)

    logger.info("parsed OK")
    logger.info("%s" % req)

    identity = dict(environ["repoze.who.identity"]["user"])
    logger.info("Identity: %s" % (identity,))
    userid = environ["repoze.who.identity"]['repoze.who.userid']
    if REPOZE_ID_EQUIVALENT:
        identity[REPOZE_ID_EQUIVALENT] = userid

    # What's the binding ? ProtocolBinding
    if req.message.protocol_binding == BINDING_HTTP_REDIRECT:
        _binding = BINDING_HTTP_POST
    else:
        _binding = req.message.protocol_binding

    try:
        resp_args = IDP.response_args(req.message, [_binding])
    except Exception:
        raise

    if req.message.assertion_consumer_service_url:
        if req.message.assertion_consumer_service_url != resp_args["destination"]:
            # serious error on someones behalf
            logger.error("%s != %s" % (req.message.assertion_consumer_service_url,
                                       resp_args["destination"]))
            resp = BadRequest("ConsumerURL and return destination mismatch")
            raise resp(environ, start_response)

    try:
        authn_resp = IDP.create_authn_response(identity, userid=userid,
                                               authn=AUTHN, **resp_args)
    except Exception, excp:
        logger.error("Exception: %s" % (excp,))
        raise
        
    logger.info("AuthNResponse: %s" % authn_resp)

    http_args = http_form_post_message(authn_resp, resp_args["destination"],
                                       relay_state=query["RelayState"][0],
                                       typ="SAMLResponse")

    resp = Response(http_args["data"], headers=http_args["headers"])
    return resp(environ, start_response)
    
def whoami(environ, start_response, user):
    identity = environ["repoze.who.identity"].copy()
    for prop in ["login", "password"]:
        try:
            del identity[prop]
        except KeyError:
            continue
    response = Response(dict_to_table(identity))
    return response(environ, start_response)
    
def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound('Not Found')
    return resp(environ, start_response)

def not_authn(environ, start_response):
    if "QUERY_STRING" in environ:
        query = parse_qs(environ["QUERY_STRING"])
        logger.info("query: %s" % query)
    resp = Unauthorized('Unknown user')
    return resp(environ, start_response)

def slo(environ, start_response, user):
    """ Expects a HTTP-redirect logout request """

    query = None
    if "QUERY_STRING" in environ:
        logger.info("Query string: %s" % environ["QUERY_STRING"])
        query = parse_qs(environ["QUERY_STRING"])

    if not query:
        resp = Unauthorized('Unknown user')
        return resp(environ, start_response)

    try:
        req_info = IDP.parse_logout_request(query["SAMLRequest"][0],
                                            BINDING_HTTP_REDIRECT)
        logger.info("LOGOUT request parsed OK")
        logger.info("REQ_INFO: %s" % req_info.message)
    except KeyError, exc:
        logger.info("logout request error: %s" % (exc,))
        resp = BadRequest('Request parse error')
        return resp(environ, start_response)

    # look for the subject
    subject = req_info.subject_id()
    subject = subject.text.strip()
    logger.info("Logout subject: %s" % (subject,))

    status = None

    # Either HTTP-Post or HTTP-redirect is possible, prefer HTTP-Post.
    # Order matters
    bindings = [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT]
    try:
        response = IDP.create_logout_response(req_info.message,
                                                        bindings)
        binding, destination = IDP.pick_binding("single_logout_service",
                                                bindings, "spsso", response)

        http_args = IDP.apply_binding(binding, "%s" % response, destination,
                                      query["RelayState"], response=True)

    except Exception, exc:
        resp = BadRequest('%s' % exc)
        return resp(environ, start_response)

    delco = delete_cookie(environ, "pysaml2idp")
    if delco:
        http_args["headers"].append(delco)

    if binding == BINDING_HTTP_POST:
        resp = Response(http_args["data"], headers=http_args["headers"])
    else:
        resp = NotFound(http_args["data"], headers=http_args["headers"])
    return resp(environ, start_response)

def delete_cookie(environ, name):
    kaka = environ.get("HTTP_COOKIE", '')
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get(name, None)
        cookie = SimpleCookie()
        cookie[name] = morsel
        cookie[name]["expires"] = \
            _expiration("now", "%a, %d-%b-%Y %H:%M:%S CET")
        return tuple(cookie.output().split(": ", 1))
    return None
    
# ----------------------------------------------------------------------------

# map urls to functions
URLS = [
    (r'whoami$', whoami),
    (r'whoami/(.*)$', whoami),
    (r'sso$', sso),
    (r'sso/(.*)$', sso),
    (r'logout$', slo),
    (r'logout/(.*)$', slo),
]

# ----------------------------------------------------------------------------

def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above and store the regular expression
    captures in the WSGI environment as  `myapp.url_args` so that
    the functions from above can access the url placeholders.

    If nothing matches call the `not_found` function.
    
    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the 
        request is done
    :return: The response as a list of lines
    """
    user = environ.get("REMOTE_USER", "")
    kaka = environ.get("HTTP_COOKIE", '')
    if not user:
        user = environ.get("repoze.who.identity", "")

    path = environ.get('PATH_INFO', '').lstrip('/')
    logger.info("<application> PATH: %s" % path)
    logger.info("Cookie: %s" % (kaka,))
    for regex, callback in URLS:
        if user:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path
                logger.info("callback: %s" % (callback,))
                return callback(environ, start_response, user)
        else:
            logger.info("-- No USER --")
            return not_authn(environ, start_response)
    return not_found(environ, start_response)

# ----------------------------------------------------------------------------

from repoze.who.config import make_middleware_with_config

APP_WITH_AUTH = make_middleware_with_config(application, {"here":"."}, 
                        './who.ini', log_file="repoze_who.log")

# ----------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    from wsgiref.simple_server import make_server

    PORT = 8088

    IDP = server.Server(sys.argv[1])
    SRV = make_server('localhost', PORT, APP_WITH_AUTH)
    print "IdP listening on port: %s" % PORT
    SRV.serve_forever()