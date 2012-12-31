#!/usr/bin/env python
from Cookie import SimpleCookie
import logging

import re
from urlparse import parse_qs
from example.idp.idp import delete_cookie
from saml2 import BINDING_HTTP_REDIRECT, time_util
from saml2.httputil import Response
from saml2.httputil import Unauthorized
from saml2.httputil import NotFound
from saml2.httputil import Redirect
from saml2.httputil import ServiceError

logger = logging.getLogger("saml2.SP")

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
            i = 0
            n = len(valarr)       
            for val in valarr:
                if not i:
                    txt.append("<th rowspan=%d>%s</td>\n" % (len(valarr),prop))
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
                if n > 1:
                    txt.append("</tr>\n")
                n -= 1
                i += 1
        elif isinstance(valarr, dict):
            txt.append("<th>%s</th>\n" % prop)
            txt.append("<td>\n")
            txt.extend(dict_to_table(valarr, lev+1, width-1))
            txt.append("</td>\n")
        txt.append("</tr>\n")
    txt.append('</table>\n')
    return txt

def _expiration(timeout, format=None):
    if timeout == "now":
        return time_util.instant(format)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, format=format)

def delete_cookie(environ, name):
    kaka = environ.get("HTTP_COOKIE", '')
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get(name, None)
        cookie = SimpleCookie()
        cookie[name] = morsel
        cookie[name]["expires"] =\
        _expiration("now", "%a, %d-%b-%Y %H:%M:%S CET")
        return tuple(cookie.output().split(": ", 1))
    return None

# ----------------------------------------------------------------------------

#noinspection PyUnusedLocal
def whoami(environ, start_response, user):
    identity = environ["repoze.who.identity"]["user"]
    if not identity:
        return not_authn(environ, start_response)
    response = ["<h2>Your identity are supposed to be</h2>"]
    response.extend(dict_to_table(identity))
    response.extend("<a href='logout'>Logout</a>")
    resp = Response(response)
    return resp(environ, start_response)
    
#noinspection PyUnusedLocal
def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound('Not Found')
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def not_authn(environ, start_response):
    resp = Unauthorized('Unknown user')
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def slo(environ, start_response, user):
    # so here I might get either a LogoutResponse or a LogoutRequest
    client = environ['repoze.who.plugins']["saml2auth"]
    sc = client.saml_client

    if "QUERY_STRING" in environ:
        query = parse_qs(environ["QUERY_STRING"])
        logger.info("query: %s" % query)
        try:
            response = sc.parse_logout_request_response(query["SAMLResponse"][0],
                                                  binding=BINDING_HTTP_REDIRECT)
            if response:
                logger.info("LOGOUT response parsed OK")
        except KeyError:
            # return error reply
            response = None

        if response is None:
            request = sc.lo

    headers = [("Location", "/done")]
    delco = delete_cookie(environ, "pysaml2")
    if delco:
        headers.append(delco)
    resp = Redirect("Successful Logout", headers=headers)
    return resp(environ, start_response)
    
#noinspection PyUnusedLocal
def logout(environ, start_response, user):
    # This is where it starts when a user wants to log out
    client = environ['repoze.who.plugins']["saml2auth"]
    subject_id = environ["repoze.who.identity"]['repoze.who.userid']
    logger.info("[logout] subject_id: '%s'" % (subject_id,))
    target = "/done"

    # What if more than one
    tmp = client.saml_client.global_logout(subject_id)
    logger.info("[logout] global_logout > %s" % (tmp,))
    (session_id, code, header, result) = tmp

    if session_id:
        start_response(code, header)
        return result
    else: # All was done using SOAP
        if result:
            resp = Redirect("Successful Logout", headers=[("Location", target)])
            return resp(environ, start_response)
        else:
            resp = ServiceError("Failed to logout from identity services")
            start_response("500 Internal Server Error")
            return []

#noinspection PyUnusedLocal
def done(environ, start_response, user):
    # remove cookie and stored info
    logger.info("[done] environ: %s" % environ)
    subject_id = environ["repoze.who.identity"]['repoze.who.userid']
    client = environ['repoze.who.plugins']["saml2auth"]
    logger.info("[logout done] remaining subjects: %s" % (
                                        client.saml_client.users.subjects(),))

    start_response('200 OK', [('Content-Type', 'text/html')])
    return ["<h3>You are now logged out from this service</h3>"]
        
# ----------------------------------------------------------------------------

# map urls to functions
urls = [
    (r'whoami$', whoami),
    (r'logout$', logout),
    (r'done$', done),
    (r'slo$', slo),
    (r'^$', whoami),
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
    if not user:
        user = environ.get("repoze.who.identity", "")
            
    path = environ.get('PATH_INFO', '').lstrip('/')
    logger.info("<application> PATH: %s" % path)
    logger.info("logger name: %s" % logger.name)
    #logger.info(logging.Logger.manager.loggerDict)
    for regex, callback in urls:
        if user:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path
                return callback(environ, start_response, user)
        else:
             return not_authn(environ, start_response)
    return not_found(environ, start_response)

# ----------------------------------------------------------------------------

from repoze.who.config import make_middleware_with_config

app_with_auth = make_middleware_with_config(application, {"here":"."}, 
                        './who.ini', log_file="repoze_who.log")

# ----------------------------------------------------------------------------
PORT = 8087

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    srv = make_server('localhost', PORT, app_with_auth)
    print "SP listening on port: %s" % PORT
    srv.serve_forever()