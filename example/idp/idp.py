#!/usr/bin/env python

import re
import base64
from cgi import parse_qs
from saml2 import server
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2 import time_util
from Cookie import SimpleCookie

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

def sso(environ, start_response, user, logger):
    """ Supposted to return a POST """
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
        start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
        return ['Unknown user']
        
    # base 64 encoded request
    req_info = IDP.parse_authn_request(query["SAMLRequest"][0])
    logger.info("parsed OK")
    logger.info("%s" % req_info)

    identity = dict(environ["repoze.who.identity"]["user"])
    logger.info("Identity: %s" % (identity,))
    userid = environ["repoze.who.identity"]['repoze.who.userid']
    if REPOZE_ID_EQUIVALENT:
        identity[REPOZE_ID_EQUIVALENT] = userid
    try:
        authn_resp = IDP.authn_response(identity, 
                                        req_info["id"], 
                                        req_info["consumer_url"], 
                                        req_info["sp_entity_id"], 
                                        req_info["request"].name_id_policy, 
                                        userid)
    except Exception, excp:
        if logger: logger.error("Exception: %s" % (excp,))
        raise
        
    if logger: logger.info("AuthNResponse: %s" % authn_resp)

    response = ["<head>",
                "<title>SAML 2.0 POST</title>",
                "</head><body>",
                FORM_SPEC % (req_info["consumer_url"],
                             base64.b64encode("".join(authn_resp)), "/"),
                """<script type="text/javascript" language="JavaScript">""",
                "     document.myform.submit();",
                """</script>""",
                "</body>"]

    start_response('200 OK', [('Content-Type', 'text/html')])
    return response
    
def whoami(environ, start_response, user, logger):
    start_response('200 OK', [('Content-Type', 'text/html')])
    identity = environ["repoze.who.identity"].copy()
    for prop in ["login", "password"]:
        try:
            del identity[prop]
        except KeyError:
            continue
    response = dict_to_table(identity)
    return response[:]
    
def not_found(environ, start_response, logger):
    """Called if no URL matches."""
    start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
    return ['Not Found']

def not_authn(environ, start_response, logger):
    if "QUERY_STRING" in environ:
        query = parse_qs(environ["QUERY_STRING"])
        if logger: logger.info("query: %s" % query)
    start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
    return ['Unknown user']

def slo(environ, start_response, user, logger):
    """ Expects a HTTP-redirect logout request """

    query = None
    if "QUERY_STRING" in environ:
        if logger: logger.info("Query string: %s" % environ["QUERY_STRING"])
        query = parse_qs(environ["QUERY_STRING"])

    if not query:
        start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
        return ['Unknown user']

    try:
        req_info = IDP.parse_logout_request(query["SAMLRequest"][0],
                                            BINDING_HTTP_REDIRECT)
        logger.info("LOGOUT request parsed OK")
        logger.info("REQ_INFO: %s" % req_info.message)
    except KeyError, exc:
        if logger: logger.info("logout request error: %s" % (exc,))
        # return error reply

    # look for the subject
    subject = req_info.subject_id()
    subject = subject.text.strip()
    sp_entity_id = req_info.message.issuer.text.strip()
    logger.info("Logout subject: %s" % (subject,))
    logger.info("local identifier: %s" % IDP.ident.local_name(sp_entity_id, 
                                                                subject))
    # remove the authentication
    
    status = None

    # Either HTTP-Post or HTTP-redirect is possible
    bindings = [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT]
    (resp, headers, message) = IDP.logout_response(req_info.message, bindings)
    #headers.append(session.cookie(expire="now"))
    logger.info("Response code: %s" % (resp,))
    logger.info("Header: %s" % (headers,))
    delco = delete_cookie(environ, "pysaml2idp")
    if delco:
        headers.append(delco)
    start_response(resp, headers)
    return message

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
    logger = environ.get('repoze.who.logger')
    if logger: logger.info("<application> PATH: %s" % path)
    if logger: logger.info("Cookie: %s" % (kaka,))
    for regex, callback in URLS:
        if user:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path
                if logger: logger.info("callback: %s" % (callback,))
                return callback(environ, start_response, user, logger)
        else:
            if logger: logger.info("-- No USER --")
            return not_authn(environ, start_response, logger)
    return not_found(environ, start_response, logger)

# ----------------------------------------------------------------------------

from repoze.who.config import make_middleware_with_config

APP_WITH_AUTH = make_middleware_with_config(application, {"here":"."}, 
                        './who.ini', log_file="app.log")

# ----------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    from wsgiref.simple_server import make_server
    import logging
    LOG_FILENAME = "./idp.log"
    PORT = 8088
    
    logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG)    
    
    IDP = server.Server(sys.argv[1], log=logging, debug=1)
    SRV = make_server('localhost', PORT, APP_WITH_AUTH)
    print "IdP listening on port: %s" % PORT
    SRV.serve_forever()