#!/usr/bin/env python

import re
import logging
import urllib
import time

from urlparse import parse_qs
from saml2 import server, BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2 import time_util
from Cookie import SimpleCookie
from saml2.httputil import Response, Redirect, Unauthorized
from saml2.pack import http_form_post_message
from saml2.pack import http_soap_message
from saml2.s_utils import rndstr
from saml2.saml import AUTHN_PASSWORD

logger = logging.getLogger("saml2.idp")

def _expiration(timeout, format="%a, %d-%b-%Y %H:%M:%S GMT"):
    if timeout == "now":
        return time_util.instant(format)
    elif timeout == "dawn":
        return time.strftime(format, time.gmtime(0))
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

def get_post(environ):
    # the environment variable CONTENT_LENGTH may be empty or missing
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0

    # When the method is POST the query string will be sent
    # in the HTTP request body which is passed by the WSGI server
    # in the file like wsgi.input environment variable.
    return environ['wsgi.input'].read(request_body_size)

# -----------------------------------------------------------------------------
AUTHN = (AUTHN_PASSWORD, "http://lingon.catalogix.se/login")

REPOZE_ID_EQUIVALENT = "uid"
FORM_SPEC = """<form name="myform" method="post" action="%s">
   <input type="hidden" name="SAMLResponse" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
</form>"""

def _sso(environ, start_response, query, binding, user):
    if not query:
        logger.info("Missing QUERY")
        start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
        return ['Unknown user']

    # base 64 encoded request
    req_info = IDP.parse_authn_request(query["SAMLRequest"][0], binding=binding)
    resp_args = IDP.response_args(req_info.message, [BINDING_HTTP_POST])
    logger.info("parsed OK")
    logger.info("%s" % req_info)

    identity = USERS[user]
    logger.info("Identity: %s" % (identity,))

    if REPOZE_ID_EQUIVALENT:
        identity[REPOZE_ID_EQUIVALENT] = user
    try:
        authn_resp = IDP.create_authn_response(identity, userid=user,
                                               authn=AUTHN, **resp_args)
    except Exception, excp:
        if logger: logger.error("Exception: %s" % (excp,))
        raise

    if logger: logger.info("AuthNResponse: %s" % authn_resp)

    http_args = http_form_post_message(authn_resp, resp_args["destination"],
                                       relay_state=query["RelayState"][0],
                                       typ="SAMLResponse")

    resp = Response(http_args["data"], headers=http_args["headers"])
    return resp(environ, start_response)

def sso(environ, start_response, user):
    """ Supposted to return a POST """

    logger.info("--- In SSO ---")
    logger.debug("user: %s" % user)
    logger.info("Query string: %s" % environ["QUERY_STRING"])
    extra = parse_qs(environ["QUERY_STRING"])
    logger.info("EXTRA: %s" % extra)
    logger.debug("keys: %s" % IDP.ticket.keys())
    query = parse_qs(IDP.ticket[extra["key"][0]])
    del IDP.ticket[extra["key"][0]]

    return _sso(environ, start_response, query, BINDING_HTTP_REDIRECT, user)

def sso_post(environ, start_response, user):
    logger.info("--- In SSO POST ---")
    logger.debug("user: %s" % user)
    logger.info("Query string: %s" % environ["QUERY_STRING"])
    extra = parse_qs(environ["QUERY_STRING"])
    logger.info("EXTRA: %s" % extra)
    logger.debug("keys: %s" % IDP.ticket.keys())
    query = parse_qs(IDP.ticket[extra["key"][0]])
    del IDP.ticket[extra["key"][0]]

    return _sso(environ, start_response, query, BINDING_HTTP_POST, user)

def whoami(environ, start_response, user):
    start_response('200 OK', [('Content-Type', 'text/html')])
    identity = USERS[user].copy()
    for prop in ["login", "password"]:
        try:
            del identity[prop]
        except KeyError:
            continue
    response = dict_to_table(identity)
    return response[:]
    
def not_found(environ, start_response):
    """Called if no URL matches."""
    start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
    return ['Not Found']

def not_authn(environ, start_response):
    # redirect to login page
    logger.info("not_authn ENV: %s" % environ)

    loc = "http://%s/login" % (environ["HTTP_HOST"])

    headers = [('Content-Type', 'text/plain')]
    if environ["REQUEST_METHOD"] == "GET":
        if "QUERY_STRING" in environ:
            query = environ["QUERY_STRING"]
            logger.info("query: %s" % query)
            key = hash(query)
            IDP.ticket[str(key)] = query
            loc += "?%s" % urllib.urlencode({"came_from": environ["PATH_INFO"],
                                             "key": key})
    elif environ["REQUEST_METHOD"] == "POST":
        query = get_post(environ)
        logger.info("query: %s" % query)
        key = hash(query)
        IDP.ticket[str(key)] = query
        loc += "?%s" % urllib.urlencode({"came_from": environ["PATH_INFO"],
                                         "key": key})

    logger.debug("location: %s" % loc)
    logger.debug("headers: %s" % headers)
    resp = Redirect(loc, headers=headers)
    return resp(environ, start_response)

def do_authentication(environ, start_response, sid, cookie=None):
    """
    Put up the login form
    """
    query = parse_qs(environ["QUERY_STRING"])

    logger.info("The login page")
    if cookie:
        headers = [cookie]
    else:
        headers = []

    resp = Response(mako_template="login.mako", template_lookup=LOOKUP,
                    headers=headers)

    argv = {
        "action": "/verify",
        "came_from": query["came_from"][0],
        "login": "",
        "password": "",
        "key": query["key"][0]
    }
    logger.info("do_authentication argv: %s" % argv)
    return resp(environ, start_response, **argv)

# ----------------------------------------------------------------------------

PASSWD = [("roland", "dianakra"),
          ("babs", "howes"),
          ("upper", "crust")]


def verify_username_and_password(dic):
    global PASSWD
    # verify username and password
    for user, pwd in PASSWD:
        if user == dic["login"][0]:
            if pwd == dic["password"][0]:
                return True, user

    return False, ""


def do_verify(environ, start_response, _user):
    query = parse_qs(get_post(environ))

    logger.debug("do_verify: %s" % query)

    _ok, user = verify_username_and_password(query)
    if not _ok:
        resp = Unauthorized("Unknown user or wrong password")
    else:
        id = rndstr()
        IDP.authn[id] = user
        logger.debug("Register %s under '%s'" % (user, id))
        kaka = set_cookie("idpauthn", "/", id)
        lox = "http://%s%s?id=%s&key=%s" % (environ["HTTP_HOST"],
                                            query["came_from"][0], id,
                                            query["key"][0])
        logger.debug("Redirect => %s" % lox)
        resp = Redirect(lox, headers=[kaka], content="text/html")

    return resp(environ, start_response)

def kaka2user(kaka):
    logger.debug("KAKA: %s" % kaka)
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get("idpauthn", None)
        if morsel:
            return IDP.authn[morsel.value]
        else:
            logger.debug()
    return None

# ===========================================================================

def _subject_sp_info(req_info):
    # look for the subject
    subject = req_info.subject_id()
    subject = subject.text.strip()
    sp_entity_id = req_info.message.issuer.text.strip()
    return subject, sp_entity_id

def _slo(environ, start_response, query, user):
    try:
        req_info = IDP.parse_logout_request(query["SAMLRequest"][0],
                                            BINDING_HTTP_REDIRECT)
        relay_state = query["SAMLRequest"][0]
        logger.info("LOGOUT request parsed OK")
        logger.info("REQ_INFO: %s" % req_info.message)
    except KeyError, exc:
        if logger: logger.info("logout request error: %s" % (exc,))
        start_response('400 Bad request', [('Content-Type', 'text/plain')])
        return ['Request parse error']

    subject, sp_entity_id = _subject_sp_info(req_info)
    logger.info("Logout subject: %s" % (subject,))
    logger.info("local identifier: %s" % IDP.ident.local_name(sp_entity_id, 
                                                                subject))
    # remove the authentication
    
    status = None

    # Either HTTP-Post or HTTP-redirect is possible
    bindings = [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT]
    logger.debug("logout response to %s" % sp_entity_id)
    logger.debug("entity info: %s" % IDP.metadata.entity[sp_entity_id]["spsso"][0])
    (resp, headers, message) = IDP.create_logout_response(req_info.message,
                                                          bindings)
    #headers.append(session.cookie(expire="now"))
    logger.info("Response code: %s" % (resp,))
    logger.info("Header: %s" % (headers,))
    delco = delete_cookie(environ, "idpauthn")
    if delco:
        headers.append(delco)
    start_response(resp, headers)
    return message

def slo(environ, start_response, user):
    """ Expects a HTTP-redirect logout request """

    query = None
    if "QUERY_STRING" in environ:
        logger.info("Query string: %s" % environ["QUERY_STRING"])
        query = parse_qs(environ["QUERY_STRING"])

    if not query:
        start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
        return ['Unknown user']
    else:
        return _slo(environ, start_response, query, user)

def slo_post(environ, start_response, user):
    """ Expects a HTTP-POST logout request """

    query = parse_qs(get_post(environ))
    return _slo(environ, start_response, query, user)

def slo_soap(environ, start_response, user):
    soap_message = get_post(environ)
    #logger.debug("info type: %s" % type(soap_message))
    #logger.debug("SLO_SOAP: %s" % soap_message)
    req_info = IDP.parse_logout_request("%s" % soap_message, BINDING_SOAP)

    subject, sp_entity_id = _subject_sp_info(req_info)
    logger.info("Logout subject: %s" % (subject,))
    logger.info("local identifier: %s" % IDP.ident.local_name(sp_entity_id,
                                                              subject))

    response = IDP.create_logout_response(req_info.message, [BINDING_SOAP])
    args = http_soap_message(response)

    delco = delete_cookie(environ, "idpauthn")
    if delco:
        args["headers"].append(delco)

    resp = Response(args["data"], headers=args["headers"])
    return resp(environ, start_response)


def delete_cookie(environ, name):
    kaka = environ.get("HTTP_COOKIE", '')
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get(name, None)
        cookie = SimpleCookie()
        cookie[name] = ""
        cookie[name]['path'] = "/"
        logger.debug("Expire: %s" % morsel)
        cookie[name]["expires"] = _expiration("dawn")
        return tuple(cookie.output().split(": ", 1))
    return None

def set_cookie(name, path, value):
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]['path'] = "/"
    cookie[name]["expires"] = _expiration(5) # 5 minutes from now
    logger.debug("Cookie expires: %s" % cookie[name]["expires"])
    return tuple(cookie.output().split(": ", 1))

# ----------------------------------------------------------------------------

# map urls to functions
AUTHN_URLS = [
    (r'whoami$', whoami),
    (r'whoami/(.*)$', whoami),
    (r'post_sso$', sso_post),
    (r'post_sso/(.*)$', sso_post),
    (r'sso$', sso),
    (r'sso/(.*)$', sso),
    (r'logout$', slo),
    (r'logout/(.*)$', slo),
    (r'logout_post$', slo_post),
    (r'logout_post/(.*)$', slo_post),
    (r'logout_soap$', slo_soap),
    (r'logout_soap/(.*)$', slo_soap),
]

NON_AUTHN_URLS = [
    (r'login?(.*)$', do_authentication),
    (r'verify?(.*)$', do_verify),
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

    path = environ.get('PATH_INFO', '').lstrip('/')
    kaka = environ.get("HTTP_COOKIE", None)
    logger.info("<application> PATH: %s" % path)

    if kaka:
        logger.info("= KAKA =")
        user = kaka2user(kaka)
    else:
        try:
            query = parse_qs(environ["QUERY_STRING"])
            logger.debug("QUERY: %s" % query)
            user = IDP.authn[query["id"][0]]
        except KeyError:
            user = None

    if not user:
        logger.info("-- No USER --")
        for regex, callback in NON_AUTHN_URLS:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path
                logger.info("callback: %s" % (callback,))
                return callback(environ, start_response, user)
        for regex, callback in AUTHN_URLS:
            match = re.search(regex, path)
            if match is not None:
                return not_authn(environ, start_response)
    else:
        for regex, callback in AUTHN_URLS:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path
                logger.info("callback: %s" % (callback,))
                return callback(environ, start_response, user)
    return not_found(environ, start_response)

# ----------------------------------------------------------------------------
from mako.lookup import TemplateLookup
ROOT = './'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')
# ----------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    from idp_user import USERS
    from wsgiref.simple_server import make_server

    PORT = 8088

    IDP = server.Server(sys.argv[1])
    IDP.ticket = {}
    SRV = make_server('', PORT, application)
    print "IdP listening on port: %s" % PORT
    SRV.serve_forever()