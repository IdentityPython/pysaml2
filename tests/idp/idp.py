#!/usr/bin/env python
import base64

import re
import logging
import urllib
import time
from hashlib import sha1

from urlparse import parse_qs
from Cookie import SimpleCookie

from saml2 import server
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_URI
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import time_util
from saml2.httputil import Response, NotFound
from saml2.httputil import get_post
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.httputil import BadRequest
from saml2.httputil import ServiceError
from saml2.ident import Unknown
from saml2.s_utils import rndstr, UnknownPrincipal, UnsupportedBinding
from saml2.s_utils import PolicyError
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

def unpack_redirect(environ):
    if "QUERY_STRING" in environ:
        _qs = environ["QUERY_STRING"]
        return dict([(k,v[0]) for k,v in parse_qs(_qs).items()])
    else:
        return None

def unpack_post(environ):
    try:
        return dict([(k,v[0]) for k,v in parse_qs(get_post(environ))])
    except Exception:
        return None

def unpack_soap(environ):
    try:
        query = get_post(environ)
        return {"SAMLRequest": query, "RelayState": ""}
    except Exception:
        return None

def unpack_artifact(environ):
    if environ["REQUEST_METHOD"] == "GET":
        _dict = unpack_redirect(environ)
    elif environ["REQUEST_METHOD"] == "POST":
        _dict = unpack_post(environ)
    else:
        _dict = None
    return _dict

def dict2list_of_tuples(d):
    return [(k,v) for k,v in d.items()]

# -----------------------------------------------------------------------------

def _operation(environ, start_response, user, _dict, func, binding,
               **kwargs):
    logger.debug("_operation: %s" % _dict)
    if not _dict:
        resp = BadRequest('Error parsing request or no request')
        return resp(environ, start_response)
    else:
        return func(environ, start_response, user, _dict["SAMLRequest"],
                    binding, _dict["RelayState"], **kwargs)

def _artifact_oper(environ, start_response, user, _dict, func):
    if not _dict:
        resp = BadRequest("Missing query")
        return resp(environ, start_response)
    else:
        # exchange artifact for request
        request = IDP.artifact2message(_dict["SAMLart"], "spsso")

        return func(environ, start_response, user, request,
                    BINDING_HTTP_ARTIFACT, _dict["RelayState"])

def _response(environ, start_response, binding, http_args):
    if binding == BINDING_HTTP_ARTIFACT:
        resp = Redirect()
    else:
        resp = Response(http_args["data"], headers=http_args["headers"])
    return resp(environ, start_response)

# -----------------------------------------------------------------------------
AUTHN = (AUTHN_PASSWORD, "http://lingon.catalogix.se/login")

REPOZE_ID_EQUIVALENT = "uid"
FORM_SPEC = """<form name="myform" method="post" action="%s">
   <input type="hidden" name="SAMLResponse" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
</form>"""

# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------

def _sso(environ, start_response, user, query, binding, relay_state="",
         response_bindings=None):
    logger.info("--- In SSO ---")
    logger.debug("user: %s" % user)

    if not query:
        logger.info("Missing QUERY")
        resp = Unauthorized('Unknown user')
        return resp(environ, start_response)

    # base 64 encoded request
    req_info = IDP.parse_authn_request(query, binding=binding)
    logger.info("parsed OK")
    logger.info("%s" % req_info)
    _authn_req = req_info.message

    try:
        resp_args = IDP.response_args(_authn_req)
    except UnknownPrincipal, excp:
        #IDP.create_error_response()
        resp = ServiceError("UnknownPrincipal: %s" % (excp,))
        return resp(environ, start_response)
    except UnsupportedBinding, excp:
        #IDP.create_error_response()
        resp = ServiceError("UnsupportedBinding: %s" % (excp,))
        return resp(environ, start_response)

    identity = USERS[user]
    logger.info("Identity: %s" % (identity,))

    if REPOZE_ID_EQUIVALENT:
        identity[REPOZE_ID_EQUIVALENT] = user
    try:
        authn_resp = IDP.create_authn_response(identity, userid=user,
                                               authn=AUTHN, **resp_args)
    except Exception, excp:
        logger.error("Exception: %s" % (excp,))
        resp = ServiceError("Exception: %s" % (excp,))
        return resp(environ, start_response)

    logger.info("AuthNResponse: %s" % authn_resp)
    binding, destination = IDP.pick_binding("assertion_consumer_service",
                                            bindings=response_bindings,
                                            entity_id=_authn_req.issuer.text)
    logger.debug("Binding: %s, destination: %s" % (binding, destination))
    http_args = IDP.apply_binding(binding, "%s" % authn_resp, destination,
                                  relay_state, response=True)

    return _response(environ, start_response, binding, http_args)

def sso(environ, start_response, user):
    """ This is the HTTP-redirect endpoint """

    _dict = unpack_redirect(environ)
    logger.debug("_dict: %s" % _dict)
    # pick up the stored original query
    logger.debug("keys: %s" % IDP.ticket.keys())
    _req = IDP.ticket[_dict["key"]]
    del IDP.ticket[_dict["key"]]

    return _operation(environ, start_response, user, _req, _sso,
                      BINDING_HTTP_REDIRECT)

def sso_post(environ, start_response, user):
    """
    The HTTP-Post endpoint
    """
    logger.info("--- In SSO POST ---")
    logger.debug("user: %s" % user)

    _dict = unpack_post(environ)

    logger.debug("message: %s" % _dict)
    logger.debug("keys: %s" % IDP.ticket.keys())
    _request = IDP.ticket[_dict["key"]]
    del IDP.ticket[_dict["key"]]

    return _operation(environ, start_response, user, _request, _sso,
                      BINDING_HTTP_POST)

def sso_art(environ, start_response, user):
    # Can be either by HTTP_Redirect or HTTP_POST
    _dict = unpack_artifact(environ)
    _request = IDP.ticket[_dict["key"]]
    del IDP.ticket[_dict["key"]]
    return _artifact_oper(environ, start_response, user, _request, _sso)

def sso_ecp(environ, start_response, user):
    # The ECP interface
    logger.info("--- ECP SSO ---")
    logger.debug("ENVIRON: %s" % environ)
    resp = None

    try:
        authz_info = environ["HTTP_AUTHORIZATION"]
        if authz_info.startswith("Basic "):
            _info = base64.b64decode(authz_info[6:])
            logger.debug("Authz_info: %s" % _info)
            try:
                (user,passwd) = _info.split(":")
                if PASSWD[user] != passwd:
                    resp = Unauthorized()
            except ValueError:
                resp = Unauthorized()
        else:
            resp = Unauthorized()
    except KeyError:
        resp = Unauthorized()

    if resp:
        return resp(environ, start_response)

    _dict = unpack_soap(environ)
    # Basic auth ?!
    return _operation(environ, start_response, user, _dict, _sso, BINDING_SOAP,
                      response_bindings=[BINDING_PAOS])

# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------

def not_authn(environ, start_response):
    # store the request and redirect to login page
    logger.info("not_authn ENV: %s" % environ)

    loc = "http://%s/login" % (environ["HTTP_HOST"])

    if environ["REQUEST_METHOD"] == "GET":
        _dict = unpack_redirect(environ)
    elif environ["REQUEST_METHOD"] == "POST":
        _dict = unpack_post(environ)
    else:
        _dict = None

    if not _dict:
        resp = BadRequest("Missing query")
    else:
        logger.info("query: %s" % _dict)
        # store the original request
        key = sha1("%s" % _dict).hexdigest()
        IDP.ticket[str(key)] = _dict

        loc += "?%s" % urllib.urlencode({"came_from": environ["PATH_INFO"],
                                         "key": key})
        headers = [('Content-Type', 'text/plain')]

        logger.debug("location: %s" % loc)
        logger.debug("headers: %s" % headers)

        resp = Redirect(loc, headers=headers)

    return resp(environ, start_response)

def do_authentication(environ, start_response, cookie=None):
    """
    Display the login form
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

def verify_username_and_password(dic):
    global PASSWD
    # verify username and password
    if PASSWD[dic["login"][0]] == dic["password"][0]:
        return True, dic["login"][0]
    else:
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

# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------

#def _subject_sp_info(req_info):
#    # look for the subject
#    subject = req_info.subject_id()
#    subject = subject.text.strip()
#    sp_entity_id = req_info.message.issuer.text.strip()
#    return subject, sp_entity_id

def _slo(environ, start_response, _, request, binding, relay_state=""):
    logger.info("--- Single Log Out Service ---")
    try:
        req_info = IDP.parse_logout_request(request, binding)
    except Exception, exc:
        logger.error("Bad request: %s" % exc)
        resp = BadRequest("%s" % exc)
        return resp(environ, start_response)

    msg = req_info.message
    if msg.name_id:
        lid = IDP.ident.find_local_id(msg.name_id)
        logger.info("local identifier: %s" % lid)
        # remove the authentication
        try:
            IDP.remove_authn_statements(msg.name_id)
        except KeyError,exc:
            logger.error("ServiceError: %s" % exc)
            resp = ServiceError("%s" % exc)
            return resp(environ, start_response)

    resp = IDP.create_logout_response(msg)

    try:
        hinfo = IDP.apply_binding(binding, "%s" % resp, "", relay_state)
    except Exception, exc:
        logger.error("ServiceError: %s" % exc)
        resp = ServiceError("%s" % exc)
        return resp(environ, start_response)

    logger.info("Header: %s" % (hinfo["headers"],))
    #_tlh = dict2list_of_tuples(hinfo["headers"])
    delco = delete_cookie(environ, "idpauthn")
    if delco:
        hinfo["headers"].append(delco)
    resp = Response(hinfo["data"], headers=hinfo["headers"])
    return resp(environ, start_response)

# -- bindings --

def slo(environ, start_response, user):
    """ Expects a HTTP-redirect logout request """

    _dict = unpack_redirect(environ)
    return _operation(environ, start_response, user, _dict, _slo,
                      BINDING_HTTP_REDIRECT)

def slo_post(environ, start_response, user):
    """ Expects a HTTP-POST logout request """

    _dict = unpack_post(environ)
    return _operation(environ, start_response, user, _dict, _slo,
                      BINDING_HTTP_POST)

def slo_art(environ, start_response, user):
    # Can be either by HTTP_Redirect or HTTP_POST
    _dict = unpack_artifact(environ)
    return _artifact_oper(environ, start_response, user, _dict, _slo)

def slo_soap(environ, start_response, user=None):
    """
    Single log out using HTTP_SOAP binding
    """
    _dict = unpack_soap(environ)
    return _operation(environ, start_response, user, _dict, _slo,
                      BINDING_SOAP)

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------

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


PASSWD = {"roland": "dianakra",
          "babs": "howes",
          "upper": "crust"}

# ----------------------------------------------------------------------------

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

# ----------------------------------------------------------------------------
# Manage Name ID service
# ----------------------------------------------------------------------------

def _mni(environ, start_response, user, query, binding, relay_state=""):
    logger.info("--- Manage Name ID Service ---")
    req = IDP.parse_manage_name_id_request(query, binding)
    request = req.message

    # Do the necessary stuff
    name_id = IDP.ident.handle_manage_name_id_request(request.name_id,
                                                      request.new_id,
                                                      request.new_encrypted_id,
                                                      request.terminate)

    logger.debug("New NameID: %s" % name_id)

    _resp = IDP.create_manage_name_id_response(request)

    # It's using SOAP binding
    hinfo = IDP.apply_binding(binding, "%s" % _resp, "", relay_state,
                              response=True)

    resp = Response(hinfo["data"], headers=hinfo["headers"])
    return resp(environ, start_response)

def mni(environ, start_response, user):
    """ Expects a HTTP-redirect logout request """

    _dict = unpack_redirect(environ)
    return _operation(environ, start_response, user, _dict, _mni,
                      BINDING_HTTP_REDIRECT)

def mni_post(environ, start_response, user):
    """ Expects a HTTP-POST logout request """

    _dict = unpack_post(environ)
    return _operation(environ, start_response, user, _dict, _mni,
                      BINDING_HTTP_POST)

def mni_soap(environ, start_response, user):
    _dict = unpack_soap(environ)
    return _operation(environ, start_response, user, _dict, _mni,
                      BINDING_SOAP)

def mni_art(environ, start_response, user):
    # Could be by HTTP_REDIRECT or HTTP_POST
    _dict = unpack_post(environ)
    return _artifact_oper(environ, start_response, user, _dict, _mni)

# ----------------------------------------------------------------------------
# === Assertion ID request ===
# ----------------------------------------------------------------------------

# Only URI binding
def assertion_id_request(environ, start_response, user=None):
    logger.info("--- Assertion ID Service ---")
    _binding = BINDING_URI

    _dict = unpack_artifact(environ)
    logger.debug("INPUT: %s" % _dict)
    # Presently only HTTP GET is supported
    if "ID" in _dict:
        aid = _dict["ID"]
    else:
        resp = BadRequest("Missing or faulty request")
        return resp(environ, start_response)

    try:
        assertion = IDP.create_assertion_id_request_response(aid)
    except Unknown:
        resp = NotFound(aid)
        return resp(environ, start_response)

    hinfo = IDP.apply_binding(_binding, "%s" % assertion, response=True)

    logger.debug("HINFO: %s" % hinfo)
    resp = Response(hinfo["data"], headers=hinfo["headers"])
    return resp(environ, start_response)

# ----------------------------------------------------------------------------
# === Artifact resolve service ===
# ----------------------------------------------------------------------------

# Only SOAP binding
def artifact_resolve_service(environ, start_response, user=None):
    """
    :param environ: Execution environment
    :param start_response: Function to start the response with
    """
    logger.info("--- Artifact resolve Service ---")
    _dict = unpack_soap(environ)
    _binding = BINDING_SOAP

    if not _dict:
        resp = BadRequest("Missing or faulty request")
        return resp(environ, start_response)

    _req = IDP.parse_artifact_resolve("%s" % _dict["SAMLRequest"], _binding)

    msg = IDP.create_artifact_response(_req, _req.artifact.text)

    hinfo = IDP.apply_binding(_binding, "%s" % msg, "","",response=True)

    resp = Response(hinfo["data"], headers=hinfo["headers"])
    return resp(environ, start_response)

# ----------------------------------------------------------------------------
# === Authn query service ===
# ----------------------------------------------------------------------------

# Only SOAP binding
def authn_query_service(environ, start_response, user=None):
    """
    :param environ: Execution environment
    :param start_response: Function to start the response with
    """
    logger.info("--- Authn Query Service ---")
    _dict = unpack_soap(environ)
    _binding = BINDING_SOAP

    if not _dict:
        resp = BadRequest("Missing or faulty request")
        return resp(environ, start_response)

    _req = IDP.parse_authn_query("%s" % _dict["SAMLRequest"], _binding)
    _query = _req.message

    msg = IDP.create_authn_query_response(_query.subject,
                                          _query.requested_authn_context,
                                          _query.session_index)

    logger.debug("response: %s" % msg)
    hinfo = IDP.apply_binding(_binding, "%s" % msg, "","",response=True)

    resp = Response(hinfo["data"], headers=hinfo["headers"])
    return resp(environ, start_response)


# ----------------------------------------------------------------------------
# === Attribute query service ===
# ----------------------------------------------------------------------------

# Only SOAP binding
def attribute_query_service(environ, start_response, user=None):
    """
    :param environ: Execution environment
    :param start_response: Function to start the response with
    """
    logger.info("--- Attribute Query Service ---")
    _dict = unpack_soap(environ)
    _binding = BINDING_SOAP

    if not _dict:
        resp = BadRequest("Missing or faulty request")
        return resp(environ, start_response)

    _req = IDP.parse_attribute_query("%s" % _dict["SAMLRequest"], _binding)
    _query = _req.message

    name_id = _query.subject.name_id
    uid = IDP.ident.find_local_id(name_id)
    logger.debug("Local uid: %s" % uid)
    identity = EXTRA[uid]

    # Comes in over SOAP so only need to construct the response
    args = IDP.response_args(_query, [BINDING_SOAP])
    msg = IDP.create_attribute_response(identity, destination="",
                                        name_id=name_id, **args)

    logger.debug("response: %s" % msg)
    hinfo = IDP.apply_binding(_binding, "%s" % msg, "","",response=True)

    resp = Response(hinfo["data"], headers=hinfo["headers"])
    return resp(environ, start_response)



# ----------------------------------------------------------------------------
# Name ID Mapping service
# When an entity that shares an identifier for a principal with an identity
# provider wishes to obtain a name identifier for the same principal in a
# particular format or federation namespace, it can send a request to
# the identity provider using this protocol.
# ----------------------------------------------------------------------------


def _nim(environ, start_response, user, query, binding, relay_state=""):
    req = IDP.parse_name_id_mapping_request(query, binding)
    request = req.message
    # Do the necessary stuff
    try:
        name_id = IDP.ident.handle_name_id_mapping_request(request.name_id,
                                                           request.name_id_policy)
    except Unknown:
        resp = BadRequest("Unknown entity")
        return resp(environ, start_response)
    except PolicyError:
        resp = BadRequest("Unknown entity")
        return resp(environ, start_response)

    info = IDP.response_args(request)
    _resp = IDP.create_name_id_mapping_response(name_id, **info)

    # Only SOAP
    hinfo = IDP.apply_binding(binding, "%s" % _resp, "", "", response=True)

    resp = Response(hinfo["data"], headers=hinfo["headers"])
    return resp(environ, start_response)

def nim_soap(environ, start_response, user):
    _dict = unpack_soap(environ)
    return _operation(environ, start_response, user, _dict, _nim, BINDING_SOAP)


# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------

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
    # sso
    (r'sso/post$', sso_post),
    (r'sso/post/(.*)$', sso_post),
    (r'sso/redirect$', sso),
    (r'sso/redirect/(.*)$', sso),
    (r'sso/art$', sso),
    (r'sso/art/(.*)$', sso),
    # slo
    (r'slo/redirect$', slo),
    (r'slo/redirect/(.*)$', slo),
    (r'slo/post$', slo_post),
    (r'slo/post/(.*)$', slo_post),
    (r'slo/soap$', slo_soap),
    (r'slo/soap/(.*)$', slo_soap),
    #
    (r'airs$', assertion_id_request),
    (r'ars$', artifact_resolve_service),
    # mni
    (r'mni/post$', mni_post),
    (r'mni/post/(.*)$', mni_post),
    (r'mni/redirect$', mni),
    (r'mni/redirect/(.*)$', mni),
    (r'mni/art$', mni_art),
    (r'mni/art/(.*)$', mni_art),
    (r'mni/soap$', mni_soap),
    (r'mni/soap/(.*)$', mni_soap),
    # nim
    (r'nim$', nim_soap),
    (r'nim/(.*)$', nim_soap),
    #
    (r'aqs$', authn_query_service),
    (r'attr$', attribute_query_service)
]

NON_AUTHN_URLS = [
    (r'login?(.*)$', do_authentication),
    (r'verify?(.*)$', do_verify),
    (r'sso/ecp$', sso_ecp),
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
    from idp_user import EXTRA
    from wsgiref.simple_server import make_server

    PORT = 8088

    IDP = server.Server(sys.argv[1])
    IDP.ticket = {}
    SRV = make_server('', PORT, application)
    print "IdP listening on port: %s" % PORT
    SRV.serve_forever()