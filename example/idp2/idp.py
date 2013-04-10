#!/usr/bin/env python
import base64

import re
import logging
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
from saml2.sigver import verify_redirect_signature

logger = logging.getLogger("saml2.idp")


def _expiration(timeout, tformat="%a, %d-%b-%Y %H:%M:%S GMT"):
    """

    :param timeout:
    :param tformat:
    :return:
    """
    if timeout == "now":
        return time_util.instant(tformat)
    elif timeout == "dawn":
        return time.strftime(tformat, time.gmtime(0))
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, format=tformat)

# -----------------------------------------------------------------------------


def dict2list_of_tuples(d):
    return [(k, v) for k, v in d.items()]

# -----------------------------------------------------------------------------


class Service(object):
    def __init__(self, environ, start_response, user=None):
        self.environ = environ
        logger.debug("ENVIRON: %s" % environ)
        self.start_response = start_response
        self.user = user

    def unpack_redirect(self):
        if "QUERY_STRING" in self.environ:
            _qs = self.environ["QUERY_STRING"]
            return dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
        else:
            return None
    
    def unpack_post(self):
        _dict = parse_qs(get_post(self.environ))
        logger.debug("unpack_post:: %s" % _dict)
        try:
            return dict([(k, v[0]) for k, v in _dict.items()])
        except Exception:
            return None
    
    def unpack_soap(self):
        try:
            query = get_post(self.environ)
            return {"SAMLRequest": query, "RelayState": ""}
        except Exception:
            return None
    
    def unpack_either(self):
        if self.environ["REQUEST_METHOD"] == "GET":
            _dict = self.unpack_redirect()
        elif self.environ["REQUEST_METHOD"] == "POST":
            _dict = self.unpack_post()
        else:
            _dict = None
        logger.debug("_dict: %s" % _dict)
        return _dict

    def operation(self, _dict, binding):
        logger.debug("_operation: %s" % _dict)
        if not _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)
        else:
            return self.do(_dict["SAMLRequest"], binding, _dict["RelayState"])

    def artifact_operation(self, _dict):
        if not _dict:
            resp = BadRequest("Missing query")
            return resp(self.environ, self.start_response)
        else:
            # exchange artifact for request
            request = IDP.artifact2message(_dict["SAMLart"], "spsso")
            return self.do(request, BINDING_HTTP_ARTIFACT, _dict["RelayState"])

    def response(self, binding, http_args):
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])
        return resp(self.environ, self.start_response)

    def do(self, query, binding, relay_state=""):
        pass

    def redirect(self):
        """ Expects a HTTP-redirect request """

        _dict = self.unpack_redirect()
        return self.operation(_dict, BINDING_HTTP_REDIRECT)

    def post(self):
        """ Expects a HTTP-POST request """

        _dict = self.unpack_post()
        return self.operation(_dict, BINDING_HTTP_POST)

    def artifact(self):
        # Can be either by HTTP_Redirect or HTTP_POST
        _dict = self.unpack_either()
        return self.artifact_operation(_dict)

    def soap(self):
        """
        Single log out using HTTP_SOAP binding
        """
        logger.debug("- SOAP -")
        _dict = self.unpack_soap()
        logger.debug("_dict: %s" % _dict)
        return self.operation(_dict, BINDING_SOAP)

    def uri(self):
        _dict = self.unpack_either()
        return self.operation(_dict, BINDING_SOAP)

    # def not_authn(self, key):
    #     """
    #
    #
    #     :return:
    #     """
    #     loc = "http://%s/login" % (self.environ["HTTP_HOST"])
    #     loc += "?%s" % urllib.urlencode({"came_from": self.environ[
    #         "PATH_INFO"], "key": key})
    #     headers = [('Content-Type', 'text/plain')]
    #
    #     logger.debug("location: %s" % loc)
    #     logger.debug("headers: %s" % headers)
    #
    #     resp = Redirect(loc, headers=headers)
    #
    #     return resp(self.environ, self.start_response)

    def not_authn(self, key):
        pass


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


class SSO(Service):
    def __init__(self, environ, start_response, user=None):
        Service.__init__(self, environ, start_response, user)
        self.binding = ""
        self.response_bindings = None
        self.resp_args = {}
        self.binding_out = None
        self.destination = None
        self.req_info = None

    def verify(self, query, binding):
        """
        :param query: The SAML query, transport encoded
        :param binding: Which binding the query came in over
        """
        if not query:
            logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return resp(self.environ, self.start_response)

        if not self.req_info:
            self.req_info = IDP.parse_authn_request(query, binding)

        logger.info("parsed OK")
        _authn_req = self.req_info.message
        logger.debug("%s" % _authn_req)

        self.binding_out, self.destination = IDP.pick_binding(
            "assertion_consumer_service",
            bindings=self.response_bindings,
            entity_id=_authn_req.issuer.text)

        logger.debug("Binding: %s, destination: %s" % (self.binding_out,
                                                       self.destination))

        resp_args = {}
        try:
            resp_args = IDP.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal, excp:
            _resp = IDP.create_error_response(_authn_req.id,
                                              self.destination, excp)
        except UnsupportedBinding, excp:
            _resp = IDP.create_error_response(_authn_req.id,
                                              self.destination, excp)

        return resp_args, _resp

    def do(self, query, binding_in, relay_state=""):
        try:
            resp_args, _resp = self.verify(query, binding_in)
        except UnknownPrincipal, excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding, excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)

        if not _resp:
            identity = USERS[self.user]
            logger.info("Identity: %s" % (identity,))

            if REPOZE_ID_EQUIVALENT:
                identity[REPOZE_ID_EQUIVALENT] = self.user
            try:
                _resp = IDP.create_authn_response(identity, userid=self.user,
                                                  authn=AUTHN, **resp_args)
            except Exception, excp:
                logger.error("Exception: %s" % (excp,))
                resp = ServiceError("Exception: %s" % (excp,))
                return resp(self.environ, self.start_response)

        logger.info("AuthNResponse: %s" % _resp)
        http_args = IDP.apply_binding(self.binding_out,
                                      "%s" % _resp, self.destination,
                                      relay_state, response=True)
        logger.debug("HTTPargs: %s" % http_args)
        return self.response(self.binding_out, http_args)

    def _authn(self, _dict):
        logger.debug("_auth: %s" % _dict)
        if not self.user:
            key = sha1("%s" % _dict).hexdigest()
            IDP.ticket[key] = _dict
            _resp = key
        else:
            try:
                _resp = IDP.ticket[_dict["key"]]
                del IDP.ticket[_dict["key"]]
            except KeyError:
                key = sha1("%s" % _dict).hexdigest()
                IDP.ticket[key] = _dict
                _resp = key

        return _resp

    def redirect(self):
        """ This is the HTTP-redirect endpoint """
        logger.info("--- In SSO Redirect ---")
        _info = self._authn(self.unpack_redirect())
        if isinstance(_info, basestring):
            return self.not_authn(_info)

        if "SigAlg" in _info and "Signature" in _info:  # Signed request
            self.req_info = IDP.parse_authn_request(_info["SAMLRequest"],
                                                    BINDING_HTTP_REDIRECT)
            issuer = self.req_info.message.issuer.text
            _certs = IDP.metadata.certs(issuer, "any", "signing")
            verified_ok = False
            for cert in _certs:
                if verify_redirect_signature(_info, cert):
                    verified_ok = True
                    break
            if not verified_ok:
                resp = BadRequest("Message signature verification failure")
                return resp(self.environ, self.start_response)

        return self.operation(_info, BINDING_HTTP_REDIRECT)

    def post(self):
        """
        The HTTP-Post endpoint
        """
        logger.info("--- In SSO POST ---")
        _dict = self.unpack_either()
        _resp = self._authn(_dict)
        logger.debug("_req: %s" % _resp)
        if isinstance(_resp, basestring):
            return self.not_authn(_resp)
        return self.operation(_resp, BINDING_HTTP_POST)

    def artifact(self):
        # Can be either by HTTP_Redirect or HTTP_POST
        _req = self._authn(self.unpack_either())
        if isinstance(_req, basestring):
            return self.not_authn(_req)
        return self.artifact_operation(_req)

    def ecp(self):
        # The ECP interface
        logger.info("--- ECP SSO ---")
        resp = None

        try:
            authz_info = self.environ["HTTP_AUTHORIZATION"]
            if authz_info.startswith("Basic "):
                _info = base64.b64decode(authz_info[6:])
                logger.debug("Authz_info: %s" % _info)
                try:
                    (user, passwd) = _info.split(":")
                    if PASSWD[user] != passwd:
                        resp = Unauthorized()
                    self.user = user
                except ValueError:
                    resp = Unauthorized()
            else:
                resp = Unauthorized()
        except KeyError:
            resp = Unauthorized()

        if resp:
            return resp(self.environ, self.start_response)

        _dict = self.unpack_soap()
        self.response_bindings = [BINDING_PAOS]
        # Basic auth ?!
        return self.operation(_dict, BINDING_SOAP)

# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------

PASSWD = {"roland": "dianakra",
          "babs": "howes",
          "upper": "crust"}


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


def do_verify(environ, start_response, _):
    query = parse_qs(get_post(environ))

    logger.debug("do_verify: %s" % query)

    try:
        _ok, user = verify_username_and_password(query)
    except KeyError:
        _ok = False
        user = None

    if not _ok:
        resp = Unauthorized("Unknown user or wrong password")
    else:
        uid = rndstr(24)
        IDP.uid2user[uid] = user
        IDP.user2uid[user] = uid
        logger.debug("Register %s under '%s'" % (user, uid))
        kaka = set_cookie("idpauthn", "/", uid)
        lox = "http://%s%s?id=%s&key=%s" % (environ["HTTP_HOST"],
                                            query["came_from"][0], uid,
                                            query["key"][0])
        logger.debug("Redirect => %s" % lox)
        resp = Redirect(lox, headers=[kaka], content="text/html")

    return resp(environ, start_response)


def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound()
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

class SLO(Service):
    def do(self, request, binding, relay_state=""):
        logger.info("--- Single Log Out Service ---")
        try:
            _, body = request.split("\n")
            logger.debug("req: '%s'" % body)
            req_info = IDP.parse_logout_request(body, binding)
        except Exception, exc:
            logger.error("Bad request: %s" % exc)
            resp = BadRequest("%s" % exc)
            return resp(self.environ, self.start_response)
    
        msg = req_info.message
        if msg.name_id:
            lid = IDP.ident.find_local_id(msg.name_id)
            logger.info("local identifier: %s" % lid)
            del IDP.uid2user[IDP.user2uid[lid]]
            del IDP.user2uid[lid]
            # remove the authentication
            try:
                IDP.session_db.remove_authn_statements(msg.name_id)
            except KeyError, exc:
                logger.error("ServiceError: %s" % exc)
                resp = ServiceError("%s" % exc)
                return resp(self.environ, self.start_response)
    
        resp = IDP.create_logout_response(msg, [binding])
    
        try:
            hinfo = IDP.apply_binding(binding, "%s" % resp, "", relay_state)
        except Exception, exc:
            logger.error("ServiceError: %s" % exc)
            resp = ServiceError("%s" % exc)
            return resp(self.environ, self.start_response)
    
        #_tlh = dict2list_of_tuples(hinfo["headers"])
        delco = delete_cookie(self.environ, "idpauthn")
        if delco:
            hinfo["headers"].append(delco)
        logger.info("Header: %s" % (hinfo["headers"],))
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)
    
# ----------------------------------------------------------------------------
# Manage Name ID service
# ----------------------------------------------------------------------------


class NMI(Service):
    
    def do(self, query, binding, relay_state=""):
        logger.info("--- Manage Name ID Service ---")
        req = IDP.parse_manage_name_id_request(query, binding)
        request = req.message
    
        # Do the necessary stuff
        name_id = IDP.ident.handle_manage_name_id_request(
            request.name_id, request.new_id, request.new_encrypted_id,
            request.terminate)
    
        logger.debug("New NameID: %s" % name_id)
    
        _resp = IDP.create_manage_name_id_response(request)
    
        # It's using SOAP binding
        hinfo = IDP.apply_binding(BINDING_SOAP, "%s" % _resp, "",
                                  relay_state, response=True)
    
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)
    
# ----------------------------------------------------------------------------
# === Assertion ID request ===
# ----------------------------------------------------------------------------


# Only URI binding
class AIDR(Service):
    def do(self, aid, binding, relay_state=""):
        logger.info("--- Assertion ID Service ---")

        try:
            assertion = IDP.create_assertion_id_request_response(aid)
        except Unknown:
            resp = NotFound(aid)
            return resp(self.environ, self.start_response)
    
        hinfo = IDP.apply_binding(BINDING_URI, "%s" % assertion, response=True)
    
        logger.debug("HINFO: %s" % hinfo)
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

    def operation(self, _dict, binding, **kwargs):
        logger.debug("_operation: %s" % _dict)
        if not _dict or "ID" not in _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)

        return self.do(_dict["ID"], binding, **kwargs)


# ----------------------------------------------------------------------------
# === Artifact resolve service ===
# ----------------------------------------------------------------------------

class ARS(Service):
    def do(self, request, binding, relay_state=""):
        _req = IDP.parse_artifact_resolve(request, binding)

        msg = IDP.create_artifact_response(_req, _req.artifact.text)

        hinfo = IDP.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# === Authn query service ===
# ----------------------------------------------------------------------------


# Only SOAP binding
class AQS(Service):
    def do(self, request, binding, relay_state=""):
        logger.info("--- Authn Query Service ---")
        _req = IDP.parse_authn_query(request, binding)
        _query = _req.message

        msg = IDP.create_authn_query_response(_query.subject,
                                              _query.requested_authn_context,
                                              _query.session_index)

        logger.debug("response: %s" % msg)
        hinfo = IDP.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)


# ----------------------------------------------------------------------------
# === Attribute query service ===
# ----------------------------------------------------------------------------


# Only SOAP binding
class ATTR(Service):
    def do(self, request, binding, relay_state=""):
        logger.info("--- Attribute Query Service ---")

        _req = IDP.parse_attribute_query(request, binding)
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
        hinfo = IDP.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# Name ID Mapping service
# When an entity that shares an identifier for a principal with an identity
# provider wishes to obtain a name identifier for the same principal in a
# particular format or federation namespace, it can send a request to
# the identity provider using this protocol.
# ----------------------------------------------------------------------------


class NIM(Service):
    def do(self, query, binding, relay_state=""):
        req = IDP.parse_name_id_mapping_request(query, binding)
        request = req.message
        # Do the necessary stuff
        try:
            name_id = IDP.ident.handle_name_id_mapping_request(
                request.name_id, request.name_id_policy)
        except Unknown:
            resp = BadRequest("Unknown entity")
            return resp(self.environ, self.start_response)
        except PolicyError:
            resp = BadRequest("Unknown entity")
            return resp(self.environ, self.start_response)
    
        info = IDP.response_args(request)
        _resp = IDP.create_name_id_mapping_response(name_id, **info)
    
        # Only SOAP
        hinfo = IDP.apply_binding(BINDING_SOAP, "%s" % _resp, "", "",
                                  response=True)
    
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)
    

# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def kaka2user(kaka):
    logger.debug("KAKA: %s" % kaka)
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get("idpauthn", None)
        if morsel:
            try:
                return IDP.uid2user[morsel.value]
            except KeyError:
                return None
        else:
            logger.debug("No idpauthn cookie")
    return None


def delete_cookie(environ, name):
    kaka = environ.get("HTTP_COOKIE", '')
    logger.debug("delete KAKA: %s" % kaka)
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


def set_cookie(name, _, value):
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]['path'] = "/"
    cookie[name]["expires"] = _expiration(5)  # 5 minutes from now
    logger.debug("Cookie expires: %s" % cookie[name]["expires"])
    return tuple(cookie.output().split(": ", 1))

# ----------------------------------------------------------------------------

# map urls to functions
AUTHN_URLS = [
    # sso
    (r'sso/post$', (SSO, "post")),
    (r'sso/post/(.*)$', (SSO, "post")),
    (r'sso/redirect$', (SSO, "redirect")),
    (r'sso/redirect/(.*)$', (SSO, "redirect")),
    (r'sso/art$', (SSO, "artifact")),
    (r'sso/art/(.*)$', (SSO, "artifact")),
    # slo
    (r'slo/redirect$', (SLO, "redirect")),
    (r'slo/redirect/(.*)$', (SLO, "redirect")),
    (r'slo/post$', (SLO, "post")),
    (r'slo/post/(.*)$', (SLO, "post")),
    (r'slo/soap$', (SLO, "soap")),
    (r'slo/soap/(.*)$', (SLO, "soap")),
    #
    (r'airs$', (AIDR, "uri")),
    (r'ars$', (ARS, "soap")),
    # mni
    (r'mni/post$', (NMI, "post")),
    (r'mni/post/(.*)$', (NMI, "post")),
    (r'mni/redirect$', (NMI, "redirect")),
    (r'mni/redirect/(.*)$', (NMI, "redirect")),
    (r'mni/art$', (NMI, "artifact")),
    (r'mni/art/(.*)$', (NMI, "artifact")),
    (r'mni/soap$', (NMI, "soap")),
    (r'mni/soap/(.*)$', (NMI, "soap")),
    # nim
    (r'nim$', (NIM, "soap")),
    (r'nim/(.*)$', (NIM, "soap")),
    #
    (r'aqs$', (AQS, "soap")),
    (r'attr$', (ATTR, "soap"))
]

NON_AUTHN_URLS = [
    (r'login?(.*)$', do_authentication),
    (r'verify?(.*)$', do_verify),
    (r'sso/ecp$', (SSO, "ecp")),
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
            user = IDP.uid2user[query["id"][0]]
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

                logger.debug("Callback: %s" % (callback,))
                if isinstance(callback, tuple):
                    cls = callback[0](environ, start_response, user)
                    func = getattr(cls, callback[1])
                    return func()
                else:
                    return callback(environ, start_response, user)
        for regex, callback in AUTHN_URLS:
            match = re.search(regex, path)
            if match is not None:
                cls = callback[0](environ, start_response, user)
                func = getattr(cls, callback[1])
                return func()
    else:
        for regex, callback in AUTHN_URLS:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path
                cls = callback[0](environ, start_response, user)
                func = getattr(cls, callback[1])
                return func()
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