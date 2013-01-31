# Copyright (C) 2009 Umea University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" 
A plugin that allows you to use SAML2 SSO as authentication 
and SAML2 attribute aggregations as metadata collector in your
WSGI application.

"""
import cgi
import logging
import sys
import platform
import shelve
import traceback
from urlparse import parse_qs

from paste.httpexceptions import HTTPSeeOther
from paste.httpexceptions import HTTPNotImplemented
from paste.httpexceptions import HTTPInternalServerError
from paste.request import parse_dict_querystring
from paste.request import construct_url
from saml2.client_base import ECP_SERVICE
from zope.interface import implements

from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from repoze.who.interfaces import IMetadataProvider
from repoze.who.plugins.form import FormPluginBase

from saml2 import ecp, BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST

from saml2.client import Saml2Client
from saml2.s_utils import sid
from saml2.config import config_factory
from saml2.profile import paos

#from saml2.population import Population
#from saml2.attribute_resolver import AttributeResolver

logger = logging.getLogger(__name__)

PAOS_HEADER_INFO = 'ver="%s";"%s"' % (paos.NAMESPACE, ECP_SERVICE)

def construct_came_from(environ):
    """ The URL that the user used when the process where interupted 
    for single-sign-on processing. """
    
    came_from = environ.get("PATH_INFO") 
    qstr = environ.get("QUERY_STRING","")
    if qstr:
        came_from += '?' + qstr
    return came_from
    
# FormPluginBase defines the methods remember and forget
def cgi_field_storage_to_dict(field_storage):
    """Get a plain dictionary, rather than the '.value' system used by the
    cgi module."""
    
    params = {}
    for key in field_storage.keys():
        try:
            params[ key ] = field_storage[ key ].value
        except AttributeError:
            if isinstance(field_storage[ key ], basestring):
                params[key] = field_storage[key]
                
    return params

def get_body(environ):
    body = ""

    length = int(environ["CONTENT_LENGTH"])
    try:
        body = environ["wsgi.input"].read(length)
    except Exception, excp:
        logger.exception("Exception while reading post: %s" % (excp,))
        raise

    # restore what I might have upset
    from StringIO import StringIO
    environ['wsgi.input'] = StringIO(body)
    environ['s2repoze.body'] = body

    return body

def exception_trace(tag, exc, log):
    message = traceback.format_exception(*sys.exc_info())
    log.error("[%s] ExcList: %s" % (tag, "".join(message),))
    log.error("[%s] Exception: %s" % (tag, exc))

class ECP_response(object):
    code = 200
    title = 'OK'

    def __init__(self, content):
        self.content = content

    #noinspection PyUnusedLocal
    def __call__(self, environ, start_response):
        start_response('%s %s' % (self.code, self.title),
                       [('Content-Type', "text/xml")])
        return [self.content]



class SAML2Plugin(FormPluginBase):

    implements(IChallenger, IIdentifier, IAuthenticator, IMetadataProvider)
    
    def __init__(self, rememberer_name, config, saml_client, 
                    wayf, cache, debug, sid_store=None, discovery=""):
        FormPluginBase.__init__(self)
        
        self.rememberer_name = rememberer_name
        self.debug = debug        
        self.wayf = wayf
        self.saml_client = saml_client
        self.conf = config
        self.cache = cache
        self.discosrv = discovery

        try:
            self.metadata = self.conf.metadata
        except KeyError:
            self.metadata = None
        if sid_store:
            self.outstanding_queries = shelve.open(sid_store, writeback=True)
        else:
            self.outstanding_queries = {}
        self.iam = platform.node()

    def _get_post(self, environ):
        """
        Get the posted information
    
        :param environ: A dictionary with environment variables
        """
    
        post = {}
    
        post_env = environ.copy()
        post_env['QUERY_STRING'] = ''
    
        _ = get_body(environ)
        
        try:
            post = cgi.FieldStorage(
                fp=environ['wsgi.input'],
                environ=post_env,
                keep_blank_values=True
            )
        except Exception, excp:
            logger.debug("Exception (II): %s" % (excp,))
            raise
    
        logger.debug('identify post: %s' % (post,))
    
        return post

    def _wayf_redirect(self, came_from):
        sid_ = sid()
        self.outstanding_queries[sid_] = came_from
        logger.info("Redirect to WAYF function: %s" % self.wayf)
        return -1, HTTPSeeOther(headers = [('Location',
                                    "%s?%s" % (self.wayf, sid_))])

    #noinspection PyUnusedLocal
    def _pick_idp(self, environ, came_from):
        """ 
        If more than one idp and if none is selected, I have to do wayf or 
        disco
        """

        # check headers to see if it's an ECP request
#        headers = {
#                    'Accept' : 'text/html; application/vnd.paos+xml',
#                    'PAOS'   : 'ver="%s";"%s"' % (paos.NAMESPACE, SERVICE)
#                    }

        logger.info("[_pick_idp] %s" % environ)
        if "HTTP_PAOS" in environ:
            if environ["HTTP_PAOS"] == PAOS_HEADER_INFO:
                if 'application/vnd.paos+xml' in environ["HTTP_ACCEPT"]:
                    # Where should I redirect the user to
                    # entityid -> the IdP to use
                    # relay_state -> when back from authentication

                    logger.info("- ECP client detected -")

                    _relay_state = construct_came_from(environ)
                    _entityid = self.saml_client.config.ecp_endpoint(
                                                    environ["REMOTE_ADDR"])
                    if not _entityid:
                        return -1, HTTPInternalServerError(
                                        detail="No IdP to talk to"
                        )
                    logger.info("IdP to talk to: %s" % _entityid)
                    return ecp.ecp_auth_request(self.saml_client, _entityid,
                                                _relay_state)
                else:
                    return -1, HTTPInternalServerError(
                                    detail='Faulty Accept header')
            else:
                return -1, HTTPInternalServerError(
                                                detail='unknown ECP version')


        idps = self.metadata.with_descriptor("idpsso")
        
        logger.info("IdP URL: %s" % idps)

        if len( idps ) == 1:
            # idps is a dictionary
            idp_entity_id = idps.keys()[0]
        elif not len(idps):
            return -1, HTTPInternalServerError(detail='Misconfiguration')
        else:
            idp_entity_id = ""
            logger.info("ENVIRON: %s" % environ)
            query = environ.get('s2repoze.body','')
            if not query:
                query = environ.get("QUERY_STRING","")
                
            logger.info("<_pick_idp> query: %s" % query)

            if self.wayf:
                if query:
                    try:
                        wayf_selected = dict(parse_qs(query))["wayf_selected"][0]
                    except KeyError:
                        return self._wayf_redirect(came_from)
                    idp_entity_id = wayf_selected
                else:
                    return self._wayf_redirect(came_from)
            elif self.discosrv:
                if query:
                    idp_entity_id = self.saml_client.parse_discovery_service_response(
                                            query=environ.get("QUERY_STRING"))
                else:
                    sid_ = sid()
                    self.outstanding_queries[sid_] = came_from
                    logger.info("Redirect to Discovery Service function")
                    eid = self.saml_client.config.entity_id
                    loc = self.saml_client.create_discovery_service_request(
                                                            self.discosrv, eid)
                    return -1, HTTPSeeOther(headers = [('Location',loc)])
            else:
                return -1, HTTPNotImplemented(detail='No WAYF or DJ present!')

        logger.info("Chosen IdP: '%s'" % idp_entity_id)
        return 0, idp_entity_id
        
    #### IChallenger ####
    #noinspection PyUnusedLocal
    def challenge(self, environ, _status, _app_headers, _forget_headers):

        # this challenge consist in login out
        if environ.has_key('rwpc.logout'): 
            # ignore right now?
            pass

        #logger = environ.get('repoze.who.logger','')

        # Which page was accessed to get here
        came_from = construct_came_from(environ)
        environ["myapp.came_from"] = came_from
        logger.debug("[sp.challenge] RelayState >> '%s'" % came_from)
        
        # Am I part of a virtual organization or more than one ?
        try:
            vorg_name = environ["myapp.vo"]
        except KeyError:
            try:
                vorg_name = self.saml_client.vorg._name
            except AttributeError:
                vorg_name = ""
            
        logger.info("[sp.challenge] VO: %s" % vorg_name)

        # If more than one idp and if none is selected, I have to do wayf
        (done, response) = self._pick_idp(environ, came_from)
        # Three cases: -1 something went wrong or Discovery service used
        #               0 I've got an IdP to send a request to
        #               >0 ECP in progress
        logger.debug("_idp_pick returned: %s" % done)
        if done == -1:
            return response
        elif done > 0:
            self.outstanding_queries[done] = came_from
            return ECP_response(response)
        else:
            entity_id = response
            logger.info("[sp.challenge] entity_id: %s" % entity_id)
            # Do the AuthnRequest
            _cli = self.saml_client
            _binding = BINDING_HTTP_REDIRECT
            try:
                srvs = _cli.metadata.single_sign_on_service(entity_id, _binding)
                logger.debug("srvs: %s" % srvs)
                dest = srvs[0]["location"]
                logger.debug("destination: %s" % dest)
                req = _cli.create_authn_request(dest, vorg=vorg_name)
                ht_args = _cli.apply_binding(_binding, "%s" % req,
                                             destination=dest,
                                             relay_state=came_from)
                _sid = req.id
                logger.debug("ht_args: %s" % ht_args)
            except Exception, exc:
                logger.exception(exc)
                raise Exception("Failed to construct the AuthnRequest: %s" % exc)

            # remember the request
            self.outstanding_queries[_sid] = came_from

            if not ht_args["data"] and ht_args["headers"][0][0] == "Location":
                logger.debug('redirect to: %s' % ht_args["headers"][0][1])
                return HTTPSeeOther(headers=ht_args["headers"])
            else :
                return ht_args["data"]

    def _construct_identity(self, session_info):
        identity = {
            "login": session_info["name_id"],
            "password": "",
            'repoze.who.userid': session_info["name_id"],
            "user": session_info["ava"],
        }
        logger.debug("Identity: %s" % identity)

        return identity
        
    def _eval_authn_response(self, environ, post):
        logger.info("Got AuthN response, checking..")
        logger.info("Outstanding: %s" % (self.outstanding_queries,))

        try:
            # Evaluate the response, returns a AuthnResponse instance
            try:
                authresp = self.saml_client.parse_authn_request_response(
                                                    post["SAMLResponse"],
                                                    BINDING_HTTP_POST,
                                                    self.outstanding_queries)
            except Exception, excp:
                logger.exception("Exception: %s" % (excp,))
                raise
                
            session_info = authresp.session_info()
        except TypeError, excp:
            logger.exception("Exception: %s" % (excp,))
            return None
                                        
        if session_info["came_from"]:
            logger.debug("came_from << %s" % session_info["came_from"])
            try:
                path, query = session_info["came_from"].split('?')
                environ["PATH_INFO"] = path
                environ["QUERY_STRING"] = query
            except ValueError:
                environ["PATH_INFO"] = session_info["came_from"]

        logger.info("Session_info: %s" % session_info)
        return session_info

    def do_ecp_response(self, body, environ):
        response, _relay_state = ecp.handle_ecp_authn_response(self.saml_client,
                                                               body)

        environ["s2repoze.relay_state"] = _relay_state.text
        session_info = response.session_info()
        logger.info("Session_info: %s" % session_info)

        return session_info

    #### IIdentifier ####
    def identify(self, environ):
        """
        Tries do the identification 
        """
        #logger = environ.get('repoze.who.logger', '')

        if "CONTENT_LENGTH" not in environ or not environ["CONTENT_LENGTH"]:
            logger.debug('[identify] get or empty post')
            return {}
        
        # if logger:
        #     logger.info("ENVIRON: %s" % environ)
        #     logger.info("self: %s" % (self.__dict__,))
        
        uri = environ.get('REQUEST_URI', construct_url(environ))
        
        logger.debug('[sp.identify] uri: %s' % (uri,))

        query = parse_dict_querystring(environ)
        logger.debug('[sp.identify] query: %s' % (query,))
        
        post = self._get_post(environ)

        try:
            logger.debug('[sp.identify] post keys: %s' % (post.keys(),))
        except (TypeError, IndexError):
            pass
            
        try:
            if not post.has_key("SAMLResponse"):
                logger.info("[sp.identify] --- NOT SAMLResponse ---")
                # Not for me, put the post back where next in line can
                # find it
                environ["post.fieldstorage"] = post
                return {}
            else:
                logger.info("[sp.identify] --- SAMLResponse ---")
                # check for SAML2 authN response
                #if self.debug:
                try:
                    session_info = self._eval_authn_response(environ,
                                                cgi_field_storage_to_dict(post))
                except Exception:
                    return None
        except TypeError, exc:
            # might be a ECP (=SOAP) response
            body = environ.get('s2repoze.body', None)
            if body:
                # might be a ECP response
                try:
                    session_info = self.do_ecp_response(body, environ)
                except Exception:
                    environ["post.fieldstorage"] = post
                    return {}
            else:
                exception_trace("sp.identity", exc, logger)
                environ["post.fieldstorage"] = post
                return {}
            
        if session_info:        
            environ["s2repoze.sessioninfo"] = session_info
            name_id = session_info["name_id"]
            # contruct and return the identity
            identity = {
                "login": name_id,
                "password": "",
                'repoze.who.userid': name_id,
                "user": self.saml_client.users.get_identity(name_id)[0],
            }
            logger.info("[sp.identify] IDENTITY: %s" % (identity,))
            return identity
        else:
            return None

                    
    # IMetadataProvider
    def add_metadata(self, environ, identity):
        """ Add information to the knowledge I have about the user """
        subject_id = identity['repoze.who.userid']
        #logger = environ.get('repoze.who.logger','')

        _cli = self.saml_client
        logger.debug("[add_metadata] for %s" % subject_id)
        try:
            logger.debug("Issuers: %s" % _cli.users.sources(subject_id))
        except KeyError:
            pass
            
        if "user" not in identity:
            identity["user"] = {}
        try:
            (ava, _) = _cli.users.get_identity(subject_id)
            #now = time.gmtime()        
            logger.debug("[add_metadata] adds: %s" % ava)
            identity["user"].update(ava)
        except KeyError:
            pass

        if "pysaml2_vo_expanded" not in identity and _cli.vorg:
            # is this a Virtual Organization situation
            for vo in _cli.vorg.values():
                try:
                    if vo.do_aggregation(subject_id):
                        # Get the extended identity
                        identity["user"] = _cli.users.get_identity(subject_id)[0]
                        # Only do this once, mark that the identity has been
                        # expanded
                        identity["pysaml2_vo_expanded"] = 1
                except KeyError:
                    logger.exception("Failed to do attribute aggregation, "
                                     "missing common attribute")
        logger.debug("[add_metadata] returns: %s" % (dict(identity),))

        if not identity["user"]:
            # remove cookie and demand re-authentication
            pass
        
# @return
# used 2 times : one to get the ticket, the other to validate it
    def _service_url(self, environ, qstr=None):
        if qstr is not None:
            url = construct_url(environ, querystring = qstr)
        else:
            url = construct_url(environ)
        return url

    #### IAuthenticatorPlugin #### 
    #noinspection PyUnusedLocal
    def authenticate(self, environ, identity=None):
        if identity:
            return identity.get('login', None)
        else:
            return None


def make_plugin(rememberer_name=None, # plugin for remember
                 cache= "", # cache
                 # Which virtual organization to support
                 virtual_organization="", 
                 saml_conf="",
                 wayf="",
                 sid_store="",
                 identity_cache="",
                 discovery="",
                 ):
    
    if saml_conf is "":
        raise ValueError(
            'must include saml_conf in configuration')

    if rememberer_name is None:
        raise ValueError(
             'must include rememberer_name in configuration')

    conf = config_factory("sp", saml_conf)

    scl = Saml2Client(config=conf, identity_cache=identity_cache,
                        virtual_organization=virtual_organization)

    plugin = SAML2Plugin(rememberer_name, conf, scl, wayf, cache, sid_store,
                         discovery)
    return plugin


