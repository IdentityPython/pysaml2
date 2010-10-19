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
import os
import shelve

from paste.httpexceptions import HTTPTemporaryRedirect
from paste.httpexceptions import HTTPNotImplemented
from paste.httpexceptions import HTTPInternalServerError
from paste.request import parse_dict_querystring
from paste.request import construct_url

from zope.interface import implements

from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from repoze.who.interfaces import IMetadataProvider
from repoze.who.plugins.form import FormPluginBase

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
#from saml2.attribute_resolver import AttributeResolver
from saml2.config import SPConfig
from saml2.s_utils import sid
#from saml2.population import Population

def construct_came_from(environ):
    """ The URL that the user used when the process where interupted 
    for single-sign-on processing. """
    
    came_from = environ.get("PATH_INFO") 
    qstr = environ.get("QUERY_STRING","")
    if qstr:
        came_from += '?' + qstr
    return came_from
    
# FormPluginBase defines the methods remember and forget
def cgi_field_storage_to_dict( field_storage ):
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
           
class SAML2Plugin(FormPluginBase):

    implements(IChallenger, IIdentifier, IAuthenticator, IMetadataProvider)
    
    def __init__(self, rememberer_name, config, saml_client, 
                virtual_organization, wayf, _cache, debug, sid_store=None):
        FormPluginBase.__init__(self)
        
        self.rememberer_name = rememberer_name
        self.debug = debug        
        self.wayf = wayf
        self.saml_client = saml_client
        
        self.conf = config
        self.srv = self.conf["service"]["sp"]
        self.log = None
        
        if virtual_organization:
            self.vorg = virtual_organization
            self.vorg_conf = None
#            try:
#                self.vorg_conf = self.conf[
#                                "virtual_organization"][virtual_organization]
#            except KeyError:
#                self.vorg = None
        else:
            self.vorg = None
            
        try:
            self.metadata = self.conf["metadata"]
        except KeyError:
            self.metadata = None
        if sid_store:
            self.outstanding_queries = shelve.open(sid_store, writeback=True)
        else:
            self.outstanding_queries = {}
        self.iam = os.uname()[1]
                         
    def _pick_idp(self, environ, came_from):
        """ 
        If more than one idp and if none is selected, I have to do wayf or 
        disco
        """
        
        idps = self.conf.idps()
        
        #self.log and self.log.info("IdP URL: %s" % idps)

        if len( idps ) == 1:
            idp_url = idps[0]["single_sign_on_service"][BINDING_HTTP_REDIRECT]
        elif len( idps ) == 0:
            return (1, HTTPInternalServerError(detail='Misconfiguration'))
        else:
            if self.wayf:
                wayf_selected = environ.get('s2repose.wayf_selected','')
                if not wayf_selected:
                    sid_ = sid()
                    self.outstanding_queries[sid_] = came_from
                    self.log.info("Redirect to WAYF function: %s" % self.wayf)
                    #self.log.info("env: %s" % (environ,))
                    return (1, HTTPTemporaryRedirect(headers = [('Location', 
                                                "%s?%s" % (self.wayf, sid_))]))
                else:
                    self.log.info("Choosen IdP: '%s'" % wayf_selected)
                    try:
                        idp_url = self.srv["idp"][wayf_selected][
                                                    "single_sign_on_service"][
                                                        BINDING_HTTP_REDIRECT]
                    except KeyError:
                        return (1, 
                            HTTPNotImplemented(
                                detail="Do not know how to talk to '%s'!" & (
                                                            wayf_selected,)))
            else:
                return (1, HTTPNotImplemented(detail='No WAYF present!'))

        return (0, idp_url)
        
    #### IChallenger ####
    def challenge(self, environ, _status, _app_headers, _forget_headers):

        # this challenge consist in loggin out
        if environ.has_key('rwpc.logout'): 
            # ignore right now?
            pass

        self.log = environ.get('repoze.who.logger','')
        self.saml_client.log = self.log
        
        # Which page was accessed to get here
        came_from = construct_came_from(environ)
        environ["myapp.came_from"] = came_from
        if self.debug:
            self.log and self.log.info("[sp.challenge] RelayState >> %s" % came_from)
        
        # Am I part of a virtual organization ?
        try:
            vorg = environ["myapp.vo"]
        except KeyError:
            vorg = self.vorg
        self.log and self.log.info("[sp.challenge] VO: %s" % vorg)

        # If more than one idp and if none is selected, I have to do wayf
        (done, response) = self._pick_idp(environ, came_from)
        if done:
            return response
        else:
            idp_url = response
            # Do the AuthnRequest
            (sid_, result) = self.saml_client.authenticate(location=idp_url,
                                                    relay_state=came_from, 
                                                    vorg=vorg)
            
            # remember the request
            self.outstanding_queries[sid_] = came_from
                
            if self.debug:
                self.log and self.log.info('sc returned: %s' % (result,))
            if isinstance(result, tuple):
                return HTTPTemporaryRedirect(headers=[result])
            else :
                return HTTPInternalServerError(detail='Incorrect returned data')

    def _get_post(self, environ):
        """ 
        Get the posted information 
        
        :param environ: A dictionary 
        """
        
        post = {}

        post_env = environ.copy()
        post_env['QUERY_STRING'] = ''

        length = int(environ["CONTENT_LENGTH"])
        try:
            body = environ["wsgi.input"].read(length)
        except Exception, excp:
            if self.debug and self.log:
                self.log.info("Exception while reading post: %s" % (excp,))
                raise
            
        from StringIO import StringIO
        environ['wsgi.input'] = StringIO(body)
        environ['s2repoze.body'] = body

        try:
            post = cgi.FieldStorage(
                fp=environ['wsgi.input'],
                environ=post_env,
                keep_blank_values=True
            )
        except Exception, excp:
            if self.debug and self.log:
                self.log.info("Exception (II): %s" % (excp,))
                raise

        if self.debug:
            self.log and self.log.info('identify post: %s' % (post,))
            
        return post
    
    def _construct_identity(self, session_info):
        identity = {}
        identity["login"] = session_info["name_id"]
        identity["password"] = ""
        identity['repoze.who.userid'] = session_info["name_id"]
        identity["user"] = session_info["ava"]
        if self.debug and self.log:
            self.log.info("Identity: %s" % identity)

        return identity
        
    def _eval_authn_response(self, environ, post):
        self.log and self.log.info("Got AuthN response, checking..")

        print "Outstanding: %s" % (self.outstanding_queries,)
        try:
            # Evaluate the response, returns a AuthnResponse instance
            try:
                authresp = self.saml_client.response(post, 
                                                    self.conf["entityid"],
                                                    self.outstanding_queries,
                                                    self.log)
            except Exception, excp:
                self.log and self.log.error("Exception: %s" % (excp,))
                raise
                
            session_info = authresp.session_info()
        except TypeError, excp:
            self.log and self.log.error("Exception: %s" % (excp,))
            return None
                                        
        if session_info["came_from"]:
            if self.debug:
                self.log and self.log.info(
                            "came_from << %s" % session_info["came_from"])
            try:
                path, query = session_info["came_from"].split('?')
                environ["PATH_INFO"] = path
                environ["QUERY_STRING"] = query
            except ValueError:
                environ["PATH_INFO"] = session_info["came_from"]

        self.log and self.log.info("Session_info: %s" % session_info)
        return session_info
        
    #### IIdentifier ####
    def identify(self, environ):
        self.log = environ.get('repoze.who.logger', '')
        self.saml_client.log = self.log
        
        if "CONTENT_LENGTH" not in environ or not environ["CONTENT_LENGTH"]:
            if self.debug:
                self.log and self.log.info('[identify] get or empty post')
            return {}
        
        # if self.log:
        #     self.log.info("ENVIRON: %s" % environ)
        #     self.log.info("self: %s" % (self.__dict__,))
        
        uri = environ.get('REQUEST_URI', construct_url(environ))
        
        if self.debug:
            #self.log and self.log.info("environ.keys(): %s" % environ.keys())
            #self.log and self.log.info("Environment: %s" % environ)
            self.log and self.log.info('[sp.identify] uri: %s' % (uri,))

        query = parse_dict_querystring(environ)
        if self.debug:
            self.log and self.log.info('[sp.identify] query: %s' % (query,))
        
        post = self._get_post(environ)

        if self.debug:
            self.log and self.log.info('[sp.identify] post keys: %s' % (post.keys(),))
            
        # Not for me, put the post back where next in line can find it
        try:
            if not post.has_key("SAMLResponse"):
                self.log.info("[sp.identify] --- NOT SAMLResponse ---")
                environ["post.fieldstorage"] = post
                return {}
            else:
                self.log.info("[sp.identify] --- SAMLResponse ---")
        except TypeError, exc:
            self.log.error("[sp.identify] Exception: %s" % (exc,))
            environ["post.fieldstorage"] = post
            return {}
            
        # check for SAML2 authN response
        #if self.debug:
        try:
            session_info = self._eval_authn_response(environ,  
                                            cgi_field_storage_to_dict(post))
        except Exception, exc:
            return None
            
        if session_info:        
            environ["s2repoze.sessioninfo"] = session_info
            name_id = session_info["name_id"]
            # contruct and return the identity
            identity = {}
            identity["login"] = name_id
            identity["password"] = ""
            identity['repoze.who.userid'] = name_id
            identity["user"] = self.saml_client.users.get_identity(name_id)[0]
            
            self.log.info("[sp.identify] IDENTITY: %s" % (identity,))
            return identity
        else:
            return None

                    
    # IMetadataProvider
    def add_metadata(self, environ, identity):
        """ Add information to the knowledge I have about the user """
        subject_id = identity['repoze.who.userid']

        self.log = environ.get('repoze.who.logger','')
        self.saml_client.log = self.log

        if self.debug and self.log:
            self.log.info(
                "[add_metadata] for %s" % subject_id)
            try:
                self.log.info(
                    "Issuers: %s" % self.saml_client.users.sources(subject_id))
            except KeyError:
                pass
            
        if "user" not in identity:
            identity["user"] = {}
        try:
            (ava, _) = self.saml_client.users.get_identity(subject_id)
            #now = time.gmtime()        
            if self.debug:
                self.log and self.log.info("Adding %s" % ava)
            identity["user"].update(ava)
        except KeyError:
            pass

        if "pysaml2_vo_expanded" not in identity:
            # is this a Virtual Organization situation
            if self.vorg:
                if self.vorg.do_vo_aggregation(subject_id):
                    # Get the extended identity
                    identity["user"] = self.saml_client.users.get_identity(
                                                                subject_id)[0]
                    # Only do this once, mark that the identity has been 
                    # expanded
                    identity["pysaml2_vo_expanded"] = 1

        if self.debug:
            self.log and self.log.info("[Adding] identity %s" % (identity,))
        
        
# @return
# used 2 times : one to get the ticket, the other to validate it
    def _service_url(self, environ, qstr=None):
        if qstr != None:
            url = construct_url(environ, querystring = qstr)
        else:
            url = construct_url(environ)
        return url

    #### IAuthenticatorPlugin #### 
    def authenticate(self, _environ, identity=None):
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
                 debug=0,
                 sid_store="",
                 identity_cache=""
                 ):
    
    if saml_conf is "":
        raise ValueError(
            'must include saml_conf in configuration')

    if rememberer_name is None:
        raise ValueError(
             'must include rememberer_name in configuration')
    
    config = SPConfig()
    config.load_file(saml_conf)

    scl = Saml2Client(config, identity_cache=identity_cache)

    plugin = SAML2Plugin(rememberer_name, config, scl,
                virtual_organization, wayf, cache, debug, sid_store)
    return plugin

# came_from = re.sub(r'ticket=[^&]*&?', '', came_from)

