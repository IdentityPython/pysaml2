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

from paste.httpexceptions import HTTPTemporaryRedirect
from paste.httpexceptions import HTTPNotImplemented
from paste.httpexceptions import HTTPInternalServerError
from paste.request import parse_dict_querystring
from paste.request import construct_url

from zope.interface import implements

from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from repoze.who.interfaces import IMetadataProvider
from repoze.who.plugins.form import FormPluginBase

from saml2.client import Saml2Client
from saml2.attribute_resolver import AttributeResolver
from saml2.config import Config
from saml2.population import Population

def construct_came_from(environ):
    """ The URL that the user used when the process where interupted 
    for single-sign-on processing. """
    
    came_from = environ.get("PATH_INFO") 
    qstr = environ.get("QUERY_STRING","")
    if qstr:
        came_from += '?' + qstr
    return came_from
    
# FormPluginBase defines the methods remember and forget
def cgi_fieldStorage_to_dict( fieldStorage ):
    """Get a plain dictionary, rather than the '.value' system used by the
    cgi module."""
    
    params = {}
    for key in fieldStorage.keys():
        try:
            params[ key ] = fieldStorage[ key ].value
        except AttributeError:
            if isinstance(fieldStorage[ key ], basestring):
                params[key] = fieldStorage[key]
                
    return params
           
class SAML2Plugin(FormPluginBase):

    implements(IChallenger, IIdentifier, IAuthenticator, IMetadataProvider)
    
    def __init__(self, rememberer_name, saml_conf_file, virtual_organization,
                wayf, cache, debug):
        FormPluginBase.__init__(self)
        self.rememberer_name = rememberer_name
        self.debug = debug        
        self.wayf = wayf
        
        self.conf = Config()
        self.conf.load_file(saml_conf_file)
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
        self.outstanding_queries = {}
        self.iam = os.uname()[1]
        
        self.users = Population(cache)
                 
    def _pick_idp(self, environ):
        """ 
        If more than one idp and if none is selected, I have to do wayf or 
        disco
        """
        
        self.log and self.log.info("IdP URL: %s" % self.srv["idp"].values())
        if len( self.srv["idp"] ) == 1:
            # Keys are entity_ids and values are urls
            idp_url = self.srv["idp"].values()[0]
        elif len( self.srv["idp"] ) == 0:
            return (1,HTTPInternalServerError(detail='Misconfiguration'))
        else:
            if self.wayf:
                wayf_selected = environ.get('s2repose.wayf_selected','')
                if not wayf_selected:
                    self.log.info("Redirect to WAYF function: %s" % self.wayf)
                    self.log.info("env, keys: %s" % (environ.keys()))
                    return (1,HTTPTemporaryRedirect(headers = [('Location', 
                                                            self.wayf)]))
                else:
                    self.log.info("Choosen IdP: '%s'" % wayf_selected)
                    idp_url = self.srv["idp"][wayf_selected]
            else:
                return (1,HTTPNotImplemented(detail='No WAYF present!'))

        return (0,idp_url)
        
    #### IChallenger ####
    def challenge(self, environ, _status, _app_headers, _forget_headers):

        # this challenge consist in loggin out
        if environ.has_key('rwpc.logout'): 
            # TODO
            pass

        self.log = environ.get('repoze.who.logger','')

        # Which page was accessed to get here
        came_from = construct_came_from(environ)
        if self.debug:
            self.log and self.log.info("RelayState >> %s" % came_from)
        
        # Am I part of a virtual organization ?
        try:
            vorg = environ["myapp.vo"]
        except KeyError:
            vorg = self.vorg
        self.log and self.log.info("VO: %s" % vorg)

        # If more than one idp and if none is selected, I have to do wayf
        (done, response) = self._pick_idp(environ)
        if done:
            return response
        else:
            idp_url = response
            # Do the AuthnRequest
            scl = Saml2Client(environ, self.conf)        
            (sid, result) = scl.authenticate(self.conf["entityid"], 
                                            idp_url, 
                                            self.srv["url"], 
                                            self.srv["name"], 
                                            relay_state=came_from, 
                                            log=self.log,
                                            vorg=vorg)
            
            # remember the request
            self.outstanding_queries[sid] = came_from
                
            if self.debug:
                self.log and self.log.info('sc returned: %s' % (result,))
            if isinstance(result, tuple):
                return HTTPTemporaryRedirect(headers=[result])
            else :
                return HTTPInternalServerError(detail='Incorrect returned data')

    def _get_post(self, environ):
        """ Get the posted information """
        post_env = environ.copy()
        post_env['QUERY_STRING'] = ''
        
        try:
            if environ["CONTENT_LENGTH"]:
                len = int(environ["CONTENT_LENGTH"])
                body = environ["wsgi.input"].read(len)
                from StringIO import StringIO
                environ['wsgi.input'] = StringIO(body)
                environ['s2repoze.body'] = body
        except KeyError:
            pass

        post = cgi.FieldStorage(
            fp=environ['wsgi.input'],
            environ=post_env,
            keep_blank_values=True
        )

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
        """ """
        self.log and self.log.info("Got AuthN response, checking..")
        scl = Saml2Client(environ, self.conf, self.debug)
        print "Outstanding: %s" % (self.outstanding_queries,)
        try:
            # Evaluate the response, returns a AuthnResponse instance
            try:
                ar = scl.response(post, self.conf["entityid"], 
                                    self.outstanding_queries, self.log)
            except Exception, excp:
                self.log and self.log.error("Exception: %s" % (excp,))
                raise
                
            session_info = ar.session_info()
            # Cache it
            name_id = self.users.add_information_about_person(session_info)
            if self.debug:
                self.log and self.log.info("stored %s with key %s" % (
                                            session_info, name_id))
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
                
        return session_info
        
    #### IIdentifier ####
    def identify(self, environ):
        self.log = environ.get('repoze.who.logger','')
        
        if self.log:
            self.log.info("ENVIRON: %s" % environ)
            self.log.info("self: %s" % (self.__dict__,))
        
        uri = environ.get('REQUEST_URI', construct_url(environ))
        if self.debug:
            #self.log and self.log.info("environ.keys(): %s" % environ.keys())
            #self.log and self.log.info("Environment: %s" % environ)
            self.log and self.log.info('identify uri: %s' % (uri,))

        query = parse_dict_querystring(environ)
        if self.debug:
            self.log and self.log.info('identify query: %s' % (query,))
        
        post = self._get_post(environ)
        
        # Not for me, put the post back where next in line can find it
        try:
            if not post.has_key("SAMLResponse"):
                environ["post.fieldstorage"] = post
                return {}
            else:
                self.log.info("--- SAMLResponse ---")
        except TypeError, exc:
            self.log.error("Exception: %s" % (exc,))
            environ["post.fieldstorage"] = post
            return {}
            
        # check for SAML2 authN response
        #if self.debug:
        session_info = self._eval_authn_response(environ,  
                                            cgi_fieldStorage_to_dict(post))
        if session_info:        
            environ["s2repoze.sessioninfo"] = session_info

            # contruct and return the identity
            return self._construct_identity(session_info)
        else:
            return None

                    
    # IMetadataProvider
    def add_metadata(self, environ, identity):
        """ Add information to the knowledge I have about the user """
        subject_id = identity['repoze.who.userid']

        self.log = environ.get('repoze.who.logger','')
        if self.debug and self.log:
            self.log.info(
                "add_metadata for %s" % subject_id)
            self.log.info(
                "Known subjects: %s" % self.cache.subjects())
            try:
                self.log.info(
                    "Issuers: %s" % self.cache.entities(subject_id))
            except KeyError:
                pass
            
        if "user" not in identity:
            identity["user"] = {}
        try:
            (ava, _) = self.cache.get_identity(subject_id)
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
                    identity["user"] = self.cache.get_identity(subject_id)[0]
                    # Only do this once, mark that the identity has been 
                    # expanded
                    identity["pysaml2_vo_expanded"] = 1

# @return
# used 2 times : one to get the ticket, the other to validate it
    def _serviceURL(self, environ, qstr=None):
        if qstr != None:
            url = construct_url(environ, querystring = qstr)
        else:
            url = construct_url(environ)
        return url

    #### IAuthenticatorPlugin #### 
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
                 debug=0,
                 ):
    
    if saml_conf is None:
        raise ValueError(
            'must include saml_conf in configuration')

    if rememberer_name is None:
        raise ValueError(
             'must include rememberer_name in configuration')

    plugin = SAML2Plugin(rememberer_name, saml_conf, 
                virtual_organization, wayf, cache, debug)
    return plugin

# came_from = re.sub(r'ticket=[^&]*&?', '', came_from)

