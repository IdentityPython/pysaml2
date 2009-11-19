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
import re
import urlparse
import urllib
import cgi
import os
import time

from paste.httpheaders import CONTENT_LENGTH
from paste.httpheaders import CONTENT_TYPE
from paste.httpheaders import LOCATION
from paste.httpexceptions import HTTPFound
from paste.httpexceptions import HTTPUnauthorized
from paste.httpexceptions import HTTPTemporaryRedirect
from paste.request import parse_dict_querystring
from paste.request import parse_formvars
from paste.request import construct_url
from paste.request import parse_querystring

from paste.response import header_value

from zope.interface import implements

from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from repoze.who.interfaces import IMetadataProvider
from repoze.who.plugins.form import FormPluginBase

from saml2.client import Saml2Client
from saml2.attribute_resolver import AttributeResolver
from saml2.metadata import MetaData
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.config import Config
from saml2.cache import Cache

def construct_came_from(environ):
    """ The URL that the user used when the process where interupted 
    for single-sign-on processing. """
    
    came_from = environ.get("PATH_INFO") 
    qs = environ.get("QUERY_STRING","")
    if qs:
        came_from += '?' + qs
    return came_from
    
# FormPluginBase defines the methods remember and forget
        
class SAML2Plugin(FormPluginBase):

    implements(IChallenger, IIdentifier, IAuthenticator, IMetadataProvider)
    
    def __init__(self, rememberer_name, saml_conf_file, virtual_organization,
                cache, path_logout, path_toskip, debug):
        
        self.rememberer_name = rememberer_name
        self.path_logout = path_logout
        self.path_toskip = path_toskip
        self.debug = debug        
        
        self.conf = Config()
        self.conf.load_file(saml_conf_file)
        self.sp = self.conf["service"]["sp"]
        if virtual_organization:
            self.vo = virtual_organization
            try:
                self.vo_conf = self.conf[
                                "virtual_organization"][virtual_organization]
            except KeyError:
                self.vo = None
        else:
            self.vo = None
            
        try:
            self.metadata = self.conf["metadata"]
        except KeyError:
            self.metadata = None
        self.outstanding_authn = {}
        self.iam = os.uname()[1]
        
        if cache:
            self.cache = Cache(cache)
        else:
            self.cache = Cache()
         
    #### IChallenger ####
    def challenge(self, environ, status, app_headers, forget_headers):

        # this challenge consist in loggin out
        if environ.has_key('rwpc.logout'): 
            # TODO
            pass

        logger = environ.get('repoze.who.logger','')
        # ELSE, perform a real challenge => asking for loggin
        # here by redirecting the user to a IdP.

        cl = Saml2Client(environ, self.conf)
        came_from = construct_came_from(environ)
        if self.debug:
            logger and logger.info("RelayState >> %s" % came_from)
        
        try:
            vo = environ["myapp.vo"]
        except KeyError:
            vo = self.vo
        logger and logger.info("VO: %s" % vo)
        # If more than one idp, I have to do wayf
        (sid, result) = cl.authenticate(self.conf["entityid"], 
                                        self.conf["idp"]["url"][0], 
                                        self.sp["url"], 
                                        self.sp["my_name"], 
                                        relay_state=came_from, 
                                        log=logger,
                                        vo=vo)
        self.outstanding_authn[sid] = came_from
            
        if self.debug:
            logger and logger.info('sc returned: %s' % (result,))
        if isinstance(result, tuple):
            return HTTPTemporaryRedirect(headers=[result])
        else :
            # possible though normally not used
            body = "\n".join(result)
            def auth_form(environ, start_response):
                content_length = CONTENT_LENGTH.tuples(str(len(result)))
                content_type = CONTENT_TYPE.tuples('text/html')
                headers = content_length + content_type + forget_headers
                start_response('200 OK', headers)
                return [result]

            return auth_form

    #### IIdentifier ####
    def identify(self, environ):
        logger = environ.get('repoze.who.logger','')
        
        uri = environ.get('REQUEST_URI',construct_url(environ))
        if self.debug:
            #logger and logger.info("environ.keys(): %s" % environ.keys())
            #logger and logger.info("Environment: %s" % environ)
            logger and logger.info('identify uri: %s' % (uri,))

        query = parse_dict_querystring(environ)
        if self.debug:
            logger and logger.info('identify query: %s' % (query,))
        
        # path_logout for every app. 
        for regex in self.path_logout:
           if re.match(regex, uri) != None:
               if self.debug : 
                   logger and logger.info("LOGOUT #### ")
               # we've been asked to perform a logout

               # use all except : POST
               # trigger the challenge and tells the challenge this is a logout
               query['bhp'] = 'go'
               environ['rwpc.logout'] = \
                    self._serviceURL(environ,urllib.urlencode(query))
               
               return None

        # skipping, whatever it is (loggin, validating ticket etc.)
        # except for logout (see above)
        for regex in self.path_toskip:
            if re.match(regex, uri) != None:
                if self.debug : 
                       logger and logger.info("########### SKIPPING")
                return None

        post_env = environ.copy()
        post_env['QUERY_STRING'] = ''
        
        if environ["CONTENT_LENGTH"]:
            body = environ["wsgi.input"].read(int(environ["CONTENT_LENGTH"]))
            from StringIO import StringIO
            environ['wsgi.input'] = StringIO(body)
            environ['s2repoze.body'] = body

        post = cgi.FieldStorage(
            fp=environ['wsgi.input'],
            environ=post_env,
            keep_blank_values=True
        )

        if self.debug:
            logger and logger.info('identify post: %s' % (post,))

        try:
            if not post.has_key("SAMLResponse"):
                environ["post.fieldstorage"] = post
                return {}
        except TypeError:
            environ["post.fieldstorage"] = post
            return {}
            
        # check for SAML2 authN
        cl = Saml2Client(environ, self.conf)
        try:
            session_info = cl.response(post, 
                                            self.conf["entityid"], 
                                            self.outstanding_authn,
                                            logger)
            name_id = session_info["ava"]["__userid"]
            del session_info["ava"]["__userid"]
            issuer = session_info["issuer"]
            del session_info["issuer"]
            self.cache.set(name_id, issuer, session_info, 
                            session_info["not_on_or_after"])
            if self.debug:
                logger and logger.info("stored %s with key %s" % (
                                        session_info, name_id))
        except TypeError:
            return None
                                        
        if session_info["came_from"]:
            if self.debug:
                logger and logger.info(
                            "came_from << %s" % session_info["came_from"])
            try:
                path, query = session_info["came_from"].split('?')
                environ["PATH_INFO"] = path
                environ["QUERY_STRING"] = query
            except ValueError:
                environ["PATH_INFO"] = session_info["came_from"]
        
        identity = {}
        identity["login"] = name_id
        identity["password"] = ""
        identity['repoze.who.userid'] = name_id
        identity["user"] = session_info["ava"]
        environ["s2repoze.sessioninfo"] = session_info
        if self.debug:
            logger and logger.info("Identity: %s" % identity)
        return identity

    # IMetadataProvider
    def add_metadata(self, environ, identity):
        subject_id = identity['repoze.who.userid']

        if self.debug:
            logger = environ.get('repoze.who.logger','')
            if logger:
                logger.info(
                    "add_metadata for %s" % subject_id)
                logger.info(
                    "Known subjects: %s" % self.cache.subjects())
                try:
                    logger.info(
                        "Issuers: %s" % self.cache.issuers(subject_id))
                except KeyError:
                    pass
            
        if "user" not in identity:
            identity["user"] = {}
        try:
            (ava, old) = self.cache.get_identity(subject_id)
            now = time.gmtime()        
            if self.debug:
                logger and logger.info("Adding %s" % ava)
            identity["user"].update(ava)
        except KeyError:
            pass

        if "pysaml2_vo_expanded" not in identity:
            # is this a Virtual Organization situation
            if self.vo:
                logger and logger.info("** Do VO aggregation **")
                #try:
                    # This ought to be caseignore 
                    #subject_id = identity["user"][
                    #                    self.vo_conf["common_identifier"]][0]
                #except KeyError:
                #    logger and logger.error("** No common identifier **")
                #    return
                logger and logger.info(
                    "SubjectID: %s, VO:%s" % (subject_id, self.vo))
                
                vo_members = [
                    member for member in self.metadata.vo_members(self.vo)\
                        if member not in self.conf["idp"]["entity_id"]]
                    
                logger and logger.info("VO members: %s" % vo_members)
                vo_members = [m for m in vo_members \
                                if not self.cache.active(subject_id, m)]
                logger and logger.info(
                                "VO members (not cached): %s" % vo_members)

                if vo_members:
                    ar = AttributeResolver(environ, self.metadata, self.conf)
                
                    if "name_id_format" in self.vo_conf:
                        name_id_format = self.vo_conf["name_id_format"]
                        sp_name_qualifier=""
                    else:
                        sp_name_qualifier=self.vo
                        name_id_format = ""
                    
                    extra = ar.extend(subject_id, 
                            self.conf["entityid"], 
                            vo_members, 
                            name_id_format=name_id_format,
                            sp_name_qualifier=sp_name_qualifier,
                            log=logger)

                    for issuer, tup in extra.items():
                        (not_on_or_after, resp) = tup
                        self.cache.set(subject_id, issuer, resp, 
                                            not_on_or_after)

                    logger.info(
                        ">Issuers: %s" % self.cache.issuers(subject_id))
                    logger.info(
                        "AVA: %s" % (self.cache.get_identity(subject_id),))
                    identity["user"] = self.cache.get_identity(subject_id)[0]
                    # Only do this once
                    identity["pysaml2_vo_expanded"] = 1
                    #self.store[identity['repoze.who.userid']] = (
                    #                        not_on_or_after, identity)
        
# @return
# used 2 times : one to get the ticket, the other to validate it
    def _serviceURL(self,environ,qs=None):
        if qs != None:
            url = construct_url(environ, querystring=qs)
        else:
            url = construct_url(environ)
        return url

    #### IAuthenticatorPlugin #### 
    def authenticate(self, environ, identity={}):
        return identity.get('login',None)


def make_plugin(rememberer_name=None, # plugin for remember
                 cache= "", # cache
                 # Which virtual organization to support
                 virtual_organization="", 
                 path_logout='', # regex url to logout
                 path_toskip='',  # regex url to skip
                 saml_conf="",
                 debug=0,
                 ):
    
    if saml_conf is None:
        raise ValueError(
            'must include saml_conf in configuration')

    if rememberer_name is None:
        raise ValueError(
             'must include rememberer_name in configuration')
    path_logout = path_logout.lstrip().split('\n');
    path_toskip = path_toskip.lstrip().splitlines()

    plugin = SAML2Plugin(rememberer_name, saml_conf, 
                virtual_organization, cache,
                path_logout, path_toskip, debug)
    return plugin

# came_from = re.sub(r'ticket=[^&]*&?', '', came_from)

