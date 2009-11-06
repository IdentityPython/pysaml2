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

from saml2.client import Saml2Client, verify_sp_conf
from saml2.attribute_resolver import AttributeResolver
from saml2.metadata import MetaData
from saml2.saml import NAMEID_FORMAT_TRANSIENT

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
    
    def __init__(self, rememberer_name, saml_conf_file, store,
                path_logout, path_toskip, debug):
        
        self.rememberer_name = rememberer_name
        self.path_logout = path_logout
        self.path_toskip = path_toskip
        self.debug = debug        
        
        self.conf = verify_sp_conf(saml_conf_file)
        try:
            self.metadata = self.conf["metadata"]
        except KeyError:
            self.metadata = None
        self.outstanding_authn = {}
        self.iam = os.uname()[1]
        
        if store==u"file":
            self.store = shelve.open(store_filename)
        elif store==u"mem":
            self.store = {}
         
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
        (sid, result) = cl.authenticate(self.conf["entityid"], 
                                        self.conf["idp_url"], 
                                        self.conf["service_url"], 
                                        self.conf["my_name"], 
                                        relay_state=came_from, log=logger)
        self.outstanding_authn[sid] = came_from
            
        if self.debug:
            logger and logger.info('sc returned: %s' % (result,))
        if isinstance(result, tuple):
            return HTTPTemporaryRedirect(headers=[result])
        else :
            # possible to normally not used
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
            logger and logger.info("environ.keys(): %s" % environ.keys())
            logger and logger.info("Environment: %s" % environ)
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
        post = cgi.FieldStorage(
            fp=environ['wsgi.input'],
            environ=post_env,
            keep_blank_values=True
        )

        if self.debug:
            logger and logger.info('identify post keys: %s' % (post.keys(),))

        # check for SAML2 authN
        cl = Saml2Client(environ, self.conf)
        try:
            (ava, came_from) = cl.response(post, 
                                            self.conf["entityid"], 
                                            self.outstanding_authn,
                                            logger)
            name_id = ava["__userid"]
            del ava["__userid"]
            self.store[name_id] = ava
            if self.debug:
                logger and logger.info("stored %s with key %s" % (ava, name_id))
        except TypeError:
            return None
                                        
        if came_from:
            if self.debug:
                logger and logger.info("came_from << %s" % came_from)
            try:
                path, query = came_from.split('?')
                environ["PATH_INFO"] = path
                environ["QUERY_STRING"] = query
            except ValueError:
                environ["PATH_INFO"] = came_from
        
        identity = {}
        identity["login"] = name_id
        identity["password"] = ""
        identity['repoze.who.userid'] = name_id
        identity.update(ava)
        if self.debug:
            logger and logger.info("Identity: %s" % identity)
        return identity

    # IMetadataProvider
    def add_metadata(self, environ, identity):
        if self.debug:
            logger = environ.get('repoze.who.logger','')
            logger and logger.info(
                "add_metadata for %s" % identity['repoze.who.userid'])
        try:
            ava = self.store[identity['repoze.who.userid']]
            if self.debug:
                logger and logger.info("Adding %s" % ava)
            identity.update(ava)
            self.store[identity['repoze.who.userid']] = identity
        except KeyError:
            pass

        if "pysaml2_vo_expanded" not in identity:
            # is this a Virtual Organization situation
            if "virtual_organization" in self.conf:
                logger and logger.info("** Do VO aggregation **")
                try:
                    subject_id = identity[self.conf["common_identifier"]][0]
                except KeyError:
                    return
                logger and logger.info("SubjectID: %s" % subject_id)
                ar = AttributeResolver(environ, self.metadata, 
                                        self.conf["xmlsec_binary"],
                                        self.conf["key_file"],
                                        self.conf["cert_file"])
                vo_members = [
                            member for member in self.metadata.vo_members(
                                self.conf["virtual_organization"])\
                                if member != self.conf["md_idp"]]
                logger and logger.info("VO members: %s" % vo_members)

                if vo_members:
                    extra = ar.extend(subject_id, 
                            self.conf["entityid"], 
                            vo_members, 
                            self.conf["nameid_format"],
                            log=logger)

                    for attr,val in extra.items():
                        try:
                            # might lead to duplicates !
                            identity[attr].extend(val)
                        except KeyError:
                            identity[attr] = val

                    # Only do this once
                    identity["pysaml2_vo_expanded"] = 1
                    self.store[identity['repoze.who.userid']] = identity
        
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
                 store= "mem", # store for remember
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

    plugin = SAML2Plugin(rememberer_name, saml_conf, store,
                path_logout, path_toskip, debug)
    return plugin

# came_from = re.sub(r'ticket=[^&]*&?', '', came_from)

