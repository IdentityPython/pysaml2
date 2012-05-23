#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
from s2repoze.plugins.sp import make_plugin
from saml2.server import Server
from saml2 import make_instance, samlp, saml

ENV1 = {'SERVER_SOFTWARE': 'CherryPy/3.1.2 WSGI Server', 
    'SCRIPT_NAME': '', 
    'ACTUAL_SERVER_PROTOCOL': 'HTTP/1.1', 
    'REQUEST_METHOD': 'GET', 
    'PATH_INFO': '/krissms', 
    'SERVER_PROTOCOL': 'HTTP/1.1', 
    'QUERY_STRING': '', 
    'REMOTE_ADDR': '127.0.0.1', 
    'HTTP_USER_AGENT': 
        'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_2; en-us) ', 
    'HTTP_CONNECTION': 'keep-alive', 
    'SERVER_NAME': 'lingon-catalogix-se-2.local', 
    'REMOTE_PORT': '57309', 
    'wsgi.url_scheme': 'http', 
    'SERVER_PORT': '8087', 
    'HTTP_HOST': '127.0.0.1:8087', 
    'wsgi.multithread': True, 
    'HTTP_ACCEPT': 
        'application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5', 
    'wsgi.version': (1, 0), 
    'wsgi.run_once': False, 
    'wsgi.multiprocess': False, 
    'HTTP_ACCEPT_LANGUAGE': 'en-us', 
    'HTTP_ACCEPT_ENCODING': 'gzip, deflate'}
    
class TestSP():
    def setup_class(self):
        self.sp = make_plugin("rem", saml_conf="server_conf")
        self.server = Server(config_file="idp_conf")

    def test_setup(self):
        assert self.sp
        
    def test_identify(self):

        # Create a SAMLResponse
        ava = { "givenName": ["Derek"], "surname": ["Jeter"], 
                "mail": ["derek@nyy.mlb.com"]}

        resp_str = "\n".join(self.server.authn_response(ava, 
                    "id1", "http://lingon.catalogix.se:8087/", 
                    "urn:mace:example.com:saml:roland:sp",
                    samlp.NameIDPolicy(format=saml.NAMEID_FORMAT_TRANSIENT,
                                        allow_create="true"),
                    "foba0001@example.com"))

        resp_str = base64.encodestring(resp_str)
        self.sp.outstanding_queries = {"id1":"http://www.example.com/service"}
        session_info = self.sp._eval_authn_response({},{"SAMLResponse":resp_str})
        
        assert len(session_info) > 1
        assert session_info["came_from"] == 'http://www.example.com/service'
        assert session_info["ava"] == {'givenName': ['Derek'], 
                                        'mail': ['derek@nyy.mlb.com'], 
                                        'sn': ['Jeter']}