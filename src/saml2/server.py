#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2009 Umeå University
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

"""Contains classes and functions that a SAML2.0 Identity provider (IdP) 
or attribute authority (AA) may use to conclude its tasks.
"""
import saml2.saml

class Server(object):
    def __init__(self, environ, config ):
        self.environ = environ
        if config:
            self.verify(config)

    def verify_conf(self, conf_file):
        """ """
        
        self.conf = eval(open(conf_file).read())
        
        # check for those that have to be there
        assert "xmlsec_binary" in self.conf
        assert "service_url" in self.conf
        assert "entityid" in self.conf
        
        if "my_key" not in self.conf:
            self.conf["my_key"] = None
        else:
            # If you have a key file you have to have a cert file
            assert "my_cert" in self.conf
            
        if "metadata" in self.conf:
            md = MetaData()
            for mdfile in self.conf["metadata"]:
                md.import_metadata(open(mdfile).read())
            self.metadata = md
        else:
            self.metadata = None
        
        if "virtual_organization" in self.conf:
            if "nameid_format" not in self.conf:
                self.conf["nameid_format"] = NAMEID_FORMAT_TRANSIENT

        print "Configuration: %s" % (self.conf,)
        
    def _issuer(self):
        return {
            "format": saml.NAMEID_FORMAT_ENTITY,
            "text": self.conf["entityid"]
        }
        
    def _status(self, status, message=None, status_code=None):
        res = {
            "status_code": {
                "value": status,
            }
        }
        if message:
            res["status_message"] = message
        if status_code:
            res["status_code"].update(status_code)
        return res
        
    def create_attribute_assertion(self, subject, condition, ava=None):
        pass
        
    def create_response(self, in_response_to, status, assertion=None):
        pass
    