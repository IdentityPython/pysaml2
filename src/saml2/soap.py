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

"""
Suppport for the client part of the SAML2.0 SOAP binding.
"""

import httplib2
import urllib

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        from elementtree import ElementTree

from saml2.samlp import NAMESPACE as SAMLP_NAMESPACE

NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"

def parse_soap_enveloped_saml_response(text):
    expected_tag = '{%s}Response' % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, expected_tag)

def parse_soap_enveloped_saml_attribute_query(text):
    expected_tag = '{%s}AttributeQuery' % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, expected_tag)

def parse_soap_enveloped_saml_thingy(text, expected_tag):
    """Parses a SOAP enveloped SAML thing and returns the thing as
    a string.
    
    :param text: The SOAP object as XML 
    :param expected_tag: What the tag of the SAML thingy is expected to be.
    :return: SAML thingy as string
    """
    envelope = ElementTree.fromstring(text)
    assert envelope.tag == '{%s}Envelope' % NAMESPACE
    
    assert len(envelope) == 1
    body = envelope[0]
    assert body.tag == '{%s}Body' % NAMESPACE
    assert len(body) == 1
    saml_part = body[0]
    if saml_part.tag == expected_tag:
        return ElementTree.tostring(saml_part, encoding="UTF-8")
    else:
        return ""

def make_soap_enveloped_saml_thingy(thingy):
    """ Returns a soap envelope containing a SAML request
    as a text string.
    
    :param thingy: The SAML thingy
    :return: The SOAP envelope as a string
    """
    envelope = ElementTree.Element('')
    envelope.tag = '{%s}Envelope' % NAMESPACE

    body = ElementTree.Element('')
    body.tag = '{%s}Body' % NAMESPACE
    envelope.append(body)

    thingy.become_child_element(body)

    return ElementTree.tostring(envelope, encoding="UTF-8")

class _Http(object):
    """ For writing to a HTTP server using POST """
    def __init__(self, path, keyfile=None, certfile=None):
        self.path = path
        self.server = httplib2.Http()
        if keyfile:
            self.server.add_certificate(keyfile, certfile, "")

    def write(self, data):
        (response, content) = self.server.request(self.path, 
                            "POST", data,
                            headers={"content-type": "application/soap+xml"})
        if response.status == 200:
            return content
        else:
            return False

class SOAPClient(object):
    
    def __init__(self, server_url, keyfile=None, certfile=None):
        self.server = _Http(server_url, keyfile, certfile)
        
    def send(self, request):
        soap_message = make_soap_enveloped_saml_thingy(request)
        response = self.server.write(soap_message)
        if response:
            return parse_soap_enveloped_saml_response(response)


