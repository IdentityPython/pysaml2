#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Umeå University
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

"""Contains classes and functions that are necessary to implement 
different bindings.

Bindings normally consists of three parts:
- rules about what to send 
- how to package the information
- which protocol to use
"""
import httplib2

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        from elementtree import ElementTree

from saml2.samlp import NAMESPACE as SAMLP_NAMESPACE

import saml2

NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"

def http_post(authn_request, sp_entity_id=None, relay_state=None):
    response = []
    response.append("<head>")
    response.append("""<title>SAML 2.0 POST</title>""")
    response.append("</head><body>")
    #login_url = location + '?spentityid=' + "lingon.catalogix.se"
    response.append(FORM_SPEC % (location, base64.b64encode(authen_req),
                        os.environ['REQUEST_URI']))
    response.append("""<script type="text/javascript">""")
    response.append("     window.onload = function ()")
    response.append(" { document.forms[0].submit(); ")
    response.append("""</script>""")
    response.append("</body>")
    
    return ([], response)
    
def http_redirect(authn_request, sp_entity_id, relay_state):
    lista = ["SAMLRequest=%s" % urllib.quote_plus(
                        deflate_and_base64_encode(
                            authen_req)),
            "spentityid=%s" % sp_entity_id]
    if relay_state:
        lista.append("RelayState=%s" % relay_state)
    login_url = "?".join([location, "&".join(lista)])
    headers = [('Location', login_url)]
    response = []
    
    return (headers, response)

def make_soap_enveloped_saml_thingy(thingy, header_parts=None):
    """ Returns a soap envelope containing a SAML request
    as a text string.

    :param thingy: The SAML thingy
    :return: The SOAP envelope as a string
    """
    envelope = ElementTree.Element('')
    envelope.tag = '{%s}Envelope' % NAMESPACE

    if header_parts:
        header = ElementTree.Element('')
        header.tag = '{%s}Header' % NAMESPACE
        envelope.append(header)
        for part in header_parts:
            part.become_child_element_of(header)

    body = ElementTree.Element('')
    body.tag = '{%s}Body' % NAMESPACE
    envelope.append(body)

    thingy.become_child_element_of(body)

    return ElementTree.tostring(envelope, encoding="UTF-8")

def http_soap(authn_request, sp_entity_id, relay_state):
    return ({"content-type": "application/soap+xml"},
            make_soap_enveloped_saml_thingy(authn_request))
    
def http_paos(authn_request, sp_entity_id, relay_state, extra=None):
    return ({"content-type": "application/soap+xml"},
            make_soap_enveloped_saml_thingy(authn_request, extra))
    
def parse_soap_enveloped_saml(text, body_class, header_class=None):
    """Parses a SOAP enveloped SAML thing and returns header parts and body

    :param text: The SOAP object as XML 
    :return: header parts and body as saml.samlbase instances
    """
    envelope = ElementTree.fromstring(text)
    assert envelope.tag == '{%s}Envelope' % NAMESPACE

    print len(envelope)
    body = None
    header = {}
    for part in envelope:
        print ">",part.tag
        if part.tag == '{%s}Body' % NAMESPACE:
            for sub in part:
                try:
                    body = saml2.create_class_from_element_tree(body_class, sub)
                except Exception, exc:
                    print exc
                    print body_class.c_tag
                    raise Exception(
                            "Wrong body type (%s) in SOAP envelope" % sub.tag)
        elif part.tag == '{%s}Header' % NAMESPACE:
            if not header_class:
                raise Exception("Header where I didn't expect one")
            print "--- HEADER ---"
            for sub in part:
                print ">>",sub.tag
                for klass in header_class:
                    print "?{%s}%s" % (klass.c_namespace,klass.c_tag)
                    if sub.tag == "{%s}%s" % (klass.c_namespace,klass.c_tag):
                        header[sub.tag] = \
                            saml2.create_class_from_element_tree(klass, sub)
                        break
                        
    return body, header

# -----------------------------------------------------------------------------

PACKING = {
    saml2.BINDING_HTTP_REDIRECT: http_redirect,
    saml2.BINDING_HTTP_POST: http_post,
    }
    
def packager( identifier ):
    try:
        return PACKING[identifier]
    except KeyError:
        raise Exception("Unkown binding type: %s" % binding)