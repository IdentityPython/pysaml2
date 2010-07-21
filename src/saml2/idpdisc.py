#!/usr/bin/env python

#
# Generated Mon Jul 12 22:05:35 2010 by parse_xsd.py version 0.2.
#

import saml2
from saml2 import SamlBase
from saml2 import md

NAMESPACE = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"

class DiscoveryResponse(md.IndexedEndpointType):
    """The idpdisc:DiscoveryResponse element"""
    c_tag = 'DiscoveryResponse'
    c_namespace = NAMESPACE
    
def discovery_response_from_string(xml_string):
    """ Create DiscoveryResponse instance from an XML string """
    return saml2.create_class_from_xml_string(DiscoveryResponse, xml_string)

ELEMENT_FROM_STRING = {
    DiscoveryResponse.c_tag: discovery_response_from_string,
}

ELEMENT_BY_TAG = {
    'DiscoveryResponse': DiscoveryResponse,
}

def factory(tag, **kwargs):
    return ELEMENT_BY_TAG[tag](**kwargs)

