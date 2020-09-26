#!/usr/bin/env python

#
# Generated Thu Dec 12 18:16:51 2019 by parse_xsd.py version 0.5.
#

import saml2
from saml2 import SamlBase


NAMESPACE = 'http://eidas.europa.eu/saml-extensions'
class NodeCountryType_(SamlBase):
    """The http://eidas.europa.eu/saml-extensions:NodeCountryType element """

    c_tag = 'NodeCountryType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def node_country_type__from_string(xml_string):
    return saml2.create_class_from_xml_string(NodeCountryType_, xml_string)


class NodeCountry(NodeCountryType_):
    """The http://eidas.europa.eu/saml-extensions:NodeCountry element """

    c_tag = 'NodeCountry'
    c_namespace = NAMESPACE
    c_children = NodeCountryType_.c_children.copy()
    c_attributes = NodeCountryType_.c_attributes.copy()
    c_child_order = NodeCountryType_.c_child_order[:]
    c_cardinality = NodeCountryType_.c_cardinality.copy()

def node_country_from_string(xml_string):
    return saml2.create_class_from_xml_string(NodeCountry, xml_string)


ELEMENT_FROM_STRING = {
    NodeCountry.c_tag: node_country_from_string,
    NodeCountryType_.c_tag: node_country_type__from_string,
}

ELEMENT_BY_TAG = {
    'NodeCountry': NodeCountry,
    'NodeCountryType': NodeCountryType_,
}
def factory(tag, **kwargs):
    return ELEMENT_BY_TAG[tag](**kwargs)
