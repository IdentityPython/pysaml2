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

"""
Contains classes representing SAML Metadata Documentation and 
Registration Information Extensions
"""

import saml2
from saml2 import SamlBase

NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata:dri"

#-----------------------------------------------
# <element name=”CreationInstant” type=”datetime” />
#-----------------------------------------------

class CreationInstant(SamlBase):
    """The dri:CreationInstant element"""

    c_tag = 'CreationInstant'
    c_type = "datetime"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def creation_instant_from_string(xml_string):
    """ Create CreationInstant instance from an XML string """
    return saml2.create_class_from_xml_string(CreationInstant, xml_string)

#----------------------------------------------------------------------------
# <element name=”SerialNumber” type=”string” />
#----------------------------------------------------------------------------

class SerialNumber(SamlBase):
    """The dri:SerialNumber element"""

    c_tag = 'SerialNumber'
    c_type = "string"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def serial_number_instant_from_string(xml_string):
    """ Create SerialNumber instance from an XML string """
    return saml2.create_class_from_xml_string(SerialNumber, xml_string)

#----------------------------------------------------------------------------
# <element name=”UsagePolicy” type=”anyURI” />
#----------------------------------------------------------------------------

class UsagePolicy(SamlBase):
    """The dri:UsagePolicy element"""

    c_tag = 'UsagePolicy'
    c_type = "anyURI"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def usage_policy_instant_from_string(xml_string):
    """ Create UsagePolicy instance from an XML string """
    return saml2.create_class_from_xml_string(UsagePolicy, xml_string)

#----------------------------------------------------------------------------
# <element name=”Publisher” type=”dri:PublisherType”/>
# <complexType name=”PublisherType”>
#    <attribute name=”PublisherID” type=”md:entityIDType” use=”required” />
#    <attribute name=”CreationInstant” type=”datetime” />
#    <attribute name=”SerialNumber” type=”string”/>
# </complexType>
#----------------------------------------------------------------------------

class Publisher(SamlBase):
    """The dri:Publisher element"""

    c_tag = 'Publisher'
    c_type = "anyURI"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
#    c_attributes['PublisherID'] = ('publisher_id', "md:entityIDType")
    c_attributes['PublisherID'] = 'publisher_id'
    c_attributes['CreationInstant'] = 'creation_instant'
    c_attributes['SerialNumber'] = 'serial_number'

    def __init__(self, publisher_id=None, creation_instant=None, 
                    serial_number=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for Publisher

        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs.
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.publisher_id = publisher_id
        self.creation_instant = creation_instant
        self.serial_number = serial_number

def publisher_instant_from_string(xml_string):
    """ Create Publisher instance from an XML string """
    return saml2.create_class_from_xml_string(Publisher, xml_string)

#-----------------------------------------------
#<element DocumentInfo type=”dri:DocumentInfoType” />
#<complexType name=”DocumentInfoType”>
#   <sequence>
#      <element ref=”dri:CreationInstant” minOccurs=”0”/>
#      <element ref=”dri:SerialNumber” minOccurs=”0” />
#      <element ref=”dri:UsagePolicy” minOccurs=”0” />
#      <element ref=”dri:Publishers” minOccurs=”0” />
#   </sequence>
#</complexType>

class DocumentInfo(SamlBase):
    """The dri:DocumentInfo element"""

    c_tag = 'DocumentInfo'
    c_type = "complex"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}CreationInstant' % NAMESPACE] = (
                        'creation_instant', CreationInstant)
    c_children['{%s}SerialNumber' % NAMESPACE] = (
                        'serial_number', SerialNumber)
    c_children['{%s}UsagePolicy' % NAMESPACE] = (
                        'usage_policy', UsagePolicy)
    c_children['{%s}Publishers' % NAMESPACE] = (
                        'publishers', Publishers)
    c_child_order = ["creation_instant", "serial_number", 
                    "usage_policy", "publishers"]

    def __init__(self, creation_instant=None, serial_number=None, 
                    usage_policy=None, publishers=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for UsagePolicy, an extension point that allows 
        applications to add new kinds of identifiers.

        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs.
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.creation_instant = creation_instant
        self.serial_number = serial_number
        self.usage_policy = usage_policy
        self.publishers = publishers

def document_info_instant_from_string(xml_string):
    """ Create DocumentInfo instance from an XML string """
    return saml2.create_class_from_xml_string(DocumentInfo, xml_string)


# ---------------------------------------------------------------------------
# <element name=”RegistrationAuthority” type=”md:entityIDType” />
# ---------------------------------------------------------------------------

class RegistrationAuthority(SamlBase):
    """The dri:RegistrationAuthority element"""

    c_tag = 'RegistrationAuthority'
    c_type = "md:entityIDType"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def registration_authority_instant_from_string(xml_string):
    """ Create RegistrationAuthority instance from an XML string """
    return saml2.create_class_from_xml_string(RegistrationAuthority, xml_string)

# ---------------------------------------------------------------------------
# <element name=”RegistrationInstant” type=”datetime” />
# ---------------------------------------------------------------------------

class RegistrationInstant(SamlBase):
    """The dri:RegistrationInstant element"""

    c_tag = 'RegistrationInstant'
    c_type = "datetime"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def registration_instant_instant_from_string(xml_string):
    """ Create RegistrationInstant instance from an XML string """
    return saml2.create_class_from_xml_string(RegistrationInstant, xml_string)

# ---------------------------------------------------------------------------
# <element name=”RegistrationPolicy” type=”anyURI” />
# ---------------------------------------------------------------------------

class RegistrationPolicy(SamlBase):
    """The dri:RegistrationPolicy element"""

    c_tag = 'RegistrationPolicy'
    c_type = "anyURI"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def registration_policy_instant_from_string(xml_string):
    """ Create RegistrationPolicy instance from an XML string """
    return saml2.create_class_from_xml_string(RegistrationPolicy, xml_string)

# ---------------------------------------------------------------------------
# <element name=”RegistrationInfo” type=”dri:RegistrationInfoType” />
# <complexType name=”RegistrationInfoType”>
#    <sequence>
#       <element ref=”dri:RegistrationAuthority” />
#       <element ref=”dri:RegistrationInstant” />
#       <element ref=”dri:RegistrationPolicy” minOccurs=”0” />
#    </sequence>
# </complexType>
# ---------------------------------------------------------------------------

class RegistrationInfo(SamlBase):
    """The dri:RegistrationInfo element"""

    c_tag = 'RegistrationInfo'
    c_type = "complex"
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}RegistrationAuthority' % NAMESPACE] = (
                        'registration_authority', RegistrationAuthority)
    c_children['{%s}RegistrationInstant' % NAMESPACE] = (
                        'registration_instant', RegistrationInstant)
    c_children['{%s}RegistrationPolicy' % NAMESPACE] = (
                        'registration_policy', RegistrationPolicy)
    c_child_order = ["registration_authority", "registration_instant", 
                    "registration_policy"]

    def __init__(self, registration_authority=None, registration_instant=None, 
                    registration_policy=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for UsagePolicy, an extension point that allows 
        applications to add new kinds of identifiers.

        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs.
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.registration_authority = registration_authority
        self.registration_instant = registration_instant
        self.registration_policy = registration_policy

def registration_info_instant_from_string(xml_string):
    """ Create RegistrationInfo instance from an XML string """
    return saml2.create_class_from_xml_string(RegistrationInfo, xml_string)
