#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2007 SIOS Technology, Inc.
# Copyright (C) 2009 Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains classes representing Metadata elements.

    Module objective: provide data classes for Metadata
    constructs. These classes hide the XML-ness of Saml and provide a
    set of native Python classes to interact with.

"""

from saml2 import saml, SamlBase, create_class_from_xml_string
from saml2.saml import Attribute
from saml2.saml import NAMESPACE as SAML_NAMESPACE
import xmldsig as ds
from xmldsig import NAMESPACE as DS_NAMESPACE
from xmlenc import NAMESPACE as XMLENC_NAMESPACE

NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:metadata'
#MD_TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:metadata}%s'
XML_TEMPLATE = '{http:#www.w3.org/XML/1998/namespace}%s'

DESCRIPTOR_CHOICE = ["role_descriptor", "idp_sso_descriptor", 
    "sp_sso_descriptor", 
#    "authn_authority_descriptor",
    "attribute_authority_descriptor", 
    "pdp_descriptor"
    ]
   
CONTACT_TYPES = ["technical", "support", "administrative", "billing", "other"]

def correct(element):
    """ Checks whether an element instance adhers to the standard 
    
    :param element: The element instance
    :return: Boolean True if it is according to the standard specification
        otherwise False.
    """
    
    if hasattr(element, "c_required_attributes"):
        for attr in element.c_required_attributes:
            if getattr(element, attr) == None:
                return False
    
    # go through the children
    for child in element.children_with_values():
        if correct(child) == False:
            return False
            
    if isinstance(element, EntitiesDescriptor):
        # The has to be at least one 
        if len(element.entity_descriptor) == 0 and \
            len(element.entities_descriptor) == 0:
            return False
    elif isinstance(element, EntityDescriptor):
        if len(element.affiliation_descriptor) > 1:
            return False
        elif len(element.affiliation_descriptor) == 1:
            for descriptor in DESCRIPTOR_CHOICE:
                if getattr(element, descriptor) != []:
                    return False
            return True
        else:
            for descriptor in DESCRIPTOR_CHOICE:
                if getattr(element, descriptor) != []:
                    return True
            return False
    elif isinstance(element, Organization):
        for prop in ["organizational_name", "organizational_display_name",
                        "organization_url"]:
            if getattr(element, prop) == []:
                return False
    elif isinstance(element, ContactPerson):
        for child in ["company", "givenname", "surname"]:
            if len(getattr(element, child)) > 1:
                return False
        if element.contact_type not in CONTACT_TYPES:
            return False
    elif isinstance(element, RoleDescriptor):
        for child in ["signature", "extensions", "organization"]:
            if len(getattr(element, child)) > 1:
                return False
    elif isinstance(element, KeyDescriptor):
        if element.key_info == []:
            return False
    elif isinstance(element, IDPSSODescriptor):
        if element.single_sign_on_service == []:
            return False
    elif isinstance(element, SPSSODescriptor):
        if element.assertion_consumer_service == []:
            return False
    elif isinstance(element, AttributeConsumingService):
        if element.service_name == []:
            return False
        if element.requested_attribute == []:
            return False
#    elif isinstance(element, AuthnAuthorityDescriptor):
#        if element.authn_query_service == []:
#            return False
    elif isinstance(element, PDPDescriptor):
        if element.authz_service == []:
            return False
    elif isinstance(element, AttributeAuthorityDescriptor):
        if element.attribute_service == []:
            return False
    elif isinstance(element, AffiliationDescriptor):
        if element.affiliate_member == []:
            return False
        if len(element.signature) > 1:
            return False
        if len(element.extensions) > 1:
            return False
    return True
            
class Extensions(SamlBase):
    """The md:Extensions element"""

    c_tag = 'Extensions'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def extensions_from_string(xml_string):
    """ Create Extensions instance from an XML string """
    return create_class_from_xml_string(Extensions, xml_string)

class LocalizedName(SamlBase):
    """The md:LocalizedName abstract type"""
    c_tag = 'LocalizedName'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes[XML_TEMPLATE % 'lang'] = 'lang'
    c_required_attributes = ["lang"]

    def __init__(self, lang=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for LocalizedName

        :param lang: xml:lang attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.lang = lang

def localized_name_from_string(xml_string):
    """ Create LocalizedName instance from an XML string """
    return create_class_from_xml_string(LocalizedName, xml_string)

class LocalizedURI(SamlBase):
    """The md:LocalizedURI abstract type"""
    c_tag = 'LocalizedURI'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes[XML_TEMPLATE % 'lang'] = 'lang'
    c_required_attributes = ["lang"]
    
    def __init__(self, lang=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for LocalizedURI

        :param lang: xml:lang attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.lang = lang

def localized_uri_from_string(xml_string):
    """ Create LocalizedURI instance from an XML string """
    return create_class_from_xml_string(LocalizedURI, xml_string)


class OrganizationName(LocalizedName):
    """The md:OrganizationName element"""
    c_tag = 'OrganizationName'
    c_namespace = NAMESPACE
    c_children = LocalizedName.c_children.copy()
    c_attributes = LocalizedName.c_attributes.copy()
    
    def __init__(self, lang=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for OrganizationName

        :param lang: xml:lang attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        LocalizedName.__init__(self, lang, text, extension_elements, 
                                extension_attributes)


def organization_name_from_string(xml_string):
    """ Create OrganizationName instance from an XML string """
    return create_class_from_xml_string(OrganizationName, xml_string)


class OrganizationDisplayName(LocalizedName):
    """The md:OrganizationDisplayName element"""
    c_tag = 'OrganizationDisplayName'
    c_namespace = NAMESPACE
    c_children = LocalizedName.c_children.copy()
    c_attributes = LocalizedName.c_attributes.copy()

    def __init__(self, lang=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for OrganizationDisplayName

        :param lang: xml:lang attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        LocalizedName.__init__(self, lang, text, extension_elements, 
                                extension_attributes)


def organization_display_name_from_string(xml_string):
    """ Create OrganizationDisplayName instance from an XML string """
    return create_class_from_xml_string(OrganizationDisplayName, xml_string)


class OrganizationURL(LocalizedURI):
    """The md:OrganizationURL element"""
    c_tag = 'OrganizationURL'
    c_namespace = NAMESPACE
    c_children = LocalizedURI.c_children.copy()
    c_attributes = LocalizedURI.c_attributes.copy()

    def __init__(self, lang=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for OrganizationURL

        :param lang: xml:lang attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        LocalizedURI.__init__(self, lang, text, extension_elements, 
                                extension_attributes)

def organization_url_from_string(xml_string):
    """ Create OrganizationURL instance from an XML string """
    return create_class_from_xml_string(OrganizationURL, xml_string)


class Organization(SamlBase):
    """The md:Organization base type"""

    c_tag = 'Organization'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}Extensions' % NAMESPACE] = ('extensions', Extensions)
    c_children['{%s}OrganizationName' % NAMESPACE] = (
        'organization_name', [OrganizationName])
    c_children['{%s}OrganizationDisplayName' % NAMESPACE] = (
        'organization_display_name', [OrganizationDisplayName])
    c_children['{%s}OrganizationURL' % NAMESPACE] = (
        'organization_url', [OrganizationURL])
    child_order = ['extensions', 'organization_name',
                    'organization_display_name', 'organization_url']

    def __init__(self, extensions=None, organization_name=None,
                organization_display_name=None, organization_url=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for Organization

        :param extensions: Extensions element
        :param organization_name: OrganizationName elements
        :param organization_display_name: OrganizationDisplayName elements
        :param organization_url: OrganizationURL elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.extensions = extensions
        self.organization_name = organization_name or []
        self.organization_display_name = organization_display_name or []
        self.organization_url = organization_url or []

def organization_from_string(xml_string):
    """ Create Organization instance from an XML string """
    return create_class_from_xml_string(Organization, xml_string)
    

class Endpoint(SamlBase):
    """The md:Endpoint base type"""

    c_tag = 'Endpoint'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Binding'] = 'binding'
    c_attributes['Location'] = 'location'
    c_attributes['ResponseLocation'] = 'response_location'
    c_required_attributes = ["binding", "location"]
    def __init__(self, binding=None, location=None, response_location=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for Endpoint

        :param binding: Binding attribute
        :param location: Location attribute
        :param response_location: ResponseLocation attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.binding = binding
        self.location = location
        self.response_location = response_location

def endpoint_from_string(xml_string):
    """ Create Endpoint instance from an XML string """
    return create_class_from_xml_string(Endpoint, xml_string)


# ---------------------------------------------------------------------------

class IndexedEndpoint(Endpoint):
    """The md:IndexedEndpoint base type"""

    c_tag = 'IndexedEndpoint'
    c_namespace = NAMESPACE
    c_children = Endpoint.c_children.copy()
    c_attributes = Endpoint.c_attributes.copy()
    c_attributes['index'] = 'index'
    c_attributes['isDefault'] = 'is_default'
    c_required_attributes = Endpoint.c_required_attributes[:]
    c_required_attributes.append("index")
    
    def __init__(self, index=None, is_default=None, binding=None, 
                location=None, response_location=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for IndexedEndpoint

        :param index: index attribute
        :param is_default: isDefault attribute
        :param binding: Binding attribute
        :param location: Location attribute
        :param response_location: ResponseLocation attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        Endpoint.__init__(self, binding, location, response_location,
                            text, extension_elements, extension_attributes)
        self.index = index
        self.is_default = is_default

def indexed_endpoint_from_string(xml_string):
    """ Create IndexedEndpoint instance from an XML string """
    return create_class_from_xml_string(IndexedEndpoint, xml_string)

# ---------------------------------------------------------------------------

class AuthzService(Endpoint):

    c_tag = 'AuthzService'
    c_namespace = NAMESPACE
    c_children = Endpoint.c_children.copy()
    c_attributes = Endpoint.c_attributes.copy()

    def __init__(self, binding=None, 
                location=None, response_location=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for AuthzService

        :param binding: Binding attribute
        :param location: Location attribute
        :param response_location: ResponseLocation attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        Endpoint.__init__(self, binding, location, response_location,
                            text, extension_elements, extension_attributes)

def authz_service_from_string(xml_string):
    """ Create AuthzService instance from an XML string """
    return create_class_from_xml_string(AuthzService, xml_string)

# ---------------------------------------------------------------------------

class AssertionIDRequestService(Endpoint):

    c_tag = 'AssertionIDRequestService'
    c_namespace = NAMESPACE
    c_children = Endpoint.c_children.copy()
    c_attributes = Endpoint.c_attributes.copy()

def assertion_id_request_service_from_string(xml_string):
    """ Create AssertionIDRequestService instance from an XML string """
    return create_class_from_xml_string(AssertionIDRequestService, xml_string)

# ---------------------------------------------------------------------------

class AuthnQueryService(Endpoint):

    c_tag = 'AuthnQueryService'
    c_namespace = NAMESPACE
    c_children = Endpoint.c_children.copy()
    c_attributes = Endpoint.c_attributes.copy()

def authn_query_service_from_string(xml_string):
    """ Create AuthnQueryService instance from an XML string """
    return create_class_from_xml_string(AuthnQueryService, xml_string)

# ---------------------------------------------------------------------------
    
class Company(SamlBase):
    """The md:Company element"""

    c_tag = 'Company'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def company_from_string(xml_string):
    """ Create Company instance from an XML string """
    return create_class_from_xml_string(Company, xml_string)

# ---------------------------------------------------------------------------

class GivenName(SamlBase):
    """The md:GivenName element"""

    c_tag = 'GivenName'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def given_name_from_string(xml_string):
    """ Create GivenName instance from an XML string """
    return create_class_from_xml_string(GivenName, xml_string)


class SurName(SamlBase):
    """The md:SurName element"""

    c_tag = 'SurName'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def sur_name_from_string(xml_string):
    """ Create SurName instance from an XML string """
    return create_class_from_xml_string(SurName, xml_string)


class EmailAddress(SamlBase):
    """The md:EmailAddress element"""

    c_tag = 'EmailAddress'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def email_address_from_string(xml_string):
    """ Create EmailAddress instance from an XML string """
    return create_class_from_xml_string(EmailAddress, xml_string)


class TelephoneNumber(SamlBase):
    """The md:TelephoneNumber element"""

    c_tag = 'TelephoneNumber'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def telephone_number_from_string(xml_string):
    """ Create TelephoneNumber instance from an XML string """
    return create_class_from_xml_string(TelephoneNumber, xml_string)


class ContactPerson(SamlBase):
    """The md:ContactPerson element"""

    c_tag = 'ContactPerson'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['contactType'] = 'contact_type'
    c_required_attributes = ["contact_type"]
    c_children['{%s}Extensions' % NAMESPACE] = ('extensions', Extensions)
    c_children['{%s}Company' % NAMESPACE] = ('company', Company)
    c_children['{%s}GivenName' % NAMESPACE] = ('given_name', GivenName)
    c_children['{%s}SurName' % NAMESPACE] = ('sur_name', SurName)
    c_children['{%s}EmailAddress' % NAMESPACE] = (
        'email_address', [EmailAddress])
    c_children['{%s}TelephoneNumber' % NAMESPACE] = (
        'telephone_number', [TelephoneNumber])
    c_child_order = ['extensions', 'company', 'given_name', 'sur_name',
                                    'email_address', 'telephone_number']

    def __init__(self, extensions=None, contact_type=None, company=None,
                given_name=None, sur_name=None, email_address=None,
                telephone_number=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for ContactPerson

        :param extensions: Extensions element
        :param contact_type: contactType attribute
        :param company: Company element
        :param given_name: GivenName element
        :param sur_name: SurName element
        :param email_address: EmailAddress elements
        :param telephone_number: TelephoneNumber elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.contact_type = contact_type
        self.extensions = extensions
        self.company = company
        self.given_name = given_name
        self.sur_name = sur_name
        self.email_address = email_address or []
        self.telephone_number = telephone_number or []

def contact_person_from_string(xml_string):
    """ Create ContactPerson instance from an XML string """
    return create_class_from_xml_string(ContactPerson, xml_string)


class AdditionalMetadataLocation(SamlBase):
    """The md:AdditionalMetadataLocation element"""

    c_tag = 'AdditionalMetadataLocation'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['namespace'] = 'namespace'
    c_required_attributes = ["namespace"]
    
    def __init__(self, namespace=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for AdditionalMetadataLocation

        :param namespace: namespace attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.namespace = namespace

def additional_metadata_location_from_string(xml_string):
    """ Create AdditionalMetadataLocation instance from an XML string """
    return create_class_from_xml_string(AdditionalMetadataLocation, xml_string)

    
class KeySize(SamlBase):
    """The xmlenc:KeySize element"""

    c_tag = 'KeySize'
    c_namespace = XMLENC_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def key_size_from_string(xml_string):
    """ Create KeySize instance from an XML string """
    return create_class_from_xml_string(KeySize, xml_string)


class OAEPparams(SamlBase):
    """The xmlenc:OAEPparams element"""

    c_tag = 'OAEPparams'
    c_namespace = XMLENC_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def oae_pparams_from_string(xml_string):
    """ Create OAEPparams instance from an XML string """
    return create_class_from_xml_string(OAEPparams, xml_string)


class EncryptionMethod(SamlBase):
    """The md:EncryptionMethod element"""

    c_tag = 'EncryptionMethod'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Algorithm'] = 'algorithm'
    c_children['{%s}KeySize' % XMLENC_NAMESPACE] = ('key_size', KeySize)
    c_children['{%s}OAEPparams' % XMLENC_NAMESPACE] = (
                    'oaep_params', OAEPparams)
    c_children['{%s}DigestMethod' % DS_NAMESPACE] = (
                    'digest_method', ds.DigestMethod)
    c_child_order = ['key_size', 'oaep_params', 'digest_method']

    def __init__(self, algorithm=None, key_size=None, digest_method=None,
                    oaep_params=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for EncryptionMethod

        :param algorithm: Algorithm attribute
        :param key_size: KeySize Element
        :param digest_method: DigestMethod Element
        :param oaep_params: OAEPparams Element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.algorithm = algorithm
        self.key_size = key_size
        self.digest_method = digest_method
        self.oaep_params = oaep_params

def encryption_method_from_string(xml_string):
    """ Create EncryptionMethod instance from an XML string """
    return create_class_from_xml_string(EncryptionMethod, xml_string)


class KeyDescriptor(SamlBase):
    """The md:KeyDescriptor element"""

    c_tag = 'KeyDescriptor'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['use'] = 'use'
    c_children['{%s}KeyInfo' % DS_NAMESPACE] = ('key_info', ds.KeyInfo)
    c_children['{%s}EncryptionMethod' % NAMESPACE] = (
        'encryption_method', [EncryptionMethod])
    c_child_order = ['key_info', 'encryption_method']
    c_required_child = ["key_info"]

    def __init__(self, use=None, key_info=None, encryption_method=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for KeyDescriptor

        :param use: use attribute
        :param key_info: KeyInfo element
        :param encryption_method: EncryptionMethod elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.use = use
        self.key_info = key_info
        self.encryption_method = encryption_method or []

def key_descriptor_from_string(xml_string):
    """ Create KeyDescriptor instance from an XML string """
    return create_class_from_xml_string(KeyDescriptor, xml_string)


class RoleDescriptor(SamlBase):
    """The md:RoleDescriptor element"""

    c_tag = 'RoleDescriptor'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['ID'] = 'id'
    c_attributes['validUntil'] = 'valid_until'
    c_attributes['cacheDuration'] = 'cache_duration'
    c_attributes['protocolSupportEnumeration'] = 'protocol_support_enumeration'
    c_attributes['errorURL'] = 'error_url'
    c_required_attributes = ["protocol_support_enumeration"]
    c_children['{%s}Signature' % DS_NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Extensions' % NAMESPACE] = ('extensions', Extensions)
    c_children['{%s}KeyDescriptor' % NAMESPACE] = (
                        'key_descriptor', [KeyDescriptor])
    c_children['{%s}Organization' % NAMESPACE] = (
                        'organization', Organization)
    c_children['{%s}ContactPerson' % NAMESPACE] = (
                        'contact_person', [ContactPerson])
    c_child_order = ['signature', 'extensions', 'key_descriptor', 
                        'organization', 'contact_person']

    def __init__(self, id=None, valid_until=None, cache_duration=None,
                    protocol_support_enumeration=None, error_url=None,
                    signature=None, extensions=None, key_descriptor=None,
                    organization=None, contact_person=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for RoleDescriptor

        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param protocol_support_enumeration: protocolSupportEnumeration attribute
        :param error_url: errorURL attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param key_descriptor: KeyDescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.id = id
        self.valid_until = valid_until
        self.cache_duration = cache_duration
        self.protocol_support_enumeration = protocol_support_enumeration
        self.error_url = error_url
        self.signature = signature
        self.extensions = extensions
        self.key_descriptor = key_descriptor or []
        self.organization = organization
        self.contact_person = contact_person or []
    
def role_descriptor_from_string(xml_string):
    """ Create RoleDescriptor instance from an XML string """
    return create_class_from_xml_string(RoleDescriptor, xml_string)

# ----------------------------------------------------------------------------


class ArtifactResolutionService(IndexedEndpoint):
    """The md:ArtifactResolutionService element"""
    c_tag = 'ArtifactResolutionService'

def artifact_resolution_service_from_string(xml_string):
    """ Create ArtifactResolutionService instance from an XML string """
    return create_class_from_xml_string(ArtifactResolutionService, xml_string)


class AssertionConsumerService(IndexedEndpoint):
    """The md:AssertionConsumerService element"""
    c_tag = 'AssertionConsumerService'

def assertion_consumer_service_from_string(xml_string):
    """ Create AssertionConsumerService instance from an XML string """
    return create_class_from_xml_string(AssertionConsumerService, xml_string)


class SingleLogoutService(Endpoint):
    """The md:SingleLogoutService element"""
    c_tag = 'SingleLogoutService'

def single_logout_service_from_string(xml_string):
    """ Create SingleLogoutService instance from an XML string """
    return create_class_from_xml_string(SingleLogoutService, xml_string)


class ManageNameIDService(Endpoint):
    """The md:ManageNameIDService element"""
    c_tag = 'ManageNameIDService'

def manage_name_id_service_from_string(xml_string):
    """ Create ManageNameIDService instance from an XML string """
    return create_class_from_xml_string(ManageNameIDService, xml_string)

# ---------------------------------------------------------------------------

class NameIDFormat(SamlBase):
    """The md:NameIDFormat element"""
    
    c_tag = 'NameIDFormat'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def name_id_format_from_string(xml_string):
    """ Create NameIDFormat instance from an XML string """
    return create_class_from_xml_string(NameIDFormat, xml_string)

# ---------------------------------------------------------------------------

class EntityIDType(SamlBase):
    """The md:entityIDType element"""
    
    c_tag = 'EntityIDType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def entity_id_type_from_string(xml_string):
    """ Create EntityIDType instance from an XML string """
    return create_class_from_xml_string(EntityIDType, xml_string)

# ---------------------------------------------------------------------------

class AffiliateMember(EntityIDType):
    """The md:AffiliateMember element"""
    
    c_tag = 'AffiliateMember'
    c_namespace = NAMESPACE
    c_children = EntityIDType.c_children.copy()
    c_attributes = EntityIDType.c_attributes.copy()

def affiliate_member_from_string(xml_string):
    """ Create AffiliateMember instance from an XML string """
    return create_class_from_xml_string(AffiliateMember, xml_string)

# ---------------------------------------------------------------------------

class PDPDescriptor(RoleDescriptor):
    """The md:PDPDescriptor element"""

    c_tag = 'PDPDescriptor'
    c_namespace = NAMESPACE
    c_children = RoleDescriptor.c_children.copy()
    c_attributes = RoleDescriptor.c_attributes.copy()
    c_children['{%s}AuthnQueryService' % NAMESPACE] = (
        'authn_query_service', [AuthnQueryService])
    c_children['{%s}AssertionIDRequestService' % NAMESPACE] = (
        'assertion_id_request_service', [AssertionIDRequestService])
    c_children['{%s}NameIDFormat' % NAMESPACE] = (
        'name_id_format', [NameIDFormat])
    c_child_order = RoleDescriptor.c_child_order[:]
    c_child_order.extend(['authn_query_service', 
                    'assertion_id_request_service',
                    'name_id_format'])

    def __init__(self, authn_query_service=None,
                    assertion_id_request_service=None,
                    name_id_format=None, id=None, valid_until=None, 
                    cache_duration=None, protocol_support_enumeration=None, 
                    error_url=None, signature=None, extensions=None, 
                    key_descriptor=None, organization=None, 
                    contact_person=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for SSODescriptor

        :param authn_query_service: ArtifactResolutionService elements
        :param assertion_id_request_service: SingleLogoutService elements
        :param name_id_format: NameIDFormat elements
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param protocol_support_enumeration: protocolSupportEnumeration attribute
        :param error_url: errorURL attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param key_descriptor: KeyDescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        RoleDescriptor.__init__(self, id, valid_until, cache_duration,
                        protocol_support_enumeration, error_url, signature, 
                        extensions, key_descriptor, organization, 
                        contact_person, text, extension_elements, 
                        extension_attributes)
        
        self.authn_query_service = authn_query_service or []
        self.assertion_id_request_service = assertion_id_request_service or []
        self.name_id_format = name_id_format or []

def pdp_descriptor_from_string(xml_string):
    """ Create PDPDescriptor instance from an XML string """
    return create_class_from_xml_string(PDPDescriptor, xml_string)

# ---------------------------------------------------------------------------

class SSODescriptor(RoleDescriptor):
    """The md:SSODescriptor element"""

    c_tag = 'SSODescriptor'
    c_namespace = NAMESPACE
    c_children = RoleDescriptor.c_children.copy()
    c_attributes = RoleDescriptor.c_attributes.copy()
    c_children['{%s}ArtifactResolutionService' % NAMESPACE] = (
        'artifact_resolution_service', [ArtifactResolutionService])
    c_children['{%s}SingleLogoutService' % NAMESPACE] = (
        'single_logout_service', [SingleLogoutService])
    c_children['{%s}ManageNameIDService' % NAMESPACE] = (
        'manage_name_id_service', [ManageNameIDService])
    c_children['{%s}NameIDFormat' % NAMESPACE] = (
        'name_id_format', [NameIDFormat])
    c_child_order = RoleDescriptor.c_child_order[:]
    c_child_order.extend(['artifact_resolution_service', 
                    'single_logout_service', 'manage_name_id_service', 
                    'name_id_format'])

    def __init__(self, artifact_resolution_service=None,
                    single_logout_service=None, manage_name_id_service=None,
                    name_id_format=None, id=None, valid_until=None, 
                    cache_duration=None, protocol_support_enumeration=None, 
                    error_url=None, signature=None, extensions=None, 
                    key_descriptor=None, organization=None, 
                    contact_person=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for SSODescriptor

        :param artifact_resolution_service: ArtifactResolutionService elements
        :param single_logout_service: SingleLogoutService elements
        :param manage_name_id_service: ManageNameIDService elements
        :param name_id_format: NameIDFormat elements
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param protocol_support_enumeration: protocolSupportEnumeration attribute
        :param error_url: errorURL attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param key_descriptor: KeyDescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        RoleDescriptor.__init__(self, id, valid_until, cache_duration,
                        protocol_support_enumeration, error_url, signature, 
                        extensions, key_descriptor, organization, 
                        contact_person, text, extension_elements, 
                        extension_attributes)
        
        self.artifact_resolution_service = artifact_resolution_service or []
        self.single_logout_service = single_logout_service or []
        self.manage_name_id_service = manage_name_id_service or []
        self.name_id_format = name_id_format or []

def sso_descriptor_from_string(xml_string):
    """ Create SSODescriptor instance from an XML string """
    return create_class_from_xml_string(SSODescriptor, xml_string)


class SingleSignOnService(Endpoint):
    """The md:SingleSignOnService element"""
    c_tag = 'SingleSignOnService'

def single_sign_on_service_from_string(xml_string):
    """ Create SingleSignOnService instance from an XML string """
    return create_class_from_xml_string(SingleSignOnService, xml_string)


class NameIDMappingService(Endpoint):
    """The md:NameIDMappingService element"""
    c_tag = 'NameIDMappingService'

def name_id_mapping_service_from_string(xml_string):
    """ Create NameIDMappingService instance from an XML string """
    return create_class_from_xml_string(NameIDMappingService, xml_string)


class AssertionIDRequestService(Endpoint):
    """The md:AssertionIDRequestService element"""
    c_tag = 'AssertionIDRequestService'

def assertion_id_request_service_from_string(xml_string):
    """ Create AssertionIDRequestService instance from an XML string """
    return create_class_from_xml_string(AssertionIDRequestService, xml_string)

class AttributeService(Endpoint):
    """The md:AttributeService element"""
    c_tag = 'AttributeService'

def attribute_service_from_string(xml_string):
    """ Create AttributeService instance from an XML string """
    return create_class_from_xml_string(AttributeService, xml_string)

# ----------------------------------------------------------------------------

class AttributeProfile(SamlBase):
    """The md:AttributeProfile element"""
    
    c_tag = 'AttributeProfile'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def attribute_profile_from_string(xml_string):
    """ Create AttributeProfile instance from an XML string """
    return create_class_from_xml_string(AttributeProfile, xml_string)

# ----------------------------------------------------------------------------

class IDPSSODescriptor(SSODescriptor):
    """The md:IDPSSODescriptor element"""

    c_tag = 'IDPSSODescriptor'
    c_namespace = NAMESPACE
    c_children = SSODescriptor.c_children.copy()
    c_attributes = SSODescriptor.c_attributes.copy()
    c_attributes['WantAuthnRequestsSigned'] = 'want_authn_requests_signed'
    c_children['{%s}SingleSignOnService' % NAMESPACE] = (
        'single_sign_on_service', [SingleSignOnService])
    c_children['{%s}NameIDMappingService' % NAMESPACE] = (
        'name_id_mapping_service', [NameIDMappingService])
    c_children['{%s}AssertionIDRequestService' % NAMESPACE] = (
        'assertion_id_request_service', [AssertionIDRequestService])
    c_children['{%s}AttributeProfile' % NAMESPACE] = (
        'attribute_profile', [AttributeProfile])
    c_children['{%s}Attribute' % SAML_NAMESPACE] = (
        'attribute', [Attribute])

    c_child_order = SSODescriptor.c_child_order[:]
    c_child_order.extend(['single_sign_on_service', 'name_id_mapping_service', 
                    'assertion_id_request_service', 'attribute_profile', 
                    'attribute'])

    def __init__(self, want_authn_requests_signed=None, 
                    single_sign_on_service=None, name_id_mapping_service=None,
                    assertion_id_request_service=None, attribute_profile=None,
                    attribute=None, artifact_resolution_service=None,
                    single_logout_service=None, manage_name_id_service=None,
                    name_id_format=None,
                    id=None, valid_until=None, cache_duration=None,
                    protocol_support_enumeration=None, error_url=None,
                    signature=None, extensions=None, key_descriptor=None,
                    organization=None, contact_person=None,
                    text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for IDPSSODescriptor

        :param want_authn_requests_signed: WantAuthnRequestsSigned attribute
        :param single_sign_on_service: SingleSignOnService elements
        :param name_id_mapping_service: NameIDMappingService elements
        :param assertion_id_request_service: AssertionIDRequestService elements
        :param attribute_profile: AttributeProfile elements
        :param attribute: Attribute elements
        :param artifact_resolution_service: ArtifactResolutionService elements
        :param single_logout_service: SingleLogoutService elements
        :param manage_name_id_service: ManageNameIDService elements
        :param name_id_format: NameIDFormat elements
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param protocol_support_enumeration: protocolSupportEnumeration attribute
        :param error_url: errorURL attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param key_descriptor: KeyDescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SSODescriptor.__init__(self, artifact_resolution_service,
                        single_logout_service, manage_name_id_service,
                        name_id_format, id, valid_until, 
                        cache_duration, protocol_support_enumeration, 
                        error_url, signature, extensions, key_descriptor, 
                        organization, contact_person, text, extension_elements, 
                        extension_attributes)

        self.want_authn_requests_signed = want_authn_requests_signed
        self.single_sign_on_service = single_sign_on_service or []
        self.name_id_mapping_service = name_id_mapping_service or []
        self.assertion_id_request_service = assertion_id_request_service or []
        self.attribute_profile = attribute_profile or []
        self.attribute = attribute or []

def idpsso_descriptor_from_string(xml_string):
    """ Create IDPSSODescriptor instance from an XML string """
    return create_class_from_xml_string(IDPSSODescriptor, xml_string)


class RequestedAttribute(Attribute):

    c_tag = 'RequestedAttribute'
    c_namespace = NAMESPACE
    c_children = Attribute.c_children.copy()
    c_attributes = Attribute.c_attributes.copy()
    c_attributes['isRequired'] = 'is_required'

    def __init__(self, is_required=None, name=None, name_format=None, 
                    friendly_name=None, attribute_value=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for RequestedAttribute

        :param is_required: isRequired attribute
        :param name: Name attribute
        :param name_format: NameFormat attribute
        :param friendly_name: FriendlyName attribute
        :param attribute_value: AttributeValue elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        Attribute.__init__(self, name, name_format, friendly_name,
                            attribute_value, text, extension_elements,
                            extension_attributes)
        self.is_required = is_required

def requested_attribute_from_string(xml_string):
    """ Create RequestedAttribute instance from an XML string """
    return create_class_from_xml_string(RequestedAttribute, xml_string)


class ServiceName(LocalizedName):
    """The md:ServiceName element"""
    c_tag = 'ServiceName'
    c_namespace = NAMESPACE
    c_children = LocalizedName.c_children.copy()
    c_attributes = LocalizedName.c_attributes.copy()

    def __init__(self, lang=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for ServiceName

        :param lang: xml:lang attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        LocalizedName.__init__(self, lang, text, extension_elements, 
                                extension_attributes)

def service_name_from_string(xml_string):
    """ Create ServiceName instance from an XML string """
    return create_class_from_xml_string(ServiceName, xml_string)


class ServiceDescription(LocalizedName):
    """The md:ServiceDescription element"""
    c_tag = 'ServiceDescription'
    c_namespace = NAMESPACE
    c_children = LocalizedName.c_children.copy()
    c_attributes = LocalizedName.c_attributes.copy()

    def __init__(self, lang=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for ServiceDescription

        :param lang: xml:lang attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        LocalizedName.__init__(self, lang, text, extension_elements, 
                                extension_attributes)

def service_description_from_string(xml_string):
    """ Create ServiceDescription instance from an XML string """
    return create_class_from_xml_string(ServiceDescription, xml_string)


class AttributeConsumingService(SamlBase):
    """The md:AttributeConsumingService element"""
    
    c_tag = 'AttributeConsumingService'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['index'] = 'index'
    c_attributes['isDefault'] = 'is_default'
    c_required_attributes = ["index"]
    c_children['{%s}ServiceName' % NAMESPACE] = (
                    'service_name', [ServiceName])
    c_children['{%s}ServiceDescription' % NAMESPACE] = (
                    'service_description', [ServiceDescription])
    c_children['{%s}RequestedAttribute' % NAMESPACE] = (
                    'requested_attribute', [RequestedAttribute])
    c_child_order = ['service_name', 'service_description', 
                    'requested_attribute']

    def __init__(self, index=None, is_default=None, service_name=None,
                    service_description=None, requested_attribute=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for AttributeConsumingService

        :param index: index attribute
        :param is_default: isDefault attribute
        :param service_name: ServiceName elements
        :param service_descriptor: ServiceDescriptor elements
        :param requested_attribute: RequestedAttribute elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.index = index
        self.is_default = is_default
        self.service_name = service_name or []
        self.service_description = service_description or []
        self.requested_attribute = requested_attribute or []

def attribute_consuming_service_from_string(xml_string):
    """ Create AttributeConsumingService instance from an XML string """
    return create_class_from_xml_string(AttributeConsumingService, xml_string)


class SPSSODescriptor(SSODescriptor):
    """The md:SPSSODescriptor element"""

    c_tag = 'SPSSODescriptor'
    c_namespace = NAMESPACE
    c_children = SSODescriptor.c_children.copy()
    c_attributes = SSODescriptor.c_attributes.copy()
    c_attributes['AuthnRequestsSigned'] = 'authn_requests_signed'
    c_attributes['WantAssertionsSigned'] = 'want_assertions_signed'
    c_children['{%s}AssertionConsumerService' % NAMESPACE] = (
        'assertion_consumer_service', [AssertionConsumerService])
    c_children['{%s}AttributeConsumingService' % NAMESPACE] = (
        'attribute_consuming_service', [AttributeConsumingService])

    c_child_order = SSODescriptor.c_child_order[:]    
    c_child_order.extend(['assertion_consumer_service', 
                    'attribute_consuming_service'])

    def __init__(self, id=None, valid_until=None, cache_duration=None,
                    protocol_support_enumeration=None, error_url=None,
                    signature=None, extensions=None, key_descriptor=None,
                    organization=None, contact_person=None,
                    artifact_resolution_service=None,
                    single_logout_service=None, manage_name_id_service=None,
                    name_id_format=None, authn_requests_signed=None,
                    want_assertions_signed=None, 
                    assertion_consumer_service=None,
                    attribute_consuming_service=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for IDPSSODescriptor

        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param protocol_support_enumeration: protocolSupportEnumeration 
            attribute
        :param error_url: errorURL attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param key_descriptor: KeyDescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param artifact_resolution_service: ArtifactResolutionService elements
        :param single_logout_service: SingleLogoutService elements
        :param manage_name_id_service: ManageNameIDService elements
        :param name_id_format: NameIDFormat elements
        :param authn_requests_signed: AuthnRequestsSigned attribute
        :param want_assertions_signed: WantAssertionsSigned attribute
        :param assertion_consumer_service: AssertionConsumerService elements
        :param attribute_consuming_service: AttributeConsumingService elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """
        SSODescriptor.__init__(self, artifact_resolution_service,
                        single_logout_service, manage_name_id_service,
                        name_id_format, id, valid_until, 
                        cache_duration, protocol_support_enumeration, 
                        error_url, signature, 
                        extensions, key_descriptor, organization, 
                        contact_person, text, extension_elements, 
                        extension_attributes)

        self.authn_requests_signed = authn_requests_signed
        self.want_assertions_signed = want_assertions_signed
        self.assertion_consumer_service = assertion_consumer_service or []
        self.attribute_consuming_service = attribute_consuming_service or []

def spsso_descriptor_from_string(xml_string):
    """ Create SPSSODescriptor instance from an XML string """
    return create_class_from_xml_string(SPSSODescriptor, xml_string)

# ----------------------------------------------------------------------------

class AttributeAuthorityDescriptor(RoleDescriptor):
    """The md:AttributeAuthorityDescriptor element"""

    c_tag = 'AttributeAuthorityDescriptor'
    c_namespace = NAMESPACE
    c_children = RoleDescriptor.c_children.copy()
    c_attributes = RoleDescriptor.c_attributes.copy()
    c_child_order = RoleDescriptor.c_child_order[:]

    c_children['{%s}AttributeService' % NAMESPACE] = (
        'attribute_service', [AttributeService])
    c_children['{%s}AssertionIDRequestService' % NAMESPACE] = (
        'assertion_id_request_service', [AssertionIDRequestService])
    c_children['{%s}NameIDFormat' % NAMESPACE] = (
        'name_id_format', [NameIDFormat])
    c_children['{%s}AttributeProfile' % NAMESPACE] = (
        'attribute_profile', [AttributeProfile])
    c_children['{%s}Attribute' % saml.NAMESPACE] = (
        'attribute', [saml.Attribute])

    c_child_order.extend(["attribute_service", "assertion_id_request_service",
                            "name_id_format", "attribute_profile",
                            "attribute"])

    def __init__(self, attribute_service=None,
                    assertion_id_request_service=None, name_id_format=None,
                    attribute_profile=None, attribute=None,
                    id=None, valid_until=None, 
                    cache_duration=None, protocol_support_enumeration=None, 
                    error_url=None, signature=None, extensions=None, 
                    key_descriptor=None, organization=None, 
                    contact_person=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for AttributeAuthorityDescriptor

        :param attribute_service: ArtifactResolutionService elements
        :param assertion_id_request_service: SingleLogoutService elements
        :param name_id_format: NameIDFormat elements
        :param attribute_profile: 
        :param attribute:
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param protocol_support_enumeration: protocolSupportEnumeration attribute
        :param error_url: errorURL attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param key_descriptor: KeyDescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        RoleDescriptor.__init__(self, id, valid_until, cache_duration,
                        protocol_support_enumeration, error_url, signature, 
                        extensions, key_descriptor, organization, 
                        contact_person, text, extension_elements, 
                        extension_attributes)

        self.attribute_service = attribute_service or []
        self.assertion_id_request_service = assertion_id_request_service or []
        self.name_id_format = name_id_format or []
        self.attribute_profile = attribute_profile or []
        self.attribute = attribute or []

def attribute_authority_descriptor_from_string(xml_string):
    """ Create AttributeAuthorityDescriptor instance from an XML string """
    return create_class_from_xml_string(AttributeAuthorityDescriptor, 
                                        xml_string)

# ---------------------------------------------------------------------------

class AffiliationDescriptor(SamlBase):
    """The md:AffiliationDescriptor element"""

    c_tag = 'AffiliationDescriptor'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['affiliationOwnerID'] = 'affiliation_owner_id'
    c_attributes['ID'] = 'id'
    c_attributes['validUntil'] = 'valid_until'
    c_attributes['cacheDuration'] = 'cache_duration'
    c_required_attributes = ["affiliation_owner_id"]
    c_children['{%s}Signature' % DS_NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Extensions' % NAMESPACE] = ('extensions', Extensions)
    c_children['{%s}AffiliateMember' % NAMESPACE] = (
                'affiliate_member', [AffiliateMember])
    c_children['{%s}KeyDescriptor' % NAMESPACE] = (
                'key_descriptor', [KeyDescriptor])
    c_child_order = ['signature', 'extensions', 'affiliate_member',
                    'key_descriptor']
 
    def __init__(self, affiliation_owner_id=None, id=None, 
                    valid_until=None, cache_duration=None, 
                    signature=None, extensions=None, 
                    affiliate_member=None, key_descriptor=None, 
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for AffiliationDescriptor

        :param affiliation_owner_id: entityID attribute
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param affiliate_member: RoleDescriptor elements
        :param key_descriptor: IDPSSODescriptor elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.affiliation_owner_id = affiliation_owner_id
        self.id = id
        self.valid_until = valid_until
        self.cache_duration = cache_duration
        self.signature = signature
        self.extensions = extensions
        self.affiliate_member = affiliate_member or []
        self.key_descriptor = key_descriptor or []
    
def affiliation_descriptor_from_string(xml_string):
    """ Create AffiliationDescriptor instance from an XML string """
    return create_class_from_xml_string(AffiliationDescriptor, xml_string)

# ---------------------------------------------------------------------------

class AuthnAuthorityDescriptor(RoleDescriptor):

    c_tag = 'AuthnAuthorityDescriptor'
    c_namespace = NAMESPACE
    c_children = RoleDescriptor.c_children.copy()
    c_attributes = RoleDescriptor.c_attributes.copy()


    c_children['{%s}AuthnQueryService' % NAMESPACE] = (
            'authn_query_service', AuthnQueryService)
    c_children['{%s}AssertionIDRequestService' % NAMESPACE] = (
            'assertion_id_request_service', AssertionIDRequestService)
    c_children['{%s}NameIDFormat' % NAMESPACE] = (
            'name_id_format', NameIDFormat)
    c_child_order = RoleDescriptor.c_child_order[:]
    c_child_order.extend(["authn_query_service",
            "assertion_id_request_service", "name_id_format"])
    
    def __init__(self, authn_query_service=None,
                    assertion_id_request_service=None, name_id_format=None,
                    attribute_profile=None, attribute=None,
                    id=None, valid_until=None, 
                    cache_duration=None, protocol_support_enumeration=None, 
                    error_url=None, signature=None, extensions=None, 
                    key_descriptor=None, organization=None, 
                    contact_person=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for AttributeAuthorityDescriptor

        :param authn_query_service: ArtifactResolutionService elements
        :param assertion_id_request_service: SingleLogoutService elements
        :param name_id_format: NameIDFormat elements
        :param attribute_profile: 
        :param attribute:
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param protocol_support_enumeration: protocolSupportEnumeration attribute
        :param error_url: errorURL attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param key_descriptor: KeyDescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        RoleDescriptor.__init__(self, id, valid_until, cache_duration,
                        protocol_support_enumeration, error_url, signature, 
                        extensions, key_descriptor, organization, 
                        contact_person, text, extension_elements, 
                        extension_attributes)

        self.authn_query_service = authn_query_service or []
        self.assertion_id_request_service = assertion_id_request_service or []
        self.name_id_format = name_id_format or []
        
def authn_authority_descriptor_from_string(xml_string):
    """ Create AuthnAuthorityDescriptor instance from an XML string """
    return create_class_from_xml_string(AuthnAuthorityDescriptor, xml_string)

# ---------------------------------------------------------------------------


class EntityDescriptor(SamlBase):
    """The md:EntityDescriptor element"""
    # TODO: AuthnAuthorityDescriptor, AttributeAuthorityDescriptor, 
    # PDPDescriptor,

    c_tag = 'EntityDescriptor'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['entityID'] = 'entity_id'
    c_attributes['ID'] = 'id'
    c_attributes['validUntil'] = 'valid_until'
    c_attributes['cacheDuration'] = 'cache_duration'
    c_required_attributes = ["entity_id"]
    c_children['{%s}Signature' % DS_NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Extensions' % NAMESPACE] = ('extensions', Extensions)
    c_children['{%s}RoleDescriptor' % NAMESPACE] = (
                                    'role_descriptor', [RoleDescriptor])
    c_children['{%s}IDPSSODescriptor' % NAMESPACE] = (
                                    'idp_sso_descriptor', [IDPSSODescriptor])
    c_children['{%s}SPSSODescriptor' % NAMESPACE] = (
                                    'sp_sso_descriptor', [SPSSODescriptor])
    c_children['{%s}Organization' % NAMESPACE] = (
                                    'organization', Organization)
    c_children['{%s}ContactPerson' % NAMESPACE] = (
                                    'contact_person', [ContactPerson])
    c_children['{%s}AdditionalMetadataLocation' % NAMESPACE] = (
                'additional_metadata_location', [AdditionalMetadataLocation])
    c_children['{%s}AttributeAuthorityDescriptor' % NAMESPACE] = (
                'attribute_authority_descriptor', 
                [AttributeAuthorityDescriptor])
    c_children['{%s}AffiliationDescriptor' % NAMESPACE] = (
                'affiliation_descriptor', [AffiliationDescriptor])
    c_child_order = ['signature', 'extensions', 'role_descriptor',
                    'idp_sso_descriptor', 'sp_sso_descriptor', 'organization', 
                    'contact_person', 'additional_metadata_location',
                    'attribute_authority_descriptor',
                    'affiliation_descriptor']

    def __init__(self, entity_id=None, id=None, valid_until=None,
                    cache_duration=None, signature=None, extensions=None, 
                    role_descriptor=None, idp_sso_descriptor=None, 
                    sp_sso_descriptor=None, organization=None, 
                    contact_person=None, additional_metadata_location=None,
                    attribute_authority_descriptor=None,
                    affiliation_descriptor=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for EntityDescriptor

        :param entity_id: entityID attribute
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param role_descriptor: RoleDescriptor elements
        :param idp_sso_descriptor: IDPSSODescriptor elements
        :param sp_sso_descriptor: SPSSODescriptor elements
        :param organization: Organization element
        :param contact_person: ContactPerson elements
        :param additional_metadata_location: AdditionalMetadataLocation elements
        :param affiliation_descriptor:
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.entity_id = entity_id
        self.id = id
        self.valid_until = valid_until
        self.cache_duration = cache_duration
        self.signature = signature
        self.extensions = extensions
        self.role_descriptor = role_descriptor or []
        self.idp_sso_descriptor = idp_sso_descriptor or []
        self.sp_sso_descriptor = sp_sso_descriptor or []
        self.organization = organization
        self.contact_person = contact_person or []
        self.additional_metadata_location = additional_metadata_location or []
        self.attribute_authority_descriptor = \
                attribute_authority_descriptor or []
        self.affiliation_descriptor = affiliation_descriptor or []
        
def entity_descriptor_from_string(xml_string):
    """ Create EntityDescriptor instance from an XML string """
    return create_class_from_xml_string(EntityDescriptor, xml_string)


class EntitiesDescriptor(SamlBase):
    """The md:EntitiesDescriptor element"""

    c_tag = 'EntitiesDescriptor'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['name'] = 'name'
    c_attributes['ID'] = 'id'
    c_attributes['validUntil'] = 'valid_until'
    c_attributes['cacheDuration'] = 'cache_duration'
    c_children['{%s}Signature' % DS_NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Extensions' % NAMESPACE] = ('extensions', Extensions)
    c_children['{%s}EntityDescriptor' % NAMESPACE] = (
        'entity_descriptor', [EntityDescriptor])
    # Entities desciption further down
    c_child_order = ['signature', 'extensions', 'entity_descriptor',
                                    'entities_descriptor']
    c_required_child = ["entity_descriptor"]
    
    def __init__(self, name=None, id=None, valid_until=None, 
                    cache_duration=None, signature=None, extensions=None,
                    entity_descriptor=None, entities_descriptor=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for EntitiesDescriptor

        :param name: name attribute
        :param id: ID attribute
        :param valid_until: validUntil attribute
        :param cache_duration: cacheDuration attribute
        :param signature: ds:Signature element
        :param extensions: Extensions element
        :param entity_descriptor: EntityDescriptor elements
        :param entities_descriptor: EntitiesDescriptor elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.name = name
        self.id = id
        self.valid_until = valid_until
        self.cache_duration = cache_duration
        self.signature = signature
        self.extensions = extensions
        self.entity_descriptor = entity_descriptor or []
        self.entities_descriptor = entities_descriptor or []

EntitiesDescriptor.c_children['{%s}EntitiesDescriptor' % NAMESPACE] = (
        'entities_descriptor', [EntitiesDescriptor])
    
def entities_descriptor_from_string(xml_string):
    """ Create EntitiesDescriptor instance from an XML string """
    return create_class_from_xml_string(EntitiesDescriptor, xml_string)

# ---------------------------------------------------------------------------

IDPDISC = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"

class DiscoveryResponse(IndexedEndpoint):
    """The idpdisc:DiscoveryResponse element"""
    c_tag = 'DiscoveryResponse'
    c_namespace = IDPDISC
    
def discovery_response_from_string(xml_string):
    """ Create DiscoveryResponse instance from an XML string """
    return create_class_from_xml_string(DiscoveryResponse, xml_string)

# ---------------------------------------------------------------------------

ELEMENT_FROM_STRING = {
    DiscoveryResponse.c_tag: discovery_response_from_string,
    Extensions.c_tag: extensions_from_string,
    LocalizedName.c_tag: localized_name_from_string,
    LocalizedURI.c_tag: localized_uri_from_string,
    OrganizationName.c_tag: organization_name_from_string,
    OrganizationDisplayName.c_tag: organization_display_name_from_string,
    OrganizationURL.c_tag: organization_url_from_string,
    Organization.c_tag: organization_from_string,
    Endpoint.c_tag: endpoint_from_string,
    IndexedEndpoint.c_tag: indexed_endpoint_from_string,
    AuthzService.c_tag: authz_service_from_string,
    AssertionIDRequestService.c_tag: assertion_id_request_service_from_string,
    AuthnQueryService.c_tag: authn_query_service_from_string,
    Company.c_tag: company_from_string,
    GivenName.c_tag: given_name_from_string,
    SurName.c_tag: sur_name_from_string,
    EmailAddress.c_tag: email_address_from_string,
    TelephoneNumber.c_tag: telephone_number_from_string,
    ContactPerson.c_tag: contact_person_from_string,
    AdditionalMetadataLocation.c_tag: additional_metadata_location_from_string,
    KeySize.c_tag: key_size_from_string,
    OAEPparams.c_tag: oae_pparams_from_string,
    EncryptionMethod.c_tag: encryption_method_from_string,
    KeyDescriptor.c_tag: key_descriptor_from_string,
    RoleDescriptor.c_tag: role_descriptor_from_string,
    ArtifactResolutionService.c_tag: artifact_resolution_service_from_string,
    AssertionConsumerService.c_tag: assertion_consumer_service_from_string,
    SingleLogoutService.c_tag: single_logout_service_from_string,
    ManageNameIDService.c_tag: manage_name_id_service_from_string,
    NameIDFormat.c_tag: name_id_format_from_string,
    EntityIDType.c_tag: entity_id_type_from_string,
    AffiliateMember.c_tag: affiliate_member_from_string,
    PDPDescriptor.c_tag: pdp_descriptor_from_string,
    SSODescriptor.c_tag: sso_descriptor_from_string,
    SingleSignOnService.c_tag: single_sign_on_service_from_string,
    NameIDMappingService.c_tag: name_id_mapping_service_from_string,
    AssertionIDRequestService.c_tag: assertion_id_request_service_from_string,
    AttributeService.c_tag: attribute_service_from_string,
    AttributeProfile.c_tag: attribute_profile_from_string,
    IDPSSODescriptor.c_tag: idpsso_descriptor_from_string,
    RequestedAttribute.c_tag: requested_attribute_from_string,
    ServiceName.c_tag: service_name_from_string,
    ServiceDescription.c_tag: service_description_from_string,
    AttributeConsumingService.c_tag: attribute_consuming_service_from_string,
    SPSSODescriptor.c_tag: spsso_descriptor_from_string,
    AttributeAuthorityDescriptor.c_tag: attribute_authority_descriptor_from_string,
    AffiliationDescriptor.c_tag: affiliation_descriptor_from_string,
    AuthnAuthorityDescriptor.c_tag: authn_authority_descriptor_from_string,
    EntityDescriptor.c_tag: entity_descriptor_from_string,
    EntitiesDescriptor.c_tag: entities_descriptor_from_string,
}

