#!/usr/bin/env python

#
# Generated Sat Jul 17 11:11:48 2010 by parse_xsd.py version 0.3.
#

import saml2
from saml2 import SamlBase

from saml2 import saml
import xmldsig as ds
import xmlenc as xenc

NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:metadata'

class entityIDType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:entityIDType element """

    c_tag = 'entityIDType'
    c_namespace = NAMESPACE
    c_value_type = {'maxlen': '1024', 'base': 'anyURI'}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def entity_id_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(entityIDType, xml_string)

class localizedNameType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:localizedNameType element """

    c_tag = 'localizedNameType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['{http://www.w3.org/XML/1998/namespace}lang'] = ('lang', '', True)

    def __init__(self,
            lang=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.lang=lang

def localized_name_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(localizedNameType, xml_string)

class localizedURIType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:localizedURIType element """

    c_tag = 'localizedURIType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['{http://www.w3.org/XML/1998/namespace}lang'] = ('lang', '', True)

    def __init__(self,
            lang=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.lang=lang

def localized_uri_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(localizedURIType, xml_string)

class ExtensionsType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ExtensionsType element """

    c_tag = 'ExtensionsType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def extensions_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ExtensionsType, xml_string)

class EndpointType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:EndpointType element """

    c_tag = 'EndpointType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['Binding'] = ('binding', 'anyURI', True)
    c_attributes['Location'] = ('location', 'anyURI', True)
    c_attributes['ResponseLocation'] = ('response_location', 'anyURI', False)

    def __init__(self,
            binding=None,
            location=None,
            response_location=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.binding=binding
        self.location=location
        self.response_location=response_location

def endpoint_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(EndpointType, xml_string)

class IndexedEndpointType(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:IndexedEndpointType element """

    c_tag = 'IndexedEndpointType'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]
    c_attributes['index'] = ('index', 'unsignedShort', True)
    c_attributes['isDefault'] = ('is_default', 'boolean', False)

    def __init__(self,
            index=None,
            is_default=None,
            binding=None,
            location=None,
            response_location=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        EndpointType.__init__(self, 
                binding=binding,
                location=location,
                response_location=response_location,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.index=index
        self.is_default=is_default

def indexed_endpoint_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(IndexedEndpointType, xml_string)

class OrganizationName(localizedNameType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:OrganizationName element """

    c_tag = 'OrganizationName'
    c_namespace = NAMESPACE
    c_children = localizedNameType.c_children.copy()
    c_attributes = localizedNameType.c_attributes.copy()
    c_child_order = localizedNameType.c_child_order[:]

def organization_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(OrganizationName, xml_string)

class OrganizationDisplayName(localizedNameType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:OrganizationDisplayName element """

    c_tag = 'OrganizationDisplayName'
    c_namespace = NAMESPACE
    c_children = localizedNameType.c_children.copy()
    c_attributes = localizedNameType.c_attributes.copy()
    c_child_order = localizedNameType.c_child_order[:]

def organization_display_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(OrganizationDisplayName, xml_string)

class OrganizationURL(localizedURIType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:OrganizationURL element """

    c_tag = 'OrganizationURL'
    c_namespace = NAMESPACE
    c_children = localizedURIType.c_children.copy()
    c_attributes = localizedURIType.c_attributes.copy()
    c_child_order = localizedURIType.c_child_order[:]

def organization_url_from_string(xml_string):
    return saml2.create_class_from_xml_string(OrganizationURL, xml_string)

class Company(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:Company element """

    c_tag = 'Company'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def company_from_string(xml_string):
    return saml2.create_class_from_xml_string(Company, xml_string)

class GivenName(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:GivenName element """

    c_tag = 'GivenName'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def given_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(GivenName, xml_string)

class SurName(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:SurName element """

    c_tag = 'SurName'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def sur_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(SurName, xml_string)

class EmailAddress(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:EmailAddress element """

    c_tag = 'EmailAddress'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def email_address_from_string(xml_string):
    return saml2.create_class_from_xml_string(EmailAddress, xml_string)

class TelephoneNumber(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:TelephoneNumber element """

    c_tag = 'TelephoneNumber'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def telephone_number_from_string(xml_string):
    return saml2.create_class_from_xml_string(TelephoneNumber, xml_string)

class ContactTypeType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ContactTypeType element """

    c_tag = 'ContactTypeType'
    c_namespace = NAMESPACE
    c_value_type = {'base': 'string', 'enumeration': ['technical', 'support', 'administrative', 'billing', 'other']}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def contact_type_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ContactTypeType, xml_string)

class AdditionalMetadataLocationType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AdditionalMetadataLocationType element """

    c_tag = 'AdditionalMetadataLocationType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['namespace'] = ('namespace', 'anyURI', True)

    def __init__(self,
            namespace=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.namespace=namespace

def additional_metadata_location_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AdditionalMetadataLocationType, xml_string)

class anyURIListType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:anyURIListType element """

    c_tag = 'anyURIListType'
    c_namespace = NAMESPACE
    c_value_type = {'member': 'anyURI', 'base': 'list'}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def any_uri_list_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(anyURIListType, xml_string)

class KeyTypes(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:KeyTypes element """

    c_tag = 'KeyTypes'
    c_namespace = NAMESPACE
    c_value_type = {'base': 'string', 'enumeration': ['encryption', 'signing']}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def key_types_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyTypes, xml_string)

class EncryptionMethod(xenc.EncryptionMethodType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:EncryptionMethod element """

    c_tag = 'EncryptionMethod'
    c_namespace = NAMESPACE
    c_children = xenc.EncryptionMethodType.c_children.copy()
    c_attributes = xenc.EncryptionMethodType.c_attributes.copy()
    c_child_order = xenc.EncryptionMethodType.c_child_order[:]

def encryption_method_from_string(xml_string):
    return saml2.create_class_from_xml_string(EncryptionMethod, xml_string)

class ArtifactResolutionService(IndexedEndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ArtifactResolutionService element """

    c_tag = 'ArtifactResolutionService'
    c_namespace = NAMESPACE
    c_children = IndexedEndpointType.c_children.copy()
    c_attributes = IndexedEndpointType.c_attributes.copy()
    c_child_order = IndexedEndpointType.c_child_order[:]

def artifact_resolution_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(ArtifactResolutionService, xml_string)

class SingleLogoutService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:SingleLogoutService element """

    c_tag = 'SingleLogoutService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def single_logout_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(SingleLogoutService, xml_string)

class ManageNameIDService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ManageNameIDService element """

    c_tag = 'ManageNameIDService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def manage_name_id_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(ManageNameIDService, xml_string)

class NameIDFormat(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:NameIDFormat element """

    c_tag = 'NameIDFormat'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def name_id_format_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDFormat, xml_string)

class SingleSignOnService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:SingleSignOnService element """

    c_tag = 'SingleSignOnService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def single_sign_on_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(SingleSignOnService, xml_string)

class NameIDMappingService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:NameIDMappingService element """

    c_tag = 'NameIDMappingService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def name_id_mapping_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDMappingService, xml_string)

class AssertionIDRequestService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AssertionIDRequestService element """

    c_tag = 'AssertionIDRequestService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def assertion_id_request_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(AssertionIDRequestService, xml_string)

class AttributeProfile(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AttributeProfile element """

    c_tag = 'AttributeProfile'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def attribute_profile_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeProfile, xml_string)

class AssertionConsumerService(IndexedEndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AssertionConsumerService element """

    c_tag = 'AssertionConsumerService'
    c_namespace = NAMESPACE
    c_children = IndexedEndpointType.c_children.copy()
    c_attributes = IndexedEndpointType.c_attributes.copy()
    c_child_order = IndexedEndpointType.c_child_order[:]

def assertion_consumer_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(AssertionConsumerService, xml_string)

class ServiceName(localizedNameType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ServiceName element """

    c_tag = 'ServiceName'
    c_namespace = NAMESPACE
    c_children = localizedNameType.c_children.copy()
    c_attributes = localizedNameType.c_attributes.copy()
    c_child_order = localizedNameType.c_child_order[:]

def service_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(ServiceName, xml_string)

class ServiceDescription(localizedNameType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ServiceDescription element """

    c_tag = 'ServiceDescription'
    c_namespace = NAMESPACE
    c_children = localizedNameType.c_children.copy()
    c_attributes = localizedNameType.c_attributes.copy()
    c_child_order = localizedNameType.c_child_order[:]

def service_description_from_string(xml_string):
    return saml2.create_class_from_xml_string(ServiceDescription, xml_string)

class RequestedAttributeType(saml.AttributeType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:RequestedAttributeType element """

    c_tag = 'RequestedAttributeType'
    c_namespace = NAMESPACE
    c_children = saml.AttributeType.c_children.copy()
    c_attributes = saml.AttributeType.c_attributes.copy()
    c_child_order = saml.AttributeType.c_child_order[:]
    c_attributes['isRequired'] = ('is_required', 'boolean', False)

    def __init__(self,
            is_required=None,
            friendly_name=None,
            name=None,
            name_format=None,
            attribute_value=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        saml.AttributeType.__init__(self, 
                friendly_name=friendly_name,
                name=name,
                name_format=name_format,
                attribute_value=attribute_value,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.is_required=is_required

def requested_attribute_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(RequestedAttributeType, xml_string)

class AuthnQueryService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AuthnQueryService element """

    c_tag = 'AuthnQueryService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def authn_query_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnQueryService, xml_string)

class AuthzService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AuthzService element """

    c_tag = 'AuthzService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def authz_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthzService, xml_string)

class AttributeService(EndpointType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AttributeService element """

    c_tag = 'AttributeService'
    c_namespace = NAMESPACE
    c_children = EndpointType.c_children.copy()
    c_attributes = EndpointType.c_attributes.copy()
    c_child_order = EndpointType.c_child_order[:]

def attribute_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeService, xml_string)

class AffiliateMember(entityIDType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AffiliateMember element """

    c_tag = 'AffiliateMember'
    c_namespace = NAMESPACE
    c_children = entityIDType.c_children.copy()
    c_attributes = entityIDType.c_attributes.copy()
    c_child_order = entityIDType.c_child_order[:]

def affiliate_member_from_string(xml_string):
    return saml2.create_class_from_xml_string(AffiliateMember, xml_string)

class Extensions(ExtensionsType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:Extensions element """

    c_tag = 'Extensions'
    c_namespace = NAMESPACE
    c_children = ExtensionsType.c_children.copy()
    c_attributes = ExtensionsType.c_attributes.copy()
    c_child_order = ExtensionsType.c_child_order[:]

def extensions_from_string(xml_string):
    return saml2.create_class_from_xml_string(Extensions, xml_string)

class OrganizationType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:OrganizationType element """

    c_tag = 'OrganizationType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Extensions'] = ('extensions', Extensions)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationName'] = ('organization_name', [OrganizationName])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationDisplayName'] = ('organization_display_name', [OrganizationDisplayName])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationURL'] = ('organization_url', [OrganizationURL])
    c_child_order.extend(['extensions', 'organization_name', 'organization_display_name', 'organization_url'])

    def __init__(self,
            extensions=None,
            organization_name=None,
            organization_display_name=None,
            organization_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.extensions=extensions
        self.organization_name=organization_name or []
        self.organization_display_name=organization_display_name or []
        self.organization_url=organization_url or []

def organization_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(OrganizationType, xml_string)

class ContactType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ContactType element """

    c_tag = 'ContactType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Extensions'] = ('extensions', Extensions)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Company'] = ('company', Company)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}GivenName'] = ('given_name', GivenName)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}SurName'] = ('sur_name', SurName)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}EmailAddress'] = ('email_address', [EmailAddress])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}TelephoneNumber'] = ('telephone_number', [TelephoneNumber])
    c_attributes['contactType'] = ('contact_type', 'ContactTypeType', True)
    c_child_order.extend(['extensions', 'company', 'given_name', 'sur_name', 'email_address', 'telephone_number'])

    def __init__(self,
            extensions=None,
            company=None,
            given_name=None,
            sur_name=None,
            email_address=None,
            telephone_number=None,
            contact_type=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.extensions=extensions
        self.company=company
        self.given_name=given_name
        self.sur_name=sur_name
        self.email_address=email_address or []
        self.telephone_number=telephone_number or []
        self.contact_type=contact_type

def contact_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ContactType, xml_string)

class AdditionalMetadataLocation(AdditionalMetadataLocationType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AdditionalMetadataLocation element """

    c_tag = 'AdditionalMetadataLocation'
    c_namespace = NAMESPACE
    c_children = AdditionalMetadataLocationType.c_children.copy()
    c_attributes = AdditionalMetadataLocationType.c_attributes.copy()
    c_child_order = AdditionalMetadataLocationType.c_child_order[:]

def additional_metadata_location_from_string(xml_string):
    return saml2.create_class_from_xml_string(AdditionalMetadataLocation, xml_string)

class KeyDescriptorType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:KeyDescriptorType element """

    c_tag = 'KeyDescriptorType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{http://www.w3.org/2000/09/xmldsig#}KeyInfo'] = ('key_info', ds.KeyInfo)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}EncryptionMethod'] = ('encryption_method', [EncryptionMethod])
    c_attributes['use'] = ('use', 'KeyTypes', False)
    c_child_order.extend(['key_info', 'encryption_method'])

    def __init__(self,
            key_info=None,
            encryption_method=None,
            use=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.key_info=key_info
        self.encryption_method=encryption_method or []
        self.use=use

def key_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyDescriptorType, xml_string)

class RequestedAttribute(RequestedAttributeType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:RequestedAttribute element """

    c_tag = 'RequestedAttribute'
    c_namespace = NAMESPACE
    c_children = RequestedAttributeType.c_children.copy()
    c_attributes = RequestedAttributeType.c_attributes.copy()
    c_child_order = RequestedAttributeType.c_child_order[:]

def requested_attribute_from_string(xml_string):
    return saml2.create_class_from_xml_string(RequestedAttribute, xml_string)

class Organization(OrganizationType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:Organization element """

    c_tag = 'Organization'
    c_namespace = NAMESPACE
    c_children = OrganizationType.c_children.copy()
    c_attributes = OrganizationType.c_attributes.copy()
    c_child_order = OrganizationType.c_child_order[:]

def organization_from_string(xml_string):
    return saml2.create_class_from_xml_string(Organization, xml_string)

class ContactPerson(ContactType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:ContactPerson element """

    c_tag = 'ContactPerson'
    c_namespace = NAMESPACE
    c_children = ContactType.c_children.copy()
    c_attributes = ContactType.c_attributes.copy()
    c_child_order = ContactType.c_child_order[:]

def contact_person_from_string(xml_string):
    return saml2.create_class_from_xml_string(ContactPerson, xml_string)

class KeyDescriptor(KeyDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:KeyDescriptor element """

    c_tag = 'KeyDescriptor'
    c_namespace = NAMESPACE
    c_children = KeyDescriptorType.c_children.copy()
    c_attributes = KeyDescriptorType.c_attributes.copy()
    c_child_order = KeyDescriptorType.c_child_order[:]

def key_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyDescriptor, xml_string)

class RoleDescriptorType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:RoleDescriptorType element """

    c_tag = 'RoleDescriptorType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{http://www.w3.org/2000/09/xmldsig#}Signature'] = ('signature', ds.Signature)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Extensions'] = ('extensions', Extensions)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor'] = ('key_descriptor', [KeyDescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Organization'] = ('organization', Organization)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}ContactPerson'] = ('contact_person', [ContactPerson])
    c_attributes['ID'] = ('id', 'ID', False)
    c_attributes['validUntil'] = ('valid_until', 'dateTime', False)
    c_attributes['cacheDuration'] = ('cache_duration', 'duration', False)
    c_attributes['protocolSupportEnumeration'] = ('protocol_support_enumeration', 'anyURIListType', True)
    c_attributes['errorURL'] = ('error_url', 'anyURI', False)
    c_child_order.extend(['signature', 'extensions', 'key_descriptor', 'organization', 'contact_person'])

    def __init__(self,
            signature=None,
            extensions=None,
            key_descriptor=None,
            organization=None,
            contact_person=None,
            id=None,
            valid_until=None,
            cache_duration=None,
            protocol_support_enumeration=None,
            error_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.signature=signature
        self.extensions=extensions
        self.key_descriptor=key_descriptor or []
        self.organization=organization
        self.contact_person=contact_person or []
        self.id=id
        self.valid_until=valid_until
        self.cache_duration=cache_duration
        self.protocol_support_enumeration=protocol_support_enumeration
        self.error_url=error_url

def role_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(RoleDescriptorType, xml_string)

class SSODescriptorType(RoleDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:SSODescriptorType element """

    c_tag = 'SSODescriptorType'
    c_namespace = NAMESPACE
    c_children = RoleDescriptorType.c_children.copy()
    c_attributes = RoleDescriptorType.c_attributes.copy()
    c_child_order = RoleDescriptorType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}ArtifactResolutionService'] = ('artifact_resolution_service', [ArtifactResolutionService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService'] = ('single_logout_service', [SingleLogoutService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}ManageNameIDService'] = ('manage_name_id_service', [ManageNameIDService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat'] = ('name_id_format', [NameIDFormat])
    c_child_order.extend(['artifact_resolution_service', 'single_logout_service', 'manage_name_id_service', 'name_id_format'])

    def __init__(self,
            artifact_resolution_service=None,
            single_logout_service=None,
            manage_name_id_service=None,
            name_id_format=None,
            signature=None,
            extensions=None,
            key_descriptor=None,
            organization=None,
            contact_person=None,
            id=None,
            valid_until=None,
            cache_duration=None,
            protocol_support_enumeration=None,
            error_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RoleDescriptorType.__init__(self, 
                signature=signature,
                extensions=extensions,
                key_descriptor=key_descriptor,
                organization=organization,
                contact_person=contact_person,
                id=id,
                valid_until=valid_until,
                cache_duration=cache_duration,
                protocol_support_enumeration=protocol_support_enumeration,
                error_url=error_url,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.artifact_resolution_service=artifact_resolution_service or []
        self.single_logout_service=single_logout_service or []
        self.manage_name_id_service=manage_name_id_service or []
        self.name_id_format=name_id_format or []

def sso_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SSODescriptorType, xml_string)

class IDPSSODescriptorType(SSODescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:IDPSSODescriptorType element """

    c_tag = 'IDPSSODescriptorType'
    c_namespace = NAMESPACE
    c_children = SSODescriptorType.c_children.copy()
    c_attributes = SSODescriptorType.c_attributes.copy()
    c_child_order = SSODescriptorType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService'] = ('single_sign_on_service', [SingleSignOnService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}NameIDMappingService'] = ('name_id_mapping_service', [NameIDMappingService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AssertionIDRequestService'] = ('assertion_id_request_service', [AssertionIDRequestService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AttributeProfile'] = ('attribute_profile', [AttributeProfile])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'] = ('attribute', [saml.Attribute])
    c_attributes['WantAuthnRequestsSigned'] = ('want_authn_requests_signed', 'boolean', False)
    c_child_order.extend(['single_sign_on_service', 'name_id_mapping_service', 'assertion_id_request_service', 'attribute_profile', 'attribute'])

    def __init__(self,
            single_sign_on_service=None,
            name_id_mapping_service=None,
            assertion_id_request_service=None,
            attribute_profile=None,
            attribute=None,
            want_authn_requests_signed=None,
            artifact_resolution_service=None,
            single_logout_service=None,
            manage_name_id_service=None,
            name_id_format=None,
            signature=None,
            extensions=None,
            key_descriptor=None,
            organization=None,
            contact_person=None,
            id=None,
            valid_until=None,
            cache_duration=None,
            protocol_support_enumeration=None,
            error_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SSODescriptorType.__init__(self, 
                artifact_resolution_service=artifact_resolution_service,
                single_logout_service=single_logout_service,
                manage_name_id_service=manage_name_id_service,
                name_id_format=name_id_format,
                signature=signature,
                extensions=extensions,
                key_descriptor=key_descriptor,
                organization=organization,
                contact_person=contact_person,
                id=id,
                valid_until=valid_until,
                cache_duration=cache_duration,
                protocol_support_enumeration=protocol_support_enumeration,
                error_url=error_url,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.single_sign_on_service=single_sign_on_service or []
        self.name_id_mapping_service=name_id_mapping_service or []
        self.assertion_id_request_service=assertion_id_request_service or []
        self.attribute_profile=attribute_profile or []
        self.attribute=attribute or []
        self.want_authn_requests_signed=want_authn_requests_signed

def idpsso_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(IDPSSODescriptorType, xml_string)

class AttributeConsumingServiceType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AttributeConsumingServiceType element """

    c_tag = 'AttributeConsumingServiceType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}ServiceName'] = ('service_name', [ServiceName])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}ServiceDescription'] = ('service_description', [ServiceDescription])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}RequestedAttribute'] = ('requested_attribute', [RequestedAttribute])
    c_attributes['index'] = ('index', 'unsignedShort', True)
    c_attributes['isDefault'] = ('is_default', 'boolean', False)
    c_child_order.extend(['service_name', 'service_description', 'requested_attribute'])

    def __init__(self,
            service_name=None,
            service_description=None,
            requested_attribute=None,
            index=None,
            is_default=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.service_name=service_name or []
        self.service_description=service_description or []
        self.requested_attribute=requested_attribute or []
        self.index=index
        self.is_default=is_default

def attribute_consuming_service_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeConsumingServiceType, xml_string)

class AuthnAuthorityDescriptorType(RoleDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AuthnAuthorityDescriptorType element """

    c_tag = 'AuthnAuthorityDescriptorType'
    c_namespace = NAMESPACE
    c_children = RoleDescriptorType.c_children.copy()
    c_attributes = RoleDescriptorType.c_attributes.copy()
    c_child_order = RoleDescriptorType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AuthnQueryService'] = ('authn_query_service', [AuthnQueryService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AssertionIDRequestService'] = ('assertion_id_request_service', [AssertionIDRequestService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat'] = ('name_id_format', [NameIDFormat])
    c_child_order.extend(['authn_query_service', 'assertion_id_request_service', 'name_id_format'])

    def __init__(self,
            authn_query_service=None,
            assertion_id_request_service=None,
            name_id_format=None,
            signature=None,
            extensions=None,
            key_descriptor=None,
            organization=None,
            contact_person=None,
            id=None,
            valid_until=None,
            cache_duration=None,
            protocol_support_enumeration=None,
            error_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RoleDescriptorType.__init__(self, 
                signature=signature,
                extensions=extensions,
                key_descriptor=key_descriptor,
                organization=organization,
                contact_person=contact_person,
                id=id,
                valid_until=valid_until,
                cache_duration=cache_duration,
                protocol_support_enumeration=protocol_support_enumeration,
                error_url=error_url,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.authn_query_service=authn_query_service or []
        self.assertion_id_request_service=assertion_id_request_service or []
        self.name_id_format=name_id_format or []

def authn_authority_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnAuthorityDescriptorType, xml_string)

class PDPDescriptorType(RoleDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:PDPDescriptorType element """

    c_tag = 'PDPDescriptorType'
    c_namespace = NAMESPACE
    c_children = RoleDescriptorType.c_children.copy()
    c_attributes = RoleDescriptorType.c_attributes.copy()
    c_child_order = RoleDescriptorType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AuthzService'] = ('authz_service', [AuthzService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AssertionIDRequestService'] = ('assertion_id_request_service', [AssertionIDRequestService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat'] = ('name_id_format', [NameIDFormat])
    c_child_order.extend(['authz_service', 'assertion_id_request_service', 'name_id_format'])

    def __init__(self,
            authz_service=None,
            assertion_id_request_service=None,
            name_id_format=None,
            signature=None,
            extensions=None,
            key_descriptor=None,
            organization=None,
            contact_person=None,
            id=None,
            valid_until=None,
            cache_duration=None,
            protocol_support_enumeration=None,
            error_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RoleDescriptorType.__init__(self, 
                signature=signature,
                extensions=extensions,
                key_descriptor=key_descriptor,
                organization=organization,
                contact_person=contact_person,
                id=id,
                valid_until=valid_until,
                cache_duration=cache_duration,
                protocol_support_enumeration=protocol_support_enumeration,
                error_url=error_url,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.authz_service=authz_service or []
        self.assertion_id_request_service=assertion_id_request_service or []
        self.name_id_format=name_id_format or []

def pdp_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(PDPDescriptorType, xml_string)

class AttributeAuthorityDescriptorType(RoleDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AttributeAuthorityDescriptorType element """

    c_tag = 'AttributeAuthorityDescriptorType'
    c_namespace = NAMESPACE
    c_children = RoleDescriptorType.c_children.copy()
    c_attributes = RoleDescriptorType.c_attributes.copy()
    c_child_order = RoleDescriptorType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AttributeService'] = ('attribute_service', [AttributeService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AssertionIDRequestService'] = ('assertion_id_request_service', [AssertionIDRequestService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat'] = ('name_id_format', [NameIDFormat])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AttributeProfile'] = ('attribute_profile', [AttributeProfile])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'] = ('attribute', [saml.Attribute])
    c_child_order.extend(['attribute_service', 'assertion_id_request_service', 'name_id_format', 'attribute_profile', 'attribute'])

    def __init__(self,
            attribute_service=None,
            assertion_id_request_service=None,
            name_id_format=None,
            attribute_profile=None,
            attribute=None,
            signature=None,
            extensions=None,
            key_descriptor=None,
            organization=None,
            contact_person=None,
            id=None,
            valid_until=None,
            cache_duration=None,
            protocol_support_enumeration=None,
            error_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RoleDescriptorType.__init__(self, 
                signature=signature,
                extensions=extensions,
                key_descriptor=key_descriptor,
                organization=organization,
                contact_person=contact_person,
                id=id,
                valid_until=valid_until,
                cache_duration=cache_duration,
                protocol_support_enumeration=protocol_support_enumeration,
                error_url=error_url,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.attribute_service=attribute_service or []
        self.assertion_id_request_service=assertion_id_request_service or []
        self.name_id_format=name_id_format or []
        self.attribute_profile=attribute_profile or []
        self.attribute=attribute or []

def attribute_authority_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeAuthorityDescriptorType, xml_string)

class AffiliationDescriptorType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AffiliationDescriptorType element """

    c_tag = 'AffiliationDescriptorType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{http://www.w3.org/2000/09/xmldsig#}Signature'] = ('signature', ds.Signature)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Extensions'] = ('extensions', Extensions)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AffiliateMember'] = ('affiliate_member', [AffiliateMember])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor'] = ('key_descriptor', [KeyDescriptor])
    c_attributes['affiliationOwnerID'] = ('affiliation_owner_id', 'entityIDType', True)
    c_attributes['validUntil'] = ('valid_until', 'dateTime', False)
    c_attributes['cacheDuration'] = ('cache_duration', 'duration', False)
    c_attributes['ID'] = ('id', 'ID', False)
    c_child_order.extend(['signature', 'extensions', 'affiliate_member', 'key_descriptor'])

    def __init__(self,
            signature=None,
            extensions=None,
            affiliate_member=None,
            key_descriptor=None,
            affiliation_owner_id=None,
            valid_until=None,
            cache_duration=None,
            id=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.signature=signature
        self.extensions=extensions
        self.affiliate_member=affiliate_member or []
        self.key_descriptor=key_descriptor or []
        self.affiliation_owner_id=affiliation_owner_id
        self.valid_until=valid_until
        self.cache_duration=cache_duration
        self.id=id

def affiliation_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AffiliationDescriptorType, xml_string)

class RoleDescriptor(RoleDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:RoleDescriptor element """

    c_tag = 'RoleDescriptor'
    c_namespace = NAMESPACE
    c_children = RoleDescriptorType.c_children.copy()
    c_attributes = RoleDescriptorType.c_attributes.copy()
    c_child_order = RoleDescriptorType.c_child_order[:]

def role_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(RoleDescriptor, xml_string)

class IDPSSODescriptor(IDPSSODescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:IDPSSODescriptor element """

    c_tag = 'IDPSSODescriptor'
    c_namespace = NAMESPACE
    c_children = IDPSSODescriptorType.c_children.copy()
    c_attributes = IDPSSODescriptorType.c_attributes.copy()
    c_child_order = IDPSSODescriptorType.c_child_order[:]

def idpsso_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(IDPSSODescriptor, xml_string)

class AttributeConsumingService(AttributeConsumingServiceType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AttributeConsumingService element """

    c_tag = 'AttributeConsumingService'
    c_namespace = NAMESPACE
    c_children = AttributeConsumingServiceType.c_children.copy()
    c_attributes = AttributeConsumingServiceType.c_attributes.copy()
    c_child_order = AttributeConsumingServiceType.c_child_order[:]

def attribute_consuming_service_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeConsumingService, xml_string)

class AuthnAuthorityDescriptor(AuthnAuthorityDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AuthnAuthorityDescriptor element """

    c_tag = 'AuthnAuthorityDescriptor'
    c_namespace = NAMESPACE
    c_children = AuthnAuthorityDescriptorType.c_children.copy()
    c_attributes = AuthnAuthorityDescriptorType.c_attributes.copy()
    c_child_order = AuthnAuthorityDescriptorType.c_child_order[:]

def authn_authority_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnAuthorityDescriptor, xml_string)

class PDPDescriptor(PDPDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:PDPDescriptor element """

    c_tag = 'PDPDescriptor'
    c_namespace = NAMESPACE
    c_children = PDPDescriptorType.c_children.copy()
    c_attributes = PDPDescriptorType.c_attributes.copy()
    c_child_order = PDPDescriptorType.c_child_order[:]

def pdp_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(PDPDescriptor, xml_string)

class AttributeAuthorityDescriptor(AttributeAuthorityDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AttributeAuthorityDescriptor element """

    c_tag = 'AttributeAuthorityDescriptor'
    c_namespace = NAMESPACE
    c_children = AttributeAuthorityDescriptorType.c_children.copy()
    c_attributes = AttributeAuthorityDescriptorType.c_attributes.copy()
    c_child_order = AttributeAuthorityDescriptorType.c_child_order[:]

def attribute_authority_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeAuthorityDescriptor, xml_string)

class AffiliationDescriptor(AffiliationDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:AffiliationDescriptor element """

    c_tag = 'AffiliationDescriptor'
    c_namespace = NAMESPACE
    c_children = AffiliationDescriptorType.c_children.copy()
    c_attributes = AffiliationDescriptorType.c_attributes.copy()
    c_child_order = AffiliationDescriptorType.c_child_order[:]

def affiliation_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(AffiliationDescriptor, xml_string)

class SPSSODescriptorType(SSODescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:SPSSODescriptorType element """

    c_tag = 'SPSSODescriptorType'
    c_namespace = NAMESPACE
    c_children = SSODescriptorType.c_children.copy()
    c_attributes = SSODescriptorType.c_attributes.copy()
    c_child_order = SSODescriptorType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService'] = ('assertion_consumer_service', [AssertionConsumerService])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AttributeConsumingService'] = ('attribute_consuming_service', [AttributeConsumingService])
    c_attributes['AuthnRequestsSigned'] = ('authn_requests_signed', 'boolean', False)
    c_attributes['WantAssertionsSigned'] = ('want_assertions_signed', 'boolean', False)
    c_child_order.extend(['assertion_consumer_service', 'attribute_consuming_service'])

    def __init__(self,
            assertion_consumer_service=None,
            attribute_consuming_service=None,
            authn_requests_signed=None,
            want_assertions_signed=None,
            artifact_resolution_service=None,
            single_logout_service=None,
            manage_name_id_service=None,
            name_id_format=None,
            signature=None,
            extensions=None,
            key_descriptor=None,
            organization=None,
            contact_person=None,
            id=None,
            valid_until=None,
            cache_duration=None,
            protocol_support_enumeration=None,
            error_url=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SSODescriptorType.__init__(self, 
                artifact_resolution_service=artifact_resolution_service,
                single_logout_service=single_logout_service,
                manage_name_id_service=manage_name_id_service,
                name_id_format=name_id_format,
                signature=signature,
                extensions=extensions,
                key_descriptor=key_descriptor,
                organization=organization,
                contact_person=contact_person,
                id=id,
                valid_until=valid_until,
                cache_duration=cache_duration,
                protocol_support_enumeration=protocol_support_enumeration,
                error_url=error_url,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.assertion_consumer_service=assertion_consumer_service or []
        self.attribute_consuming_service=attribute_consuming_service or []
        self.authn_requests_signed=authn_requests_signed
        self.want_assertions_signed=want_assertions_signed

def spsso_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SPSSODescriptorType, xml_string)

class SPSSODescriptor(SPSSODescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:SPSSODescriptor element """

    c_tag = 'SPSSODescriptor'
    c_namespace = NAMESPACE
    c_children = SPSSODescriptorType.c_children.copy()
    c_attributes = SPSSODescriptorType.c_attributes.copy()
    c_child_order = SPSSODescriptorType.c_child_order[:]

def spsso_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(SPSSODescriptor, xml_string)

class EntityDescriptorType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptorType element """

    c_tag = 'EntityDescriptorType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{http://www.w3.org/2000/09/xmldsig#}Signature'] = ('signature', ds.Signature)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Extensions'] = ('extensions', Extensions)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor'] = ('role_descriptor', [RoleDescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor'] = ('idpsso_descriptor', [IDPSSODescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor'] = ('spsso_descriptor', [SPSSODescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AuthnAuthorityDescriptor'] = ('authn_authority_descriptor', [AuthnAuthorityDescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AttributeAuthorityDescriptor'] = ('attribute_authority_descriptor', [AttributeAuthorityDescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}PDPDescriptor'] = ('pdp_descriptor', [PDPDescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AffiliationDescriptor'] = ('affiliation_descriptor', [AffiliationDescriptor])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Organization'] = ('organization', [Organization])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}ContactPerson'] = ('contact_person', [ContactPerson])
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}AdditionalMetadataLocation'] = ('additional_metadata_location', [AdditionalMetadataLocation])
    c_attributes['entityID'] = ('entity_id', 'entityIDType', True)
    c_attributes['validUntil'] = ('valid_until', 'dateTime', False)
    c_attributes['cacheDuration'] = ('cache_duration', 'duration', False)
    c_attributes['ID'] = ('id', 'ID', False)
    c_child_order.extend(['signature', 'extensions', 'role_descriptor', 'idpsso_descriptor', 'spsso_descriptor', 'authn_authority_descriptor', 'attribute_authority_descriptor', 'pdp_descriptor', 'affiliation_descriptor', 'organization', 'contact_person', 'additional_metadata_location'])

    def __init__(self,
            signature=None,
            extensions=None,
            role_descriptor=None,
            idpsso_descriptor=None,
            spsso_descriptor=None,
            authn_authority_descriptor=None,
            attribute_authority_descriptor=None,
            pdp_descriptor=None,
            affiliation_descriptor=None,
            organization=None,
            contact_person=None,
            additional_metadata_location=None,
            entity_id=None,
            valid_until=None,
            cache_duration=None,
            id=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.signature=signature
        self.extensions=extensions
        self.role_descriptor=role_descriptor or []
        self.idpsso_descriptor=idpsso_descriptor or []
        self.spsso_descriptor=spsso_descriptor or []
        self.authn_authority_descriptor=authn_authority_descriptor or []
        self.attribute_authority_descriptor=attribute_authority_descriptor or []
        self.pdp_descriptor=pdp_descriptor or []
        self.affiliation_descriptor=affiliation_descriptor or []
        self.organization=organization or []
        self.contact_person=contact_person or []
        self.additional_metadata_location=additional_metadata_location or []
        self.entity_id=entity_id
        self.valid_until=valid_until
        self.cache_duration=cache_duration
        self.id=id

def entity_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(EntityDescriptorType, xml_string)

class EntityDescriptor(EntityDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor element """

    c_tag = 'EntityDescriptor'
    c_namespace = NAMESPACE
    c_children = EntityDescriptorType.c_children.copy()
    c_attributes = EntityDescriptorType.c_attributes.copy()
    c_child_order = EntityDescriptorType.c_child_order[:]

def entity_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(EntityDescriptor, xml_string)

#..................
# ['EntitiesDescriptor', 'EntitiesDescriptorType']
class EntitiesDescriptorType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptorType element """

    c_tag = 'EntitiesDescriptorType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{http://www.w3.org/2000/09/xmldsig#}Signature'] = ('signature', ds.Signature)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}Extensions'] = ('extensions', Extensions)
    c_children['{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'] = ('entity_descriptor', [EntityDescriptor])
    c_attributes['validUntil'] = ('valid_until', 'dateTime', False)
    c_attributes['cacheDuration'] = ('cache_duration', 'duration', False)
    c_attributes['ID'] = ('id', 'ID', False)
    c_attributes['Name'] = ('name', 'string', False)
    c_child_order.extend(['signature', 'extensions', 'entity_descriptor', 'entities_descriptor'])

    def __init__(self,
            signature=None,
            extensions=None,
            entity_descriptor=None,
            entities_descriptor=None,
            valid_until=None,
            cache_duration=None,
            id=None,
            name=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.signature=signature
        self.extensions=extensions
        self.entity_descriptor=entity_descriptor or []
        self.entities_descriptor=entities_descriptor or []
        self.valid_until=valid_until
        self.cache_duration=cache_duration
        self.id=id
        self.name=name

def entities_descriptor_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(EntitiesDescriptorType, xml_string)

class EntitiesDescriptor(EntitiesDescriptorType):
    """The urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor element """

    c_tag = 'EntitiesDescriptor'
    c_namespace = NAMESPACE
    c_children = EntitiesDescriptorType.c_children.copy()
    c_attributes = EntitiesDescriptorType.c_attributes.copy()
    c_child_order = EntitiesDescriptorType.c_child_order[:]

def entities_descriptor_from_string(xml_string):
    return saml2.create_class_from_xml_string(EntitiesDescriptor, xml_string)

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
EntitiesDescriptorType.c_children['{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor'] = ('entities_descriptor', [EntitiesDescriptor])
EntitiesDescriptor.c_children['{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor'] = ('entities_descriptor', [EntitiesDescriptor])
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

ELEMENT_FROM_STRING = {
    entityIDType.c_tag: entity_id_type_from_string,
    localizedNameType.c_tag: localized_name_type_from_string,
    localizedURIType.c_tag: localized_uri_type_from_string,
    Extensions.c_tag: extensions_from_string,
    ExtensionsType.c_tag: extensions_type_from_string,
    EndpointType.c_tag: endpoint_type_from_string,
    IndexedEndpointType.c_tag: indexed_endpoint_type_from_string,
    EntitiesDescriptor.c_tag: entities_descriptor_from_string,
    EntitiesDescriptorType.c_tag: entities_descriptor_type_from_string,
    EntityDescriptor.c_tag: entity_descriptor_from_string,
    EntityDescriptorType.c_tag: entity_descriptor_type_from_string,
    Organization.c_tag: organization_from_string,
    OrganizationType.c_tag: organization_type_from_string,
    OrganizationName.c_tag: organization_name_from_string,
    OrganizationDisplayName.c_tag: organization_display_name_from_string,
    OrganizationURL.c_tag: organization_url_from_string,
    ContactPerson.c_tag: contact_person_from_string,
    ContactType.c_tag: contact_type_from_string,
    Company.c_tag: company_from_string,
    GivenName.c_tag: given_name_from_string,
    SurName.c_tag: sur_name_from_string,
    EmailAddress.c_tag: email_address_from_string,
    TelephoneNumber.c_tag: telephone_number_from_string,
    ContactTypeType.c_tag: contact_type_type_from_string,
    AdditionalMetadataLocation.c_tag: additional_metadata_location_from_string,
    AdditionalMetadataLocationType.c_tag: additional_metadata_location_type_from_string,
    RoleDescriptor.c_tag: role_descriptor_from_string,
    RoleDescriptorType.c_tag: role_descriptor_type_from_string,
    anyURIListType.c_tag: any_uri_list_type_from_string,
    KeyDescriptor.c_tag: key_descriptor_from_string,
    KeyDescriptorType.c_tag: key_descriptor_type_from_string,
    KeyTypes.c_tag: key_types_from_string,
    EncryptionMethod.c_tag: encryption_method_from_string,
    SSODescriptorType.c_tag: sso_descriptor_type_from_string,
    ArtifactResolutionService.c_tag: artifact_resolution_service_from_string,
    SingleLogoutService.c_tag: single_logout_service_from_string,
    ManageNameIDService.c_tag: manage_name_id_service_from_string,
    NameIDFormat.c_tag: name_id_format_from_string,
    IDPSSODescriptor.c_tag: idpsso_descriptor_from_string,
    IDPSSODescriptorType.c_tag: idpsso_descriptor_type_from_string,
    SingleSignOnService.c_tag: single_sign_on_service_from_string,
    NameIDMappingService.c_tag: name_id_mapping_service_from_string,
    AssertionIDRequestService.c_tag: assertion_id_request_service_from_string,
    AttributeProfile.c_tag: attribute_profile_from_string,
    SPSSODescriptor.c_tag: spsso_descriptor_from_string,
    SPSSODescriptorType.c_tag: spsso_descriptor_type_from_string,
    AssertionConsumerService.c_tag: assertion_consumer_service_from_string,
    AttributeConsumingService.c_tag: attribute_consuming_service_from_string,
    AttributeConsumingServiceType.c_tag: attribute_consuming_service_type_from_string,
    ServiceName.c_tag: service_name_from_string,
    ServiceDescription.c_tag: service_description_from_string,
    RequestedAttribute.c_tag: requested_attribute_from_string,
    RequestedAttributeType.c_tag: requested_attribute_type_from_string,
    AuthnAuthorityDescriptor.c_tag: authn_authority_descriptor_from_string,
    AuthnAuthorityDescriptorType.c_tag: authn_authority_descriptor_type_from_string,
    AuthnQueryService.c_tag: authn_query_service_from_string,
    PDPDescriptor.c_tag: pdp_descriptor_from_string,
    PDPDescriptorType.c_tag: pdp_descriptor_type_from_string,
    AuthzService.c_tag: authz_service_from_string,
    AttributeAuthorityDescriptor.c_tag: attribute_authority_descriptor_from_string,
    AttributeAuthorityDescriptorType.c_tag: attribute_authority_descriptor_type_from_string,
    AttributeService.c_tag: attribute_service_from_string,
    AffiliationDescriptor.c_tag: affiliation_descriptor_from_string,
    AffiliationDescriptorType.c_tag: affiliation_descriptor_type_from_string,
    AffiliateMember.c_tag: affiliate_member_from_string,
}

ELEMENT_BY_TAG = {
    'entityIDType': entityIDType,
    'localizedNameType': localizedNameType,
    'localizedURIType': localizedURIType,
    'Extensions': Extensions,
    'ExtensionsType': ExtensionsType,
    'EndpointType': EndpointType,
    'IndexedEndpointType': IndexedEndpointType,
    'EntitiesDescriptor': EntitiesDescriptor,
    'EntitiesDescriptorType': EntitiesDescriptorType,
    'EntityDescriptor': EntityDescriptor,
    'EntityDescriptorType': EntityDescriptorType,
    'Organization': Organization,
    'OrganizationType': OrganizationType,
    'OrganizationName': OrganizationName,
    'OrganizationDisplayName': OrganizationDisplayName,
    'OrganizationURL': OrganizationURL,
    'ContactPerson': ContactPerson,
    'ContactType': ContactType,
    'Company': Company,
    'GivenName': GivenName,
    'SurName': SurName,
    'EmailAddress': EmailAddress,
    'TelephoneNumber': TelephoneNumber,
    'ContactTypeType': ContactTypeType,
    'AdditionalMetadataLocation': AdditionalMetadataLocation,
    'AdditionalMetadataLocationType': AdditionalMetadataLocationType,
    'RoleDescriptor': RoleDescriptor,
    'RoleDescriptorType': RoleDescriptorType,
    'anyURIListType': anyURIListType,
    'KeyDescriptor': KeyDescriptor,
    'KeyDescriptorType': KeyDescriptorType,
    'KeyTypes': KeyTypes,
    'EncryptionMethod': EncryptionMethod,
    'SSODescriptorType': SSODescriptorType,
    'ArtifactResolutionService': ArtifactResolutionService,
    'SingleLogoutService': SingleLogoutService,
    'ManageNameIDService': ManageNameIDService,
    'NameIDFormat': NameIDFormat,
    'IDPSSODescriptor': IDPSSODescriptor,
    'IDPSSODescriptorType': IDPSSODescriptorType,
    'SingleSignOnService': SingleSignOnService,
    'NameIDMappingService': NameIDMappingService,
    'AssertionIDRequestService': AssertionIDRequestService,
    'AttributeProfile': AttributeProfile,
    'SPSSODescriptor': SPSSODescriptor,
    'SPSSODescriptorType': SPSSODescriptorType,
    'AssertionConsumerService': AssertionConsumerService,
    'AttributeConsumingService': AttributeConsumingService,
    'AttributeConsumingServiceType': AttributeConsumingServiceType,
    'ServiceName': ServiceName,
    'ServiceDescription': ServiceDescription,
    'RequestedAttribute': RequestedAttribute,
    'RequestedAttributeType': RequestedAttributeType,
    'AuthnAuthorityDescriptor': AuthnAuthorityDescriptor,
    'AuthnAuthorityDescriptorType': AuthnAuthorityDescriptorType,
    'AuthnQueryService': AuthnQueryService,
    'PDPDescriptor': PDPDescriptor,
    'PDPDescriptorType': PDPDescriptorType,
    'AuthzService': AuthzService,
    'AttributeAuthorityDescriptor': AttributeAuthorityDescriptor,
    'AttributeAuthorityDescriptorType': AttributeAuthorityDescriptorType,
    'AttributeService': AttributeService,
    'AffiliationDescriptor': AffiliationDescriptor,
    'AffiliationDescriptorType': AffiliationDescriptorType,
    'AffiliateMember': AffiliateMember,
}

def factory(tag, **kwargs):
    return ELEMENT_BY_TAG[tag](**kwargs)

