#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
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

"""Contains classes representing Saml elements.

    Module objective: provide data classes for Saml constructs. These
    classes hide the XML-ness of Saml and provide a set of native Python
    classes to interact with.

    Conversions to and from XML should only be necessary when the Saml classes
    "touch the wire" and are sent over HTTP. For this reason this module 
    provides methods and functions to convert Saml classes to and from strings.
"""

import xmldsig as ds
import saml2
from saml2 import SamlBase

SAML_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'
SAML_TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:assertion}%s'
XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'

NAMEID_FORMAT_EMAILADDRESS = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
NAMEID_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
NAMEID_FORMAT_ENCRYPTED = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")
NAMEID_FORMAT_PERSISTENT = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")

PROFILE_ATTRIBUTE_BASIC = (
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic")

URN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
NAME_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:2.0:attrnam-format:unspecified")
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrnam-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrnam-format:basic"
SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

CONSENT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"

class BaseID(SamlBase):
    """A foundation class on which Saml classes are built. It 
    handles the parsing of attributes and children which are common to all
    Saml classes. By default, the SamlBase class translates all XML child 
    nodes into ExtensionElements.
    """

    c_tag = 'BaseID'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['NameQualifier'] = 'name_qualifier'
    c_attributes['SPNameQualifier'] = 'sp_name_qualifier'

    def __init__(self, name_qualifier=None, sp_name_qualifier=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for BaseID

        :param name_qualifier: NameQualifier attribute
        :param sp_name_qualifier: SPNameQualifier attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.name_qualifier = name_qualifier
        self.sp_name_qualifier = sp_name_qualifier

def base_id_from_string(xml_string):
    """ Create BaseID instance from an XML string """
    return saml2.create_class_from_xml_string(BaseID, xml_string)

        
class NameID(BaseID):
    """The saml:NameID element"""

    c_tag = 'NameID'
    c_namespace = SAML_NAMESPACE
    c_children = BaseID.c_children.copy()
    c_attributes = BaseID.c_attributes.copy()
    c_attributes['Format'] = 'name_format'
    c_attributes['SPProvidedID'] = 'sp_provided_id'

    def __init__(self, name_qualifier=None, sp_name_qualifier=None, 
                    name_format=None, sp_provided_id=None, 
                    text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for NameID

        :param format: Format attribute
        :param sp_provided_id: SPProvidedID attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        BaseID.__init__(self, name_qualifier, sp_name_qualifier, text,
                                 extension_elements, extension_attributes)
        
        self.name_format = name_format
        self.sp_provided_id = sp_provided_id

def name_id_from_string(xml_string):
    """ Create NameID instance from an XML string """
    return saml2.create_class_from_xml_string(NameID, xml_string)


class Issuer(NameID):
    """The saml:Issuer element"""

    c_tag = 'Issuer'
    c_children = NameID.c_children.copy()
    c_attributes = NameID.c_attributes.copy()

def issuer_from_string(xml_string):
    """ Create Issuer instance from an XML string """
    return saml2.create_class_from_xml_string(Issuer, xml_string)


class SubjectLocality(SamlBase):
    """The saml:SubjectLocality element"""
    
    c_tag = 'SubjectLocality'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Address'] = 'address'
    c_attributes['DNSName'] = 'dns_name'

    def __init__(self, address=None, dns_name=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for SubjectLocality

        :param address: Address attribute
        :param dns_name: DNSName attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.address = address
        self.dns_name = dns_name

def subject_locality_from_string(xml_string):
    """ Create SubjectLocality instance from an XML string """
    return saml2.create_class_from_xml_string(SubjectLocality, xml_string)


class AuthnContextClassRef(SamlBase):
    """The saml:AuthnContextClassRef element"""

    c_tag = 'AuthnContextClassRef'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authn_context_class_ref_from_string(xml_string):
    """ Create AuthnContextClassRef instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnContextClassRef, xml_string)


class AuthnContextDeclRef(SamlBase):
    """The saml:AuthnContextDeclRef element"""

    c_tag = 'AuthnContextDeclRef'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authn_context_decl_ref_from_string(xml_string):
    """ Create AuthnContextDeclRef instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnContextDeclRef, xml_string)


class AuthnContextDecl(SamlBase):
    """The saml:AuthnContextDecl element"""

    c_tag = 'AuthnContextDecl'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authn_context_decl_from_string(xml_string):
    """ Create AuthnContextDecl instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnContextDecl, xml_string)


class AuthenticatingAuthority(SamlBase):
    """The saml:AuthenticatingAuthority element"""

    c_tag = 'AuthenticatingAuthority'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authenticating_authority_from_string(xml_string):
    """ Create AuthenticatingAuthority instance from an XML string """
    return saml2.create_class_from_xml_string(AuthenticatingAuthority, 
                                                xml_string)


class AuthnContext(SamlBase):
    """The saml:AuthnContext element"""

    c_tag = 'AuthnContext'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}AuthnContextClassRef' % SAML_NAMESPACE] = (
        'authn_context_class_ref', AuthnContextClassRef)
    c_children['{%s}AuthnContextDeclRef' % SAML_NAMESPACE] = (
        'authn_context_decl_ref', AuthnContextDeclRef)
    c_children['{%s}AuthnContextDecl' % SAML_NAMESPACE] = (
        'authn_context_decl', AuthnContextDecl)
    c_children['{%s}AuthenticatingAuthority' % SAML_NAMESPACE] = (
        'authenticating_authority', [AuthenticatingAuthority])
    c_child_order = ['authn_context_class_ref', 'authn_context_decl_ref',
                    'authn_context_decl', 'authenticating_authority']

    def __init__(self, authn_context_class_ref=None, 
                    authn_context_decl_ref=None,
                    authn_context_decl=None, authenticating_authority=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for AuthnContext

        Args:
        :param authn_context_class_ref: AuthnContextClassRef element
        :param authn_context_decl_ref: AuthnContextDeclRef element
        :param authn_context_decl: AuthnContextDecl element
        :param authenticating_authority: AuthenticatingAuthority element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)

        self.authn_context_class_ref = authn_context_class_ref
        self.authn_context_decl_ref = authn_context_decl_ref
        self.authn_context_decl = authn_context_decl
        self.authenticating_authority = authenticating_authority or []

def authn_context_from_string(xml_string):
    """ Create AuthnContext instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnContext, xml_string)

class Statement(SamlBase):
    """The saml:Statement element"""

    c_tag = 'Statement'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    
def statement_from_string(xml_string):
    """ Create Statement instance from an XML string """
    return saml2.create_class_from_xml_string(Statement, xml_string)


class AuthnStatement(Statement):
    """The saml:AuthnStatement element"""

    c_tag = 'AuthnStatement'
    c_namespace = SAML_NAMESPACE
    c_children = Statement.c_children.copy()
    c_attributes = Statement.c_attributes.copy()
    c_attributes['AuthnInstant'] = 'authn_instant'
    c_attributes['SessionIndex'] = 'session_index'
    c_attributes['SessionNotOnOrAfter'] = 'session_not_on_or_after'
    c_children['{%s}SubjectLocality' % SAML_NAMESPACE] = (
        'subject_locality', SubjectLocality)
    c_children['{%s}AuthnContext' % SAML_NAMESPACE] = (
        'authn_context', AuthnContext)
    c_child_order = ['subject_locality', 'authn_context']
    
    def __init__(self, authn_instant=None, session_index=None,
                    session_not_on_or_after=None, subject_locality=None,
                    authn_context=None, text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for AuthnStatement

        :param authn_instant: AuthnInstant attribute
        :param session_index: SessionIndex attribute
        :param session_not_on_or_after: SessionNotOnOrAfter attribute
        :param subject_locality: SubjectLocality element
        :param authn_context: AuthnContext element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        Statement.__init__(self, extension_elements, extension_attributes, 
                            text)

        self.authn_instant = authn_instant
        self.session_index = session_index
        self.session_not_on_or_after = session_not_on_or_after
        self.subject_locality = subject_locality
        self.authn_context = authn_context

def authn_statement_from_string(xml_string):
    """ Create AuthnStatement instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnStatement, xml_string)

# TODO: EncryptedAttribute

class AttributeValue(SamlBase):
    """The saml:AttributeValue element"""

    c_tag = 'AttributeValue'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def attribute_value_from_string(xml_string):
    """ Create AttributeValue instance from an XML string """
    return saml2.create_class_from_xml_string(AttributeValue, xml_string)


class Attribute(SamlBase):
    """The saml:Attribute element"""

    c_tag = 'Attribute'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Name'] = 'name'
    c_attributes['NameFormat'] = 'name_format'
    c_attributes['FriendlyName'] = 'friendly_name'
    c_children['{%s}AttributeValue' % SAML_NAMESPACE] = ('attribute_value', 
                                                        [AttributeValue])
    
    def __init__(self, name=None, name_format=None, friendly_name=None,
                    attribute_value=None, text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for Attribute

        :param name: Name attribute
        :param name_format: NameFormat attribute
        :param friendly_name: FriendlyName attribute
        :param attribute_value: AttributeValue elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.name = name
        self.name_format = name_format
        self.friendly_name = friendly_name
        self.attribute_value = attribute_value or []

def attribute_from_string(xml_string):
    """ Create Attribute instance from an XML string """
    return saml2.create_class_from_xml_string(Attribute, xml_string)


class AttributeStatement(Statement):
    """The saml:AttributeStatement element"""

    # TODO: EncryptedAttribute
    c_tag = 'AttributeStatement'
    c_namespace = SAML_NAMESPACE
    c_children = Statement.c_children.copy()
    c_attributes = Statement.c_attributes.copy()
    c_children['{%s}Attribute' % SAML_NAMESPACE] = ('attribute', [Attribute])
    
    def __init__(self, attribute=None, text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for AttributeStatement

        :param attribute: Attribute elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        Statement.__init__(self, extension_elements, extension_attributes, 
                            text)
        self.attribute = attribute or []

def attribute_statement_from_string(xml_string):
    """ Create AttributeStatement instance from an XML string """
    return saml2.create_class_from_xml_string(AttributeStatement, xml_string)

# TODO: AuthzDecisionStatement

class Action(SamlBase):
    """The saml:Action element"""

    c_tag = 'Action'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Namespace'] = 'namespace'
    
    def __init__(self, namespace=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for Action

        :param namespace: Namespace attribute
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.namespace = namespace

def action_from_string(xml_string):
    """ Create Action instance from an XML string """
    return saml2.create_class_from_xml_string(Action, xml_string)


class SubjectConfirmationData(SamlBase):
    """The saml:SubjectConfirmationData element"""

    c_tag = 'SubjectConfirmationData'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['NotBefore'] = 'not_before'
    c_attributes['NotOnOrAfter'] = 'not_on_or_after'
    c_attributes['Recipient'] = 'recipient'
    c_attributes['InResponseTo'] = 'in_response_to'
    c_attributes['Address'] = 'address'
    
    def __init__(self, not_before=None, not_on_or_after=None, recipient=None,
                    in_response_to=None, address=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for SubjectConfirmationData

        :param not_before: NotBefore attribute
        :param not_on_or_after: NotOnOrAfter attribute
        :param recipient: Recipient attribute
        :param in_response_to: InResponseTo attribute
        :param address: Address attribute
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.not_before = not_before
        self.not_on_or_after = not_on_or_after
        self.recipient = recipient
        self.in_response_to = in_response_to
        self.address = address

def subject_confirmation_data_from_string(xml_string):
    """ Create SubjectConfirmationData instance from an XML string """
    return saml2.create_class_from_xml_string(SubjectConfirmationData, 
                                                xml_string)


class SubjectConfirmation(SamlBase):
    """The saml:SubjectConfirmation element"""
    # TODO: BaseID, EncryptedID element

    c_tag = 'SubjectConfirmation'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Method'] = 'method'
    c_children['{%s}NameID' % SAML_NAMESPACE] = ('name_id', NameID)
    c_children['{%s}SubjectConfirmationData' % SAML_NAMESPACE] = (
        'subject_confirmation_data', SubjectConfirmationData)
    c_child_order = ['name_id', 'subject_confirmation_data']

    def __init__(self, method=None, name_id=None, 
                    subject_confirmation_data=None, text=None, 
                    extension_elements=None, extension_attributes=None):
        """Constructor for SubjectConfirmation

        :param method: Method attribute
        :param name_id: NameID element
        :param subject_confirmation_data: SubjectConfirmationData element
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.method = method
        self.name_id = name_id
        self.subject_confirmation_data = subject_confirmation_data

def subject_confirmation_from_string(xml_string):
    """ Create SubjectConfirmation instance from an XML string """
    return saml2.create_class_from_xml_string(SubjectConfirmation, xml_string)


class Subject(SamlBase):
    """The saml:Subject element"""
    # TODO: BaseID, EncryptedID element

    c_tag = 'Subject'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}NameID' % SAML_NAMESPACE] = ('name_id', NameID)
    c_children['{%s}SubjectConfirmation' % SAML_NAMESPACE] = (
        'subject_confirmation', [SubjectConfirmation])
    c_child_order = ['name_id', 'subject_confirmation']

    def __init__(self, name_id=None, subject_confirmation=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for SubjectConfirmation

        :param name_id: NameID element
        :param subject_confirmation: SubjectConfirmation element
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.name_id = name_id
        self.subject_confirmation = subject_confirmation or []

def subject_from_string(xml_string):
    """ Create Subject instance from an XML string """
    return saml2.create_class_from_xml_string(Subject, xml_string)


class Condition(SamlBase):
    """The saml:Condition element"""

    c_tag = 'Condition'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def condition_from_string(xml_string):
    """ Create Condition instance from an XML string """
    return saml2.create_class_from_xml_string(Condition, xml_string)


class Audience(SamlBase):
    """The saml:Audience element"""

    c_tag = 'Audience'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def audience_from_string(xml_string):
    """ Create Audience instance from an XML string """
    return saml2.create_class_from_xml_string(Audience, xml_string)


class AudienceRestriction(Condition):
    """The saml:AudienceRestriction element"""

    c_tag = 'AudienceRestriction'
    c_namespace = SAML_NAMESPACE
    c_children = Condition.c_children.copy()
    c_attributes = Condition.c_attributes.copy()
    c_children['{%s}Audience' % SAML_NAMESPACE] = ('audience', Audience)

    def __init__(self, text=None, audience=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for AudienceRestriction

        :param text: The text data in this element
        :param audience: Audience elements
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        Condition.__init__(self, extension_elements, extension_attributes, 
                            text)
        self.audience = audience

def audience_restriction_from_string(xml_string):
    """ Create AudienceRestriction instance from an XML string """
    return saml2.create_class_from_xml_string(AudienceRestriction, xml_string)

class OneTimeUse(Condition):
    """The saml:OneTimeUse element"""
    
    c_tag = 'OneTimeUse'
    c_children = Condition.c_children.copy()
    c_attributes = Condition.c_attributes.copy()

def one_time_use_from_string(xml_string):
    """ Create OneTimeUse instance from an XML string """
    return saml2.create_class_from_xml_string(OneTimeUse, xml_string)


class ProxyRestriction(Condition):
    """The saml:Condition element"""

    c_tag = 'ProxyRestriction'
    c_namespace = SAML_NAMESPACE
    c_children = Condition.c_children.copy()
    c_attributes = Condition.c_attributes.copy()
    c_attributes['Count'] = 'count'
    c_children['{%s}Audience' % SAML_NAMESPACE] = ('audience', [Audience])

    def __init__(self, text=None, count=None, audience=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for ProxyRestriction

        :param text: The text data in this element
        :param count: Count attribute
        :param audience: Audience elements
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        Condition.__init__(self, extension_elements, extension_attributes, 
                            text)
        self.count = count
        self.audience = audience or []

def proxy_restriction_from_string(xml_string):
    """ Create ProxyRestriction instance from an XML string """
    return saml2.create_class_from_xml_string(ProxyRestriction, xml_string)


class Conditions(SamlBase):
    """The saml:Conditions element"""

    c_tag = 'Conditions'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()    
    c_attributes['NotBefore'] = 'not_before'
    c_attributes['NotOnOrAfter'] = 'not_on_or_after'
    c_children['{%s}Condition' % SAML_NAMESPACE] = ('condition', [Condition])
    c_children['{%s}AudienceRestriction' % SAML_NAMESPACE] = (
        'audience_restriction', [AudienceRestriction])
    c_children['{%s}OneTimeUse' % SAML_NAMESPACE] = (
        'one_time_use', [OneTimeUse])
    c_children['{%s}ProxyRestriction' % SAML_NAMESPACE] = (
        'proxy_restriction', [ProxyRestriction])
    c_child_order = ['condition', 'audience_restriction', 'one_time_use',
                                    'proxy_restriction']

    def __init__(self, text=None, not_before=None, not_on_or_after=None,
                    condition=None, audience_restriction=None, 
                    one_time_use=None, proxy_restriction=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for ProxyRestriction

        :param text: The text data in this element
        :param not_before: NotBefore attribute
        :param not_on_or_after: NotOnOrAfter attribute
        :param condition: Condition elements
        :param audience_restriction: AudienceRestriction elements
        :param one_time_use: OneTimeUse elements
        :param proxy_restriction: ProxyRestriction elements
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.not_before = not_before
        self.not_on_or_after = not_on_or_after
        self.condition = condition or []
        self.audience_restriction = audience_restriction or []
        self.one_time_use = one_time_use or []
        self.proxy_restriction = proxy_restriction or []

def conditions_from_string(xml_string):
    """ Create Conditions instance from an XML string """
    return saml2.create_class_from_xml_string(Conditions, xml_string)


class AssertionIDRef(SamlBase):
    """The saml:AssertionIDRef element"""
    c_tag = 'AssertionIDRef'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def assertion_id_ref_from_string(xml_string):
    """ Create AssertionIDRef instance from an XML string """
    return saml2.create_class_from_xml_string(AssertionIDRef, xml_string)


class AssertionURIRef(SamlBase):
    """The saml:AssertionURIRef element"""
    c_tag = 'AssertionURIRef'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def assertion_uri_ref_from_string(xml_string):
    """ Create AssertionURIRef instance from an XML string """
    return saml2.create_class_from_xml_string(AssertionURIRef, xml_string)


class Evidence(SamlBase):
    """The saml:Evidence element"""

    c_tag = 'Evidence'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}AssertionIDRef' % SAML_NAMESPACE] = ('assertion_id_ref', 
                                                        [AssertionIDRef])
    c_children['{%s}AssertionURIRef' % SAML_NAMESPACE] = ('assertion_uri_ref', 
                                                        [AssertionURIRef])
    
    def __init__(self, assertion_id_ref=None, assertion_uri_ref=None,
                    assertion=None, encrypted_assertion=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for Evidence

        :param assertion_id_ref: AssertionIDRef elements
        :param assertion_uri_ref: AssertionURIRef elements
        :param assertion: Assertion elements
        :param encrypted_assertion: EncryptedAssertion elements
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.assertion_id_ref = assertion_id_ref or []
        self.assertion_uri_ref = assertion_uri_ref or []
        self.assertion = assertion or []
        self.encrypted_assertion = encrypted_assertion or []

def evidence_from_string(xml_string):
    """ Create Evidence instance from an XML string """
    return saml2.create_class_from_xml_string(Evidence, xml_string)

class Advice(SamlBase):
    """The saml:Advice element"""

    c_tag = 'Advice'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}AssertionIDRef' % SAML_NAMESPACE] = ('assertion_id_ref', 
                                                        [AssertionIDRef])
    c_children['{%s}AssertionURIRef' % SAML_NAMESPACE] = ('assertion_uri_ref', 
                                                        [AssertionURIRef])
    
    def __init__(self, assertion_id_ref=None, assertion_uri_ref=None,
                    assertion=None, encrypted_assertion=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for Advice

        :param assertion_id_ref: AssertionIDRef elements
        :param assertion_uri_ref: AssertionURIRef elements
        :param assertion: Assertion elements
        :param encrypted_assertion: EncryptedAssertion elements
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.assertion_id_ref = assertion_id_ref or []
        self.assertion_uri_ref = assertion_uri_ref or []
        self.assertion = assertion or []
        self.encrypted_assertion = encrypted_assertion or []

def advice_from_string(xml_string):
    """ Create Advice instance from an XML string """
    return saml2.create_class_from_xml_string(Advice, xml_string)


class Assertion(SamlBase):
    """The saml:Assertion element"""
    c_tag = 'Assertion'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Version'] = 'version'
    c_attributes['ID'] = 'identifier'
    c_attributes['IssueInstant'] = 'issue_instant'
    c_children['{%s}Issuer' % SAML_NAMESPACE] = ('issuer', Issuer)
    c_children['{%s}Signature' % ds.DS_NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Subject' % SAML_NAMESPACE] = ('subject', Subject)
    c_children['{%s}Conditions' % SAML_NAMESPACE] = ('conditions', Conditions)
    c_children['{%s}Advice' % SAML_NAMESPACE] = ('advice', Advice)
    c_children['{%s}Statement' % SAML_NAMESPACE] = ('statement', [Statement])
    c_children['{%s}AuthnStatement' % SAML_NAMESPACE] = (
        'authn_statement', [AuthnStatement])
    c_children['{%s}AttributeStatement' % SAML_NAMESPACE] = (
        'attribute_statement', [AttributeStatement])
    c_child_order = ['issuer', 'signature', 'subject', 'conditions', 'advice',
                    'statement', 'authn_statement', 'authz_decision_statement',
                    'attribute_statement']

    def __init__(self, version=None, identifier=None, issue_instant=None, 
                    issuer=None, signature=None, subject=None, conditions=None, 
                    advice=None, statement=None, authn_statement=None,
                    authz_decision_statement=None, attribute_statement=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for Assertion

        :param version: Version attribute
        :param identifier: ID attribute
        :param issue_instant: IssueInstant attribute
        :param issuer: Issuer element
        :param signature: ds:Signature element
        :param subject: Subject element
        :param conditions: Conditions element
        :param advice: Advice element
        :param statement: Statement elements
        :param authn_statement: AuthnStatement elements
        :param authz_decision_statement: AuthzDecisionStatement elements
        :param attribute_statement: AttributeStatement elements
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.version = version
        self.identifier = identifier
        self.issue_instant = issue_instant
        self.issuer = issuer
        self.signature = signature
        self.subject = subject
        self.conditions = conditions
        self.advice = advice
        self.statement = statement or []
        self.authn_statement = authn_statement or []
        self.authz_decision_statement = authz_decision_statement or []
        self.attribute_statement = attribute_statement or []

def assertion_from_string(xml_string):
    """ Create Assertion instance from an XML string """
    return saml2.create_class_from_xml_string(Assertion, xml_string)

Evidence.c_children['{%s}Assertion' % SAML_NAMESPACE] = (
    'assertion', [Assertion])
Advice.c_children['{%s}Assertion' % SAML_NAMESPACE] = (
    'assertion', [Assertion])


class EncryptedID(SamlBase):
    """The saml:EncryptedID element"""
    c_tag = 'EncryptedID'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

    # TODO: This is just a skelton yet.

def encrypted_id_from_string(xml_string):
    """ Create EncryptedID instance from an XML string """
    return saml2.create_class_from_xml_string(EncryptedID, xml_string)


class EncryptedAssertion(SamlBase):
    """The saml:EncryptedAssertion element"""
    c_tag = 'EncryptedAssertion'
    c_namespace = SAML_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

    # TODO: This is just a skelton yet.

def encrypted_assertion_from_string(xml_string):
    """ Create EncryptedAssertion instance from an XML string """
    return saml2.create_class_from_xml_string(EncryptedAssertion, xml_string)

Evidence.c_children['{%s}EncryptedAssertion' % SAML_NAMESPACE] = (
    'encrypted_assertion', [EncryptedAssertion])
Advice.c_children['{%s}EncryptedAssertion' % SAML_NAMESPACE] = (
    'encrypted_assertion', [EncryptedAssertion])

class AuthzDecisionStatement(Statement):
    """The saml:AuthzDecisionStatement element"""

    c_tag = 'AuthzDecisionStatement'
    c_namespace = SAML_NAMESPACE
    c_children = Statement.c_children.copy()
    c_attributes = Statement.c_attributes.copy()

    c_attributes['Resource'] = 'resource'
    c_attributes['Decision'] = 'decision'
    c_children['{%s}Action' % SAML_NAMESPACE] = ('action', [Action])
    c_children['{%s}Evidence' % SAML_NAMESPACE] = ('evidence', [Evidence])
    c_child_order = ['action', 'evidence']

    def __init__(self, text=None, resource=None, decision=None, action=None,
                             evidence=None, extension_elements=None,
                             extension_attributes=None):
        """Constructor for AuthzDecisionStatement

        :param text: str The text data in this element
        :param resource: Resource attribute
        :param decision: Decision attribute
        :param action: Action Elements
        :param evidence: Evidence Elements
        :param extension_elements:A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        Statement.__init__(self, extension_elements, extension_attributes, 
                            text)
        self.resource = resource
        self.decision = decision
        self.action = action or []
        self.evidence = evidence or []

def authz_decision_statement_from_string(xml_string):
    """ Create AuthzDecisionStatement instance from an XML string """
    return saml2.create_class_from_xml_string(AuthzDecisionStatement, 
                                                xml_string)

Assertion.c_children['{%s}AuthzDecisionStatement' % SAML_NAMESPACE] = (
    'authz_decision_statement', [AuthzDecisionStatement])

