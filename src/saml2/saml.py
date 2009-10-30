#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
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

"""Contains classes representing Saml elements.

    Module objective: provide data classes for Saml constructs. These
    classes hide the XML-ness of Saml and provide a set of native Python
    classes to interact with.

    Conversions to and from XML should only be necessary when the Saml classes
    "touch the wire" and are sent over HTTP. For this reason this module 
    provides methods and functions to convert Saml classes to and from strings.
"""

import xmldsig as ds
import xmlenc
import saml2
from saml2 import SamlBase

NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'
XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'

NAMEID_FORMAT_EMAILADDRESS = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
NAMEID_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
NAMEID_FORMAT_ENCRYPTED = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")
NAMEID_FORMAT_PERSISTENT = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
NAMEID_FORMAT_TRANSIENT = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")

PROFILE_ATTRIBUTE_BASIC = (
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic")

URN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
NAME_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

CONSENT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"

# ---------------------------------------------------------------------------
# BaseID
# ---------------------------------------------------------------------------

class BaseID(SamlBase):
    """ The saml:BaseID element """

    c_tag = 'BaseID'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['NameQualifier'] = 'name_qualifier'
    c_attributes['SPNameQualifier'] = 'sp_name_qualifier'

    def __init__(self, name_qualifier=None, sp_name_qualifier=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for BaseID, an extension point that allows applications
        to add new kinds of identifiers.

        :param name_qualifier: NameQualifier attribute; The security or 
            administrative domain that qualifies the identifier. 
        :param sp_name_qualifier: SPNameQualifier attribute; Further qualifies
            an identifier with the name of a service provider or affiliation 
            of providers.
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs.
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.name_qualifier = name_qualifier
        self.sp_name_qualifier = sp_name_qualifier

def base_id_from_string(xml_string):
    """ Create BaseID instance from an XML string """
    return saml2.create_class_from_xml_string(BaseID, xml_string)

# ---------------------------------------------------------------------------
# NameID
# ---------------------------------------------------------------------------

class NameID(BaseID):
    """The saml:NameID element"""

    c_tag = 'NameID'
    c_namespace = NAMESPACE
    c_children = BaseID.c_children.copy()
    c_attributes = BaseID.c_attributes.copy()
    c_attributes['Format'] = 'name_format'
    c_attributes['SPProvidedID'] = 'sp_provided_id'

    def __init__(self, name_qualifier=None, sp_name_qualifier=None, 
                    name_format=None, sp_provided_id=None, 
                    text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for NameID

        :param format: Format attribute; A URI reference representing the 
            classification of string-based identifier information.
        :param sp_provided_id: SPProvidedID attribute; A name identifier 
            established by a service provider or affiliation of providers 
            for the entity, if different from the primary name identifier 
            given in the content of the element.
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        BaseID.__init__(self, name_qualifier, sp_name_qualifier, text,
                                 extension_elements, extension_attributes)
        
        self.name_format = name_format
        self.sp_provided_id = sp_provided_id

def name_id_from_string(xml_string):
    """ Create NameID instance from an XML string """
    return saml2.create_class_from_xml_string(NameID, xml_string)

# ---------------------------------------------------------------------------
# EncryptedID
# ---------------------------------------------------------------------------

class EncryptedID(SamlBase):
    """The saml:EncryptedID element"""
    c_tag = 'EncryptedID'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

    # TODO: This is just a skelton yet.

def encrypted_id_from_string(xml_string):
    """ Create EncryptedID instance from an XML string """
    return saml2.create_class_from_xml_string(EncryptedID, xml_string)

# ---------------------------------------------------------------------------
# Issuer
# ---------------------------------------------------------------------------

class Issuer(NameID):
    """The saml:Issuer element"""

    c_tag = 'Issuer'
    c_children = NameID.c_children.copy()
    c_attributes = NameID.c_attributes.copy()

def issuer_from_string(xml_string):
    """ Create Issuer instance from an XML string """
    return saml2.create_class_from_xml_string(Issuer, xml_string)


# ---------------------------------------------------------------------------
# AssertionIDRef
# ---------------------------------------------------------------------------

class AssertionIDRef(SamlBase):
    """The saml:AssertionIDRef element makes a reference to a SAML assertion 
    by its unique identifier."""
    c_tag = 'AssertionIDRef'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def assertion_id_ref_from_string(xml_string):
    """ Create AssertionIDRef instance from an XML string """
    return saml2.create_class_from_xml_string(AssertionIDRef, xml_string)

# ---------------------------------------------------------------------------
# AssertionURIRef
# ---------------------------------------------------------------------------

class AssertionURIRef(SamlBase):
    """The saml:AssertionURIRef element makes a reference to a SAML assertion 
    by URI reference."""
    c_tag = 'AssertionURIRef'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def assertion_uri_ref_from_string(xml_string):
    """ Create AssertionURIRef instance from an XML string """
    return saml2.create_class_from_xml_string(AssertionURIRef, xml_string)

# ---------------------------------------------------------------------------
# EncryptedElement
# ---------------------------------------------------------------------------

class EncryptedElement(SamlBase):

    c_tag = 'EncryptedElement'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

    c_children['{%s}EncryptedData' % xmlenc.NAMESPACE] = (
                        'encrypted_data', xmlenc.EncryptedData)
    c_children['{%s}EncryptedKey' % xmlenc.NAMESPACE] = (
                        'encrypted_key', xmlenc.EncryptedKey)
    c_child_order = ["encrypted_data", "encrypted_key", "encrypted_id"]
    
    def __init__(self, encrypted_data=None, encrypted_key=None, 
                encrypted_id=None,
                text=None,
                extension_elements=None, 
                extension_attributes=None):

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.encrypted_data = encrypted_data
        self.encrypted_key = encrypted_key
        self.encrypted_id = encrypted_id

def encrypted_element_from_string(xml_string):
    """ Create EncryptedElement instance from an XML string """
    return saml2.create_class_from_xml_string(EncryptedElement, xml_string)

# ---------------------------------------------------------------------------
# EncryptedID
# ---------------------------------------------------------------------------

class EncryptedID(EncryptedElement):
    c_tag = 'EncryptedID'
    c_namespace = NAMESPACE
    c_children = EncryptedElement.c_children.copy()
    c_attributes = EncryptedElement.c_attributes.copy()

def encrypted_id_from_string(xml_string):
    """ Create EncryptedID instance from an XML string """
    return saml2.create_class_from_xml_string(EncryptedID, xml_string)


EncryptedElement.c_children['{%s}EncryptedID' % NAMESPACE] = (
                        'encrypted_id', EncryptedID)
                        
# ---------------------------------------------------------------------------
# EncryptedAssertion
# ---------------------------------------------------------------------------

class EncryptedAssertion(EncryptedElement):
    """The saml:EncryptedAssertion element represents an assertion in 
    encrypted fashion, as defined by the XML Encryption Syntax and 
    Processing specification"""
    
    c_tag = 'EncryptedAssertion'
    c_namespace = NAMESPACE
    c_children = EncryptedElement.c_children.copy()
    c_attributes = EncryptedElement.c_attributes.copy()

    # TODO: This is just a skelton yet.

def encrypted_assertion_from_string(xml_string):
    """ Create EncryptedAssertion instance from an XML string """
    return saml2.create_class_from_xml_string(EncryptedAssertion, xml_string)

# ===========================================================================
# SubjectConfirmationData
# ---------------------------------------------------------------------------

class SubjectConfirmationData(SamlBase):
    """The saml:SubjectConfirmationData element has the 
    SubjectConfirmationDataType complex type. It specifies additional data 
    that allows the subject to be confirmed or constrains the circumstances 
    under which the act of subject confirmation can take place"""

    c_tag = 'SubjectConfirmationData'
    c_namespace = NAMESPACE
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

        :param not_before: NotBefore attribute; A time instant before which 
            the subject cannot be confirmed.
        :param not_on_or_after: NotOnOrAfter attribute; A time instant at 
            which the subject can no longer be confirmed.
        :param recipient: Recipient attribute; A URI specifying the entity or 
            location to which an attesting entity can present the assertion. 
            For example, this attribute might indicate that the assertion must 
            be delivered to a particular network endpoint in order to prevent 
            an intermediary from redirecting it someplace else.
        :param in_response_to: InResponseTo attribute; The ID of a SAML 
            protocol message in response to which an attesting entity can 
            present the assertion.
        :param address: Address attribute; The network address/location from 
            which an attesting entity can present the assertion. 
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
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

# ---------------------------------------------------------------------------
# KeyInfoConfirmationDataType
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SubjectConfirmation
# ---------------------------------------------------------------------------

class SubjectConfirmation(SamlBase):
    """The saml:SubjectConfirmation element provides the means for a relying 
    party to verify the correspondence of the subject of the assertion with 
    the party with whom the relying party is communicating."""

    c_tag = 'SubjectConfirmation'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Method'] = 'method'
    c_children['{%s}BaseID' % NAMESPACE] = ('base_id', BaseID)
    c_children['{%s}NameID' % NAMESPACE] = ('name_id', NameID)
    c_children['{%s}EncryptedID' % NAMESPACE] = ('encrypted_id', 
        EncryptedID)
    c_children['{%s}SubjectConfirmationData' % NAMESPACE] = (
        'subject_confirmation_data', SubjectConfirmationData)
    c_child_order = ['base_id', 'name_id', 'encrypted_id', 
                    'subject_confirmation_data']

    def __init__(self, base_id=None, name_id=None, encrypted_id=None,
                    subject_confirmation_data=None, text=None, 
                    extension_elements=None, extension_attributes=None):
        """Constructor for SubjectConfirmation

        :param base_id: Method attribute
        :param name_id: NameID element
        :param subject_confirmation_data: SubjectConfirmationData element
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.base_id = base_id
        self.name_id = name_id
        self.encrypted_id = encrypted_id
        self.subject_confirmation_data = subject_confirmation_data

def subject_confirmation_from_string(xml_string):
    """ Create SubjectConfirmation instance from an XML string """
    return saml2.create_class_from_xml_string(SubjectConfirmation, xml_string)

# ---------------------------------------------------------------------------
# Subject
# ---------------------------------------------------------------------------

class Subject(SamlBase):
    """The saml:Subject element"""

    c_tag = 'Subject'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}NameID' % NAMESPACE] = ('name_id', NameID)
    c_children['{%s}SubjectConfirmation' % NAMESPACE] = (
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


# ===========================================================================
# Condition
# ---------------------------------------------------------------------------

class Condition(SamlBase):
    """The saml:Condition element"""

    c_tag = 'Condition'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def condition_from_string(xml_string):
    """ Create Condition instance from an XML string """
    return saml2.create_class_from_xml_string(Condition, xml_string)


# ---------------------------------------------------------------------------
# Audience
# ---------------------------------------------------------------------------

class Audience(SamlBase):
    """The saml:Audience element, a URI reference that identifies an intended
    audience."""

    c_tag = 'Audience'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def audience_from_string(xml_string):
    """ Create Audience instance from an XML string """
    return saml2.create_class_from_xml_string(Audience, xml_string)

# ---------------------------------------------------------------------------
# AudienceRestriction
# ---------------------------------------------------------------------------

class AudienceRestriction(Condition):
    """The saml:AudienceRestriction element specifies that the assertion is 
    addressed to one or more specific audiences identified by <Audience> 
    elements."""

    c_tag = 'AudienceRestriction'
    c_namespace = NAMESPACE
    c_children = Condition.c_children.copy()
    c_attributes = Condition.c_attributes.copy()
    c_children['{%s}Audience' % NAMESPACE] = ('audience', Audience)

    def __init__(self, audience=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for AudienceRestriction

        :param text: The text data in this element
        :param audience: Audience elements
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        Condition.__init__(self, text, extension_elements, 
            extension_attributes)
        self.audience = audience

def audience_restriction_from_string(xml_string):
    """ Create AudienceRestriction instance from an XML string """
    return saml2.create_class_from_xml_string(AudienceRestriction, xml_string)

# ---------------------------------------------------------------------------
# OneTimeUse
# ---------------------------------------------------------------------------

class OneTimeUse(Condition):
    """The saml:OneTimeUse element. In general, relying parties may choose to 
    retain assertions, or the information they contain in some other form, 
    for reuse. The <OneTimeUse> condition element allows an authority to 
    indicate that the information in the assertion is likely to change very 
    soon and fresh information should be obtained for each use."""

    c_tag = 'OneTimeUse'
    c_children = Condition.c_children.copy()
    c_attributes = Condition.c_attributes.copy()

def one_time_use_from_string(xml_string):
    """ Create OneTimeUse instance from an XML string """
    return saml2.create_class_from_xml_string(OneTimeUse, xml_string)

# ---------------------------------------------------------------------------
# OneTimeUse
# ---------------------------------------------------------------------------

class ProxyRestriction(Condition):
    """The saml:ProxyRestriction element. Specifies limitations that the 
    asserting party imposes on relying parties that in turn wish to act as 
    asserting parties and issue subsequent assertions of their own on the basis
    of the information contained in the original assertion."""

    c_tag = 'ProxyRestriction'
    c_namespace = NAMESPACE
    c_children = Condition.c_children.copy()
    c_attributes = Condition.c_attributes.copy()
    c_attributes['Count'] = 'count'
    c_children['{%s}Audience' % NAMESPACE] = ('audience', [Audience])

    def __init__(self, count=None, audience=None, text=None,
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


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------

class Conditions(SamlBase):
    """The saml:Conditions element"""

    c_tag = 'Conditions'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()    
    c_attributes['NotBefore'] = 'not_before'
    c_attributes['NotOnOrAfter'] = 'not_on_or_after'
    c_children['{%s}Condition' % NAMESPACE] = ('condition', [Condition])
    c_children['{%s}AudienceRestriction' % NAMESPACE] = (
        'audience_restriction', [AudienceRestriction])
    c_children['{%s}OneTimeUse' % NAMESPACE] = (
        'one_time_use', [OneTimeUse])
    c_children['{%s}ProxyRestriction' % NAMESPACE] = (
        'proxy_restriction', [ProxyRestriction])
    c_child_order = ['condition', 'audience_restriction', 'one_time_use',
                                    'proxy_restriction']

    def __init__(self, not_before=None, not_on_or_after=None,
                    condition=None, audience_restriction=None, 
                    one_time_use=None, proxy_restriction=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for ProxyRestriction

        :param not_before: NotBefore attribute; Specifies the earliest 
            time instant at which the assertion is valid.
        :param not_on_or_after: NotOnOrAfter attribute; Specifies the 
            time instant at which the assertion has expired.
        :param condition: Condition elements; A condition of a type 
            defined in an extension schema.
        :param audience_restriction: AudienceRestriction elements; 
            Specifies that the assertion is addressed to a particular audience.
        :param one_time_use: OneTimeUse elements; Specifies that the assertion
            SHOULD be used immediately and MUST NOT be retained for future use.
        :param proxy_restriction: ProxyRestriction elements; Specifies 
            limitations that the asserting party imposes on relying parties 
            that wish to subsequently act as asserting parties themselves and 
            issue assertions of their own on the basis of the information 
            contained in the original assertion. 
        :param text: The text data in this element
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


# ---------------------------------------------------------------------------
# Statement
# ---------------------------------------------------------------------------

class Statement(SamlBase):
    """The saml:Statement element is an extension point that allows other 
    assertion-based applications to reuse the SAML assertion framework."""

    c_tag = 'Statement'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    
def statement_from_string(xml_string):
    """ Create Statement instance from an XML string """
    return saml2.create_class_from_xml_string(Statement, xml_string)

# ---------------------------------------------------------------------------
# SubjectLocality
# ---------------------------------------------------------------------------

class SubjectLocality(SamlBase):
    """The saml:SubjectLocality element"""

    c_tag = 'SubjectLocality'
    c_namespace = NAMESPACE
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

# ---------------------------------------------------------------------------
# AuthnContextClassRef
# ---------------------------------------------------------------------------

class AuthnContextClassRef(SamlBase):
    """The saml:AuthnContextClassRef element"""

    c_tag = 'AuthnContextClassRef'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authn_context_class_ref_from_string(xml_string):
    """ Create AuthnContextClassRef instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnContextClassRef, xml_string)


class AuthnContextDeclRef(SamlBase):
    """The saml:AuthnContextDeclRef element"""

    c_tag = 'AuthnContextDeclRef'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authn_context_decl_ref_from_string(xml_string):
    """ Create AuthnContextDeclRef instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnContextDeclRef, xml_string)


class AuthnContextDecl(SamlBase):
    """The saml:AuthnContextDecl element"""

    c_tag = 'AuthnContextDecl'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authn_context_decl_from_string(xml_string):
    """ Create AuthnContextDecl instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnContextDecl, xml_string)


class AuthenticatingAuthority(SamlBase):
    """The saml:AuthenticatingAuthority element"""

    c_tag = 'AuthenticatingAuthority'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def authenticating_authority_from_string(xml_string):
    """ Create AuthenticatingAuthority instance from an XML string """
    return saml2.create_class_from_xml_string(AuthenticatingAuthority, 
                                                xml_string)


class AuthnContext(SamlBase):
    """The saml:AuthnContext element"""

    c_tag = 'AuthnContext'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}AuthnContextClassRef' % NAMESPACE] = (
        'authn_context_class_ref', AuthnContextClassRef)
    c_children['{%s}AuthnContextDeclRef' % NAMESPACE] = (
        'authn_context_decl_ref', AuthnContextDeclRef)
    c_children['{%s}AuthnContextDecl' % NAMESPACE] = (
        'authn_context_decl', AuthnContextDecl)
    c_children['{%s}AuthenticatingAuthority' % NAMESPACE] = (
        'authenticating_authority', [AuthenticatingAuthority])
    c_child_order = ['authn_context_class_ref', 
                    'authn_context_decl', 'authn_context_decl_ref',
                    'authenticating_authority']

    def __init__(self, authn_context_class_ref=None, 
                    authn_context_decl=None, authn_context_decl_ref=None,
                    authenticating_authority=None,
                    text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for AuthnContext

        Args:
        :param authn_context_class_ref: AuthnContextClassRef element;
            A URI reference identifying an authentication context class 
            that describes the authentication context declaration that follows.
        :param authn_context_decl: AuthnContextDecl element
        :param authn_context_decl_ref: AuthnContextDeclRef element;
            Either an authentication context declaration provided by value, 
            or a URI reference that identifies such a declaration.
        :param authenticating_authority: AuthenticatingAuthority element;
            Zero or more unique identifiers of authentication authorities 
            that were involved in the authentication of the principal 
            (not including the assertion issuer, who is presumed to have 
            been involved without being explicitly named here).
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


# ---------------------------------------------------------------------------
# AuthnStatement
# ---------------------------------------------------------------------------

class AuthnStatement(Statement):
    """The saml:AuthnStatement element"""

    c_tag = 'AuthnStatement'
    c_namespace = NAMESPACE
    c_children = Statement.c_children.copy()
    c_attributes = Statement.c_attributes.copy()
    c_attributes['AuthnInstant'] = 'authn_instant'
    c_attributes['SessionIndex'] = 'session_index'
    c_attributes['SessionNotOnOrAfter'] = 'session_not_on_or_after'
    c_children['{%s}SubjectLocality' % NAMESPACE] = (
        'subject_locality', SubjectLocality)
    c_children['{%s}AuthnContext' % NAMESPACE] = (
        'authn_context', AuthnContext)
    c_child_order = Statement.c_child_order[:]
    c_child_order.extend(['subject_locality', 'authn_context'])
    
    def __init__(self, authn_instant=None, session_index=None,
                    session_not_on_or_after=None, subject_locality=None,
                    authn_context=None, text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for AuthnStatement

        :param authn_instant: AuthnInstant attribute; Specifies the time at 
            which the authentication took place. 
        :param session_index: SessionIndex attribute; Specifies the index of
            a particular session between the principal identified by the 
            subject and the authenticating authority.
        :param session_not_on_or_after: SessionNotOnOrAfter attribute;
            Specifies a time instant at which the session between the 
            principal identified by the subject and the SAML authority 
            issuing this statement MUST be considered ended.
        :param subject_locality: SubjectLocality element; Specifies the DNS 
            domain name and IP address for the system from which the 
            assertion subject was apparently authenticated.
        :param authn_context: AuthnContext element; The context used by the 
            authenticating authority up to and including the authentication 
            event that yielded this statement.
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        Statement.__init__(self, text, extension_elements, 
                            extension_attributes )

        self.authn_instant = authn_instant
        self.session_index = session_index
        self.session_not_on_or_after = session_not_on_or_after
        self.subject_locality = subject_locality
        self.authn_context = authn_context

def authn_statement_from_string(xml_string):
    """ Create AuthnStatement instance from an XML string """
    return saml2.create_class_from_xml_string(AuthnStatement, xml_string)

# ---------------------------------------------------------------------------
# AttributeValue
# ---------------------------------------------------------------------------

class AttributeValue(SamlBase):
    """The saml:AttributeValue element supplies the value of a specified SAML 
    attribute."""

    c_tag = 'AttributeValue'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def attribute_value_from_string(xml_string):
    """ Create AttributeValue instance from an XML string """
    return saml2.create_class_from_xml_string(AttributeValue, xml_string)


# ---------------------------------------------------------------------------
# EncryptedAttribute
# ---------------------------------------------------------------------------

class EncryptedAttribute(SamlBase):
    """The saml:EncryptedAttribute element represents a SAML attribute in 
    encrypted fashion, as defined by the XML Encryption Syntax and Processing 
    specification."""

    c_tag = 'EncryptedAttribute'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def encrypted_attribute_from_string(xml_string):
    """ Create EncryptedAttribute instance from an XML string """
    return saml2.create_class_from_xml_string(EncryptedAttribute, xml_string)

# ---------------------------------------------------------------------------
#  Attribute
# ---------------------------------------------------------------------------

class Attribute(SamlBase):
    """The saml:Attribute element"""

    c_tag = 'Attribute'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Name'] = 'name'
    c_attributes['NameFormat'] = 'name_format'
    c_attributes['FriendlyName'] = 'friendly_name'
    c_children['{%s}AttributeValue' % NAMESPACE] = ('attribute_value', 
                                                        [AttributeValue])
    
    def __init__(self, name=None, name_format=None, friendly_name=None,
                    attribute_value=None, text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for Attribute

        :param name: The name of the attribute.
        :param name_format: NameFormat attribute, A URI reference representing 
            the classification of the attribute name for purposes of 
            interpreting the name.
        :param friendly_name: FriendlyName attribute; A string that provides a 
            more human-readable form of the attribute's name, which may be 
            useful in cases in which the actual Name is complex or opaque, 
            such as an OID or a UUID.
        :param attribute_value: AttributeValue elements, Contains a value of 
            the attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.name = name
        self.name_format = name_format
        self.friendly_name = friendly_name
        self.attribute_value = attribute_value or []

def attribute_from_string(xml_string):
    """ Create Attribute instance from an XML string """
    return saml2.create_class_from_xml_string(Attribute, xml_string)

# ---------------------------------------------------------------------------
#  AttributeStatement
# ---------------------------------------------------------------------------

class AttributeStatement(Statement):
    """The saml:AttributeStatement element describes a statement by the SAML 
    authority asserting that the assertion subject is associated with the 
    specified attributes."""

    c_tag = 'AttributeStatement'
    c_namespace = NAMESPACE
    c_children = Statement.c_children.copy()
    c_attributes = Statement.c_attributes.copy()
    c_children['{%s}Attribute' % NAMESPACE] = ('attribute', [Attribute])
    c_children['{%s}EncryptedAttribute' % NAMESPACE] = (
            'encrypted_attribute', [EncryptedAttribute])
    c_child_order = Statement.c_child_order[:]
    c_child_order.extend(['attribute', 'encrypted_attribute'])
    
    def __init__(self, attribute=None, encrypted_attribute=None, 
                    text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for AttributeStatement

        :param attribute: Attribute elements
        :param encrypted_attribute: EncryptedAttribute elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        Statement.__init__(self, text, extension_elements, 
                            extension_attributes)
        self.attribute = attribute or []
        self.encrypted_attribute = encrypted_attribute or []

def attribute_statement_from_string(xml_string):
    """ Create AttributeStatement instance from an XML string """
    return saml2.create_class_from_xml_string(AttributeStatement, xml_string)

# ---------------------------------------------------------------------------
#  Action
# ---------------------------------------------------------------------------

class Action(SamlBase):
    """The saml:Action element specifies an action on the specified resource 
    for which permission is sought."""

    c_tag = 'Action'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Namespace'] = 'namespace'
    
    def __init__(self, namespace=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for Action

        :param namespace: Namespace attribute; A URI reference representing the
            namespace in which the name of the specified action is to be 
            interpreted.
        :param text: The text data in this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.namespace = namespace

def action_from_string(xml_string):
    """ Create Action instance from an XML string """
    return saml2.create_class_from_xml_string(Action, xml_string)

# ---------------------------------------------------------------------------
#  Evidence
# ---------------------------------------------------------------------------

class Evidence(SamlBase):
    """The saml:Evidence element contains one or more assertions or 
    assertion references that the SAML authority relied on in issuing 
    the authorization decision."""

    c_tag = 'Evidence'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}AssertionIDRef' % NAMESPACE] = ('assertion_id_ref', 
                                                        [AssertionIDRef])
    c_children['{%s}AssertionURIRef' % NAMESPACE] = ('assertion_uri_ref', 
                                                        [AssertionURIRef])
    # Can't do this here since Assertion isn't defined                                                    
    #c_children['{%s}Assertion' % NAMESPACE] = ('assertion', [Assertion])
    c_children['{%s}EncryptedAssertion' % NAMESPACE] = (
        'encrypted_assertion', [EncryptedAssertion])
    c_child_order = ['assertion_id_ref', 'assertion_uri_ref', 'assertion',
                    'encrypted_assertion']
    
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


# ---------------------------------------------------------------------------
#  AuthzDecisionStatement
# ---------------------------------------------------------------------------

class AuthzDecisionStatement(Statement):
    """The saml:AuthzDecisionStatement element describes a statement by the 
    SAML authority asserting that a request for access by the assertion subject
    to the specified resource has resulted in the specified authorization 
    decision on the basis of some optionally specified evidence."""

    c_tag = 'AuthzDecisionStatement'
    c_namespace = NAMESPACE
    c_children = Statement.c_children.copy()
    c_attributes = Statement.c_attributes.copy()

    c_attributes['Resource'] = 'resource'
    c_attributes['Decision'] = 'decision'
    c_children['{%s}Action' % NAMESPACE] = ('action', [Action])
    c_children['{%s}Evidence' % NAMESPACE] = ('evidence', [Evidence])
    c_child_order = Statement.c_child_order[:]
    c_child_order.extend(['action', 'evidence'])

    def __init__(self, resource=None, decision=None, action=None,
                    evidence=None, text=None, extension_elements=None,
                    extension_attributes=None):
        """Constructor for AuthzDecisionStatement

        :param text: str The text data in this element
        :param resource: Resource attribute; A URI reference identifying 
            the resource to which access authorization is sought.
        :param decision: Decision attribute; The decision rendered by the 
            SAML authority with respect to the specified resource.
        :param action: Action Elements; The set of actions authorized to 
            be performed on the specified resource.
        :param evidence: Evidence Elements; A set of assertions that the 
            SAML authority relied on in making the decision.
        :param text: The text data in this element
        :param extension_elements:A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        Statement.__init__(self, text, extension_elements, 
                            extension_attributes)
        self.resource = resource
        self.decision = decision
        self.action = action or []
        self.evidence = evidence or []

def authz_decision_statement_from_string(xml_string):
    """ Create AuthzDecisionStatement instance from an XML string """
    return saml2.create_class_from_xml_string(AuthzDecisionStatement, 
                                                xml_string)

# ---------------------------------------------------------------------------
#  Assertion
# ---------------------------------------------------------------------------

class Assertion(SamlBase):
    """The saml:Assertion element"""
    c_tag = 'Assertion'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Version'] = 'version'
    c_attributes['ID'] = 'identifier'
    c_attributes['IssueInstant'] = 'issue_instant'
    c_children['{%s}Issuer' % NAMESPACE] = ('issuer', Issuer)
    c_children['{%s}Signature' % ds.NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Subject' % NAMESPACE] = ('subject', Subject)
    c_children['{%s}Conditions' % NAMESPACE] = ('conditions', Conditions)
    #c_children['{%s}Advice' % NAMESPACE] = ('advice', Advice)
    c_children['{%s}Statement' % NAMESPACE] = ('statement', [Statement])
    c_children['{%s}AuthnStatement' % NAMESPACE] = (
        'authn_statement', [AuthnStatement])
    c_children['{%s}AuthzDecisionStatement' % NAMESPACE] = (
        'authz_decision_statement', [AuthzDecisionStatement])
    c_children['{%s}AttributeStatement' % NAMESPACE] = (
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

        :param version: Version attribute; The version of this assertion. 
            The identifier for the version of SAML defined in this 
            specification is "2.0".
        :param identifier: ID attribute, The identifier for this assertion.
        :param issue_instant: IssueInstant attribute; The time instant of 
            issue in UTC.
        :param issuer: Issuer element; The SAML authority that is making 
            the claim(s) in the assertion.
        :param signature: ds:Signature element; An XML Signature that 
            protects the integrity of and authenticates the issuer of 
            the assertion
        :param subject: Subject element; The subject of the statement(s) 
            in the assertion.
        :param conditions: Conditions element; Conditions that MUST be 
            evaluated when assessing the validity of and/or when using 
            the assertion.
        :param advice: Advice element; Additional information related 
            to the assertion that assists processing in certain 
            situations but which MAY be ignored by applications that do not 
            understand the advice or do not wish to make use of it.
        :param statement: Statement elements; A statement of a type 
            defined in an extension schema. An xsi:type attribute MUST 
            be used to indicate the actual statement type.
        :param authn_statement: AuthnStatement elements; An authentication 
            statement.
        :param authz_decision_statement: AuthzDecisionStatement elements;
            An authorization decision statement
        :param attribute_statement: AttributeStatement elements:
            An attribute statement.
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

Evidence.c_children['{%s}Assertion' % NAMESPACE] = (
    'assertion', [Assertion])

# ---------------------------------------------------------------------------
# Advice
# ---------------------------------------------------------------------------

class Advice(SamlBase):
    """The saml:Advice element contains any additional information that the 
    SAML authority wishes to provide."""

    c_tag = 'Advice'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}AssertionIDRef' % NAMESPACE] = ('assertion_id_ref', 
                                                        [AssertionIDRef])
    c_children['{%s}AssertionURIRef' % NAMESPACE] = ('assertion_uri_ref', 
                                                        [AssertionURIRef])
    c_children['{%s}Assertion' % NAMESPACE] = ('assertion', [Assertion])
    c_children['{%s}EncryptedAssertion' % NAMESPACE] = (
            'encrypted_assertion', [EncryptedAssertion])
    c_child_order = ['assertion_id_ref', 'assertion_uri_ref',
                    'assertion', 'encrypted_assertion']

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

Assertion.c_children['{%s}Advice' % NAMESPACE] = ('advice', Advice)
Evidence.c_children['{%s}Assertion' % NAMESPACE] = ('assertion', [Assertion])

ELEMENT_FROM_STRING = {
    BaseID.c_tag: base_id_from_string,
    NameID.c_tag: name_id_from_string,
    EncryptedID.c_tag: encrypted_id_from_string,
    Issuer.c_tag: issuer_from_string,
    AssertionIDRef.c_tag: assertion_id_ref_from_string,
    AssertionURIRef.c_tag: assertion_uri_ref_from_string,
    EncryptedAssertion.c_tag: encrypted_assertion_from_string,
    SubjectConfirmationData.c_tag: subject_confirmation_data_from_string,
    SubjectConfirmation.c_tag: subject_confirmation_from_string,
    Subject.c_tag: subject_from_string,
    Condition.c_tag: condition_from_string,
    Audience.c_tag: audience_from_string,
    AudienceRestriction.c_tag: audience_restriction_from_string,
    OneTimeUse.c_tag: one_time_use_from_string,
    ProxyRestriction.c_tag: proxy_restriction_from_string,
    Conditions.c_tag: conditions_from_string,
    Statement.c_tag: statement_from_string,
    SubjectLocality.c_tag: subject_locality_from_string,
    AuthnContextClassRef.c_tag: authn_context_class_ref_from_string,
    AuthnContextDeclRef.c_tag: authn_context_decl_ref_from_string,
    AuthnContextDecl.c_tag: authn_context_decl_from_string,
    AuthenticatingAuthority.c_tag: authenticating_authority_from_string,
    AuthnContext.c_tag: authn_context_from_string,
    AuthnStatement(Statement): authn_statement_from_string,
    AttributeValue.c_tag: attribute_value_from_string,
    EncryptedAttribute.c_tag: encrypted_attribute_from_string,
    Attribute.c_tag: attribute_from_string,
    AttributeStatement(Statement): attribute_statement_from_string,
    Action.c_tag: action_from_string,
    Evidence.c_tag: evidence_from_string,
    AuthzDecisionStatement(Statement): authz_decision_statement_from_string,
    Assertion.c_tag: assertion_from_string,
    Advice.c_tag: advice_from_string,
}