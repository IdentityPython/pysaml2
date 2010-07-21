#!/usr/bin/env python

#
# Generated Thu Jul 15 21:40:22 2010 by parse_xsd.py version 0.3.
#

import saml2
import xmldsig as ds

from saml2 import SamlBase
from saml2 import saml

NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:protocol'

STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester'
STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder'
STATUS_VERSION_MISMATCH = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch'

STATUS_AUTHN_FAILED = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'
STATUS_INVALID_ATTR_NAME_OR_VALUE = (
    'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue')
STATUS_INVALID_NAMEID_POLICY = (
    'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy')
STATUS_NO_AUTHN_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext'
STATUS_NO_AVAILABLE_IDP = 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP'
STATUS_NO_PASSIVE = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive'
STATUS_NO_SUPPORTED_IDP = 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP'
STATUS_PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout'
STATUS_PROXY_COUNT_EXCEEDED = (
    'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded')
STATUS_REQUEST_DENIED = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied'
STATUS_REQUEST_UNSUPPORTED = (
    'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported')
STATUS_REQUEST_VERSION_DEPRECATED = (
    'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated')
STATUS_REQUEST_VERSION_TOO_HIGH = (
    'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh')
STATUS_REQUEST_VERSION_TOO_LOW = (
    'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow')
STATUS_RESOURCE_NOT_RECOGNIZED = (
    'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized')
STATUS_TOO_MANY_RESPONSES = (
    'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses')
STATUS_UNKNOWN_ATTR_PROFILE = (
    'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile')
STATUS_UNKNOWN_PRINCIPAL = (
    'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal')
STATUS_UNSUPPORTED_BINDING = (
    'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding')


class ExtensionsType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ExtensionsType element """

    c_tag = 'ExtensionsType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def extensions_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ExtensionsType, xml_string)

class StatusMessage(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:StatusMessage element """

    c_tag = 'StatusMessage'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def status_message_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatusMessage, xml_string)

class StatusDetailType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:StatusDetailType element """

    c_tag = 'StatusDetailType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def status_detail_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatusDetailType, xml_string)

class RequestedAuthnContextType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:RequestedAuthnContextType element """

    c_tag = 'RequestedAuthnContextType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef'] = ('authn_context_class_ref', [saml.AuthnContextClassRef])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDeclRef'] = ('authn_context_decl_ref', [saml.AuthnContextDeclRef])
    c_attributes['Comparison'] = ('comparison', 'AuthnContextComparisonType', False)
    c_child_order.extend(['authn_context_class_ref', 'authn_context_decl_ref'])

    def __init__(self,
            authn_context_class_ref=None,
            authn_context_decl_ref=None,
            comparison=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.authn_context_class_ref=authn_context_class_ref or []
        self.authn_context_decl_ref=authn_context_decl_ref or []
        self.comparison=comparison

def requested_authn_context_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(RequestedAuthnContextType, xml_string)

class AuthnContextComparisonType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AuthnContextComparisonType element """

    c_tag = 'AuthnContextComparisonType'
    c_namespace = NAMESPACE
    c_value_type = {'base': 'string', 'enumeration': ['exact', 'minimum', 'maximum', 'better']}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def authn_context_comparison_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnContextComparisonType, xml_string)

class NameIDPolicyType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDPolicyType element """

    c_tag = 'NameIDPolicyType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['Format'] = ('format', 'anyURI', False)
    c_attributes['SPNameQualifier'] = ('sp_name_qualifier', 'string', False)
    c_attributes['AllowCreate'] = ('allow_create', 'boolean', False)

    def __init__(self,
            format=None,
            sp_name_qualifier=None,
            allow_create=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.format=format
        self.sp_name_qualifier=sp_name_qualifier
        self.allow_create=allow_create

def name_id_policy_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDPolicyType, xml_string)

class RequesterID(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:RequesterID element """

    c_tag = 'RequesterID'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def requester_id_from_string(xml_string):
    return saml2.create_class_from_xml_string(RequesterID, xml_string)

class IDPEntryType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:IDPEntryType element """

    c_tag = 'IDPEntryType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['ProviderID'] = ('provider_id', 'anyURI', True)
    c_attributes['Name'] = ('name', 'string', False)
    c_attributes['Loc'] = ('loc', 'anyURI', False)

    def __init__(self,
            provider_id=None,
            name=None,
            loc=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.provider_id=provider_id
        self.name=name
        self.loc=loc

def idp_entry_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(IDPEntryType, xml_string)

class GetComplete(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:GetComplete element """

    c_tag = 'GetComplete'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def get_complete_from_string(xml_string):
    return saml2.create_class_from_xml_string(GetComplete, xml_string)

class Artifact(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:Artifact element """

    c_tag = 'Artifact'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def artifact_from_string(xml_string):
    return saml2.create_class_from_xml_string(Artifact, xml_string)

class NewID(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NewID element """

    c_tag = 'NewID'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def new_id_from_string(xml_string):
    return saml2.create_class_from_xml_string(NewID, xml_string)

class NewEncryptedID(saml.EncryptedElementType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NewEncryptedID element """

    c_tag = 'NewEncryptedID'
    c_namespace = NAMESPACE
    c_children = saml.EncryptedElementType.c_children.copy()
    c_attributes = saml.EncryptedElementType.c_attributes.copy()
    c_child_order = saml.EncryptedElementType.c_child_order[:]

def new_encrypted_id_from_string(xml_string):
    return saml2.create_class_from_xml_string(NewEncryptedID, xml_string)

class TerminateType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:TerminateType element """

    c_tag = 'TerminateType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def terminate_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(TerminateType, xml_string)

class SessionIndex(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:SessionIndex element """

    c_tag = 'SessionIndex'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def session_index_from_string(xml_string):
    return saml2.create_class_from_xml_string(SessionIndex, xml_string)

class Extensions(ExtensionsType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:Extensions element """

    c_tag = 'Extensions'
    c_namespace = NAMESPACE
    c_children = ExtensionsType.c_children.copy()
    c_attributes = ExtensionsType.c_attributes.copy()
    c_child_order = ExtensionsType.c_child_order[:]

def extensions_from_string(xml_string):
    return saml2.create_class_from_xml_string(Extensions, xml_string)

class StatusDetail(StatusDetailType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:StatusDetail element """

    c_tag = 'StatusDetail'
    c_namespace = NAMESPACE
    c_children = StatusDetailType.c_children.copy()
    c_attributes = StatusDetailType.c_attributes.copy()
    c_child_order = StatusDetailType.c_child_order[:]

def status_detail_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatusDetail, xml_string)

class RequestAbstractType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:RequestAbstractType element """

    c_tag = 'RequestAbstractType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'] = ('issuer', saml.Issuer)
    c_children['{http://www.w3.org/2000/09/xmldsig#}Signature'] = ('signature', ds.Signature)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}Extensions'] = ('extensions', Extensions)
    c_attributes['ID'] = ('id', 'ID', True)
    c_attributes['Version'] = ('version', 'string', True)
    c_attributes['IssueInstant'] = ('issue_instant', 'dateTime', True)
    c_attributes['Destination'] = ('destination', 'anyURI', False)
    c_attributes['Consent'] = ('consent', 'anyURI', False)
    c_child_order.extend(['issuer', 'signature', 'extensions'])

    def __init__(self,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.issuer=issuer
        self.signature=signature
        self.extensions=extensions
        self.id=id
        self.version=version
        self.issue_instant=issue_instant
        self.destination=destination
        self.consent=consent

def request_abstract_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(RequestAbstractType, xml_string)

class AssertionIDRequestType(RequestAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AssertionIDRequestType element """

    c_tag = 'AssertionIDRequestType'
    c_namespace = NAMESPACE
    c_children = RequestAbstractType.c_children.copy()
    c_attributes = RequestAbstractType.c_attributes.copy()
    c_child_order = RequestAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AssertionIDRef'] = ('assertion_id_ref', [saml.AssertionIDRef])
    c_child_order.extend(['assertion_id_ref'])

    def __init__(self,
            assertion_id_ref=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RequestAbstractType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.assertion_id_ref=assertion_id_ref or []

def assertion_id_request_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AssertionIDRequestType, xml_string)

class SubjectQueryAbstractType(RequestAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:SubjectQueryAbstractType element """

    c_tag = 'SubjectQueryAbstractType'
    c_namespace = NAMESPACE
    c_children = RequestAbstractType.c_children.copy()
    c_attributes = RequestAbstractType.c_attributes.copy()
    c_child_order = RequestAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Subject'] = ('subject', saml.Subject)
    c_child_order.extend(['subject'])

    def __init__(self,
            subject=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RequestAbstractType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.subject=subject

def subject_query_abstract_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectQueryAbstractType, xml_string)

class RequestedAuthnContext(RequestedAuthnContextType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:RequestedAuthnContext element """

    c_tag = 'RequestedAuthnContext'
    c_namespace = NAMESPACE
    c_children = RequestedAuthnContextType.c_children.copy()
    c_attributes = RequestedAuthnContextType.c_attributes.copy()
    c_child_order = RequestedAuthnContextType.c_child_order[:]

def requested_authn_context_from_string(xml_string):
    return saml2.create_class_from_xml_string(RequestedAuthnContext, xml_string)

class AttributeQueryType(SubjectQueryAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AttributeQueryType element """

    c_tag = 'AttributeQueryType'
    c_namespace = NAMESPACE
    c_children = SubjectQueryAbstractType.c_children.copy()
    c_attributes = SubjectQueryAbstractType.c_attributes.copy()
    c_child_order = SubjectQueryAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'] = ('attribute', [saml.Attribute])
    c_child_order.extend(['attribute'])

    def __init__(self,
            attribute=None,
            subject=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SubjectQueryAbstractType.__init__(self, 
                subject=subject,
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.attribute=attribute or []

def attribute_query_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeQueryType, xml_string)

class AuthzDecisionQueryType(SubjectQueryAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AuthzDecisionQueryType element """

    c_tag = 'AuthzDecisionQueryType'
    c_namespace = NAMESPACE
    c_children = SubjectQueryAbstractType.c_children.copy()
    c_attributes = SubjectQueryAbstractType.c_attributes.copy()
    c_child_order = SubjectQueryAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Action'] = ('action', [saml.Action])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Evidence'] = ('evidence', saml.Evidence)
    c_attributes['Resource'] = ('resource', 'anyURI', True)
    c_child_order.extend(['action', 'evidence'])

    def __init__(self,
            action=None,
            evidence=None,
            resource=None,
            subject=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SubjectQueryAbstractType.__init__(self, 
                subject=subject,
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.action=action or []
        self.evidence=evidence
        self.resource=resource

def authz_decision_query_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthzDecisionQueryType, xml_string)

class NameIDPolicy(NameIDPolicyType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDPolicy element """

    c_tag = 'NameIDPolicy'
    c_namespace = NAMESPACE
    c_children = NameIDPolicyType.c_children.copy()
    c_attributes = NameIDPolicyType.c_attributes.copy()
    c_child_order = NameIDPolicyType.c_child_order[:]

def name_id_policy_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDPolicy, xml_string)

class IDPEntry(IDPEntryType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:IDPEntry element """

    c_tag = 'IDPEntry'
    c_namespace = NAMESPACE
    c_children = IDPEntryType.c_children.copy()
    c_attributes = IDPEntryType.c_attributes.copy()
    c_child_order = IDPEntryType.c_child_order[:]

def idp_entry_from_string(xml_string):
    return saml2.create_class_from_xml_string(IDPEntry, xml_string)

class ArtifactResolveType(RequestAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResolveType element """

    c_tag = 'ArtifactResolveType'
    c_namespace = NAMESPACE
    c_children = RequestAbstractType.c_children.copy()
    c_attributes = RequestAbstractType.c_attributes.copy()
    c_child_order = RequestAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}Artifact'] = ('artifact', Artifact)
    c_child_order.extend(['artifact'])

    def __init__(self,
            artifact=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RequestAbstractType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.artifact=artifact

def artifact_resolve_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ArtifactResolveType, xml_string)

class Terminate(TerminateType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:Terminate element """

    c_tag = 'Terminate'
    c_namespace = NAMESPACE
    c_children = TerminateType.c_children.copy()
    c_attributes = TerminateType.c_attributes.copy()
    c_child_order = TerminateType.c_child_order[:]

def terminate_from_string(xml_string):
    return saml2.create_class_from_xml_string(Terminate, xml_string)

class LogoutRequestType(RequestAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:LogoutRequestType element """

    c_tag = 'LogoutRequestType'
    c_namespace = NAMESPACE
    c_children = RequestAbstractType.c_children.copy()
    c_attributes = RequestAbstractType.c_attributes.copy()
    c_child_order = RequestAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}BaseID'] = ('base_id', saml.BaseID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}NameID'] = ('name_id', saml.NameID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID'] = ('encrypted_id', saml.EncryptedID)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}SessionIndex'] = ('session_index', [SessionIndex])
    c_attributes['Reason'] = ('reason', 'string', False)
    c_attributes['NotOnOrAfter'] = ('not_on_or_after', 'dateTime', False)
    c_child_order.extend(['base_id', 'name_id', 'encrypted_id', 'session_index'])

    def __init__(self,
            base_id=None,
            name_id=None,
            encrypted_id=None,
            session_index=None,
            reason=None,
            not_on_or_after=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RequestAbstractType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.base_id=base_id
        self.name_id=name_id
        self.encrypted_id=encrypted_id
        self.session_index=session_index or []
        self.reason=reason
        self.not_on_or_after=not_on_or_after

def logout_request_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(LogoutRequestType, xml_string)

class NameIDMappingRequestType(RequestAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDMappingRequestType element """

    c_tag = 'NameIDMappingRequestType'
    c_namespace = NAMESPACE
    c_children = RequestAbstractType.c_children.copy()
    c_attributes = RequestAbstractType.c_attributes.copy()
    c_child_order = RequestAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}BaseID'] = ('base_id', saml.BaseID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}NameID'] = ('name_id', saml.NameID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID'] = ('encrypted_id', saml.EncryptedID)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy'] = ('name_id_policy', NameIDPolicy)
    c_child_order.extend(['base_id', 'name_id', 'encrypted_id', 'name_id_policy'])

    def __init__(self,
            base_id=None,
            name_id=None,
            encrypted_id=None,
            name_id_policy=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RequestAbstractType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.base_id=base_id
        self.name_id=name_id
        self.encrypted_id=encrypted_id
        self.name_id_policy=name_id_policy

def name_id_mapping_request_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDMappingRequestType, xml_string)

class AssertionIDRequest(AssertionIDRequestType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AssertionIDRequest element """

    c_tag = 'AssertionIDRequest'
    c_namespace = NAMESPACE
    c_children = AssertionIDRequestType.c_children.copy()
    c_attributes = AssertionIDRequestType.c_attributes.copy()
    c_child_order = AssertionIDRequestType.c_child_order[:]

def assertion_id_request_from_string(xml_string):
    return saml2.create_class_from_xml_string(AssertionIDRequest, xml_string)

class SubjectQuery(SubjectQueryAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:SubjectQuery element """

    c_tag = 'SubjectQuery'
    c_namespace = NAMESPACE
    c_children = SubjectQueryAbstractType.c_children.copy()
    c_attributes = SubjectQueryAbstractType.c_attributes.copy()
    c_child_order = SubjectQueryAbstractType.c_child_order[:]

def subject_query_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectQuery, xml_string)

class AuthnQueryType(SubjectQueryAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AuthnQueryType element """

    c_tag = 'AuthnQueryType'
    c_namespace = NAMESPACE
    c_children = SubjectQueryAbstractType.c_children.copy()
    c_attributes = SubjectQueryAbstractType.c_attributes.copy()
    c_child_order = SubjectQueryAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext'] = ('requested_authn_context', RequestedAuthnContext)
    c_attributes['SessionIndex'] = ('session_index', 'string', False)
    c_child_order.extend(['requested_authn_context'])

    def __init__(self,
            requested_authn_context=None,
            session_index=None,
            subject=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SubjectQueryAbstractType.__init__(self, 
                subject=subject,
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.requested_authn_context=requested_authn_context
        self.session_index=session_index

def authn_query_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnQueryType, xml_string)

class AttributeQuery(AttributeQueryType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AttributeQuery element """

    c_tag = 'AttributeQuery'
    c_namespace = NAMESPACE
    c_children = AttributeQueryType.c_children.copy()
    c_attributes = AttributeQueryType.c_attributes.copy()
    c_child_order = AttributeQueryType.c_child_order[:]

def attribute_query_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeQuery, xml_string)

class AuthzDecisionQuery(AuthzDecisionQueryType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AuthzDecisionQuery element """

    c_tag = 'AuthzDecisionQuery'
    c_namespace = NAMESPACE
    c_children = AuthzDecisionQueryType.c_children.copy()
    c_attributes = AuthzDecisionQueryType.c_attributes.copy()
    c_child_order = AuthzDecisionQueryType.c_child_order[:]

def authz_decision_query_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthzDecisionQuery, xml_string)

class IDPListType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:IDPListType element """

    c_tag = 'IDPListType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}IDPEntry'] = ('idp_entry', [IDPEntry])
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}GetComplete'] = ('get_complete', GetComplete)
    c_child_order.extend(['idp_entry', 'get_complete'])

    def __init__(self,
            idp_entry=None,
            get_complete=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.idp_entry=idp_entry or []
        self.get_complete=get_complete

def idp_list_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(IDPListType, xml_string)

class ArtifactResolve(ArtifactResolveType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResolve element """

    c_tag = 'ArtifactResolve'
    c_namespace = NAMESPACE
    c_children = ArtifactResolveType.c_children.copy()
    c_attributes = ArtifactResolveType.c_attributes.copy()
    c_child_order = ArtifactResolveType.c_child_order[:]

def artifact_resolve_from_string(xml_string):
    return saml2.create_class_from_xml_string(ArtifactResolve, xml_string)

class ManageNameIDRequestType(RequestAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ManageNameIDRequestType element """

    c_tag = 'ManageNameIDRequestType'
    c_namespace = NAMESPACE
    c_children = RequestAbstractType.c_children.copy()
    c_attributes = RequestAbstractType.c_attributes.copy()
    c_child_order = RequestAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}NameID'] = ('name_id', saml.NameID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID'] = ('encrypted_id', saml.EncryptedID)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}NewID'] = ('new_id', NewID)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}NewEncryptedID'] = ('new_encrypted_id', NewEncryptedID)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}Terminate'] = ('terminate', Terminate)
    c_child_order.extend(['name_id', 'encrypted_id', 'new_id', 'new_encrypted_id', 'terminate'])

    def __init__(self,
            name_id=None,
            encrypted_id=None,
            new_id=None,
            new_encrypted_id=None,
            terminate=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RequestAbstractType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.name_id=name_id
        self.encrypted_id=encrypted_id
        self.new_id=new_id
        self.new_encrypted_id=new_encrypted_id
        self.terminate=terminate

def manage_name_id_request_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ManageNameIDRequestType, xml_string)

class LogoutRequest(LogoutRequestType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:LogoutRequest element """

    c_tag = 'LogoutRequest'
    c_namespace = NAMESPACE
    c_children = LogoutRequestType.c_children.copy()
    c_attributes = LogoutRequestType.c_attributes.copy()
    c_child_order = LogoutRequestType.c_child_order[:]

def logout_request_from_string(xml_string):
    return saml2.create_class_from_xml_string(LogoutRequest, xml_string)

class NameIDMappingRequest(NameIDMappingRequestType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDMappingRequest element """

    c_tag = 'NameIDMappingRequest'
    c_namespace = NAMESPACE
    c_children = NameIDMappingRequestType.c_children.copy()
    c_attributes = NameIDMappingRequestType.c_attributes.copy()
    c_child_order = NameIDMappingRequestType.c_child_order[:]

def name_id_mapping_request_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDMappingRequest, xml_string)

class AuthnQuery(AuthnQueryType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AuthnQuery element """

    c_tag = 'AuthnQuery'
    c_namespace = NAMESPACE
    c_children = AuthnQueryType.c_children.copy()
    c_attributes = AuthnQueryType.c_attributes.copy()
    c_child_order = AuthnQueryType.c_child_order[:]

def authn_query_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnQuery, xml_string)

class IDPList(IDPListType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:IDPList element """

    c_tag = 'IDPList'
    c_namespace = NAMESPACE
    c_children = IDPListType.c_children.copy()
    c_attributes = IDPListType.c_attributes.copy()
    c_child_order = IDPListType.c_child_order[:]

def idp_list_from_string(xml_string):
    return saml2.create_class_from_xml_string(IDPList, xml_string)

class ManageNameIDRequest(ManageNameIDRequestType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ManageNameIDRequest element """

    c_tag = 'ManageNameIDRequest'
    c_namespace = NAMESPACE
    c_children = ManageNameIDRequestType.c_children.copy()
    c_attributes = ManageNameIDRequestType.c_attributes.copy()
    c_child_order = ManageNameIDRequestType.c_child_order[:]

def manage_name_id_request_from_string(xml_string):
    return saml2.create_class_from_xml_string(ManageNameIDRequest, xml_string)

class ScopingType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ScopingType element """

    c_tag = 'ScopingType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}IDPList'] = ('idp_list', IDPList)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}RequesterID'] = ('requester_id', [RequesterID])
    c_attributes['ProxyCount'] = ('proxy_count', 'nonNegativeInteger', False)
    c_child_order.extend(['idp_list', 'requester_id'])

    def __init__(self,
            idp_list=None,
            requester_id=None,
            proxy_count=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.idp_list=idp_list
        self.requester_id=requester_id or []
        self.proxy_count=proxy_count

def scoping_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ScopingType, xml_string)

class Scoping(ScopingType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:Scoping element """

    c_tag = 'Scoping'
    c_namespace = NAMESPACE
    c_children = ScopingType.c_children.copy()
    c_attributes = ScopingType.c_attributes.copy()
    c_child_order = ScopingType.c_child_order[:]

def scoping_from_string(xml_string):
    return saml2.create_class_from_xml_string(Scoping, xml_string)

class AuthnRequestType(RequestAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequestType element """

    c_tag = 'AuthnRequestType'
    c_namespace = NAMESPACE
    c_children = RequestAbstractType.c_children.copy()
    c_attributes = RequestAbstractType.c_attributes.copy()
    c_child_order = RequestAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Subject'] = ('subject', saml.Subject)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy'] = ('name_id_policy', NameIDPolicy)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'] = ('conditions', saml.Conditions)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext'] = ('requested_authn_context', RequestedAuthnContext)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}Scoping'] = ('scoping', Scoping)
    c_attributes['ForceAuthn'] = ('force_authn', 'boolean', False)
    c_attributes['IsPassive'] = ('is_passive', 'boolean', False)
    c_attributes['ProtocolBinding'] = ('protocol_binding', 'anyURI', False)
    c_attributes['AssertionConsumerServiceIndex'] = ('assertion_consumer_service_index', 'unsignedShort', False)
    c_attributes['AssertionConsumerServiceURL'] = ('assertion_consumer_service_url', 'anyURI', False)
    c_attributes['AttributeConsumingServiceIndex'] = ('attribute_consuming_service_index', 'unsignedShort', False)
    c_attributes['ProviderName'] = ('provider_name', 'string', False)
    c_child_order.extend(['subject', 'name_id_policy', 'conditions', 'requested_authn_context', 'scoping'])

    def __init__(self,
            subject=None,
            name_id_policy=None,
            conditions=None,
            requested_authn_context=None,
            scoping=None,
            force_authn=None,
            is_passive=None,
            protocol_binding=None,
            assertion_consumer_service_index=None,
            assertion_consumer_service_url=None,
            attribute_consuming_service_index=None,
            provider_name=None,
            issuer=None,
            signature=None,
            extensions=None,
            id=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        RequestAbstractType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                id=id,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.subject=subject
        self.name_id_policy=name_id_policy
        self.conditions=conditions
        self.requested_authn_context=requested_authn_context
        self.scoping=scoping
        self.force_authn=force_authn
        self.is_passive=is_passive
        self.protocol_binding=protocol_binding
        self.assertion_consumer_service_index=assertion_consumer_service_index
        self.assertion_consumer_service_url=assertion_consumer_service_url
        self.attribute_consuming_service_index=attribute_consuming_service_index
        self.provider_name=provider_name

def authn_request_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnRequestType, xml_string)

class AuthnRequest(AuthnRequestType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest element """

    c_tag = 'AuthnRequest'
    c_namespace = NAMESPACE
    c_children = AuthnRequestType.c_children.copy()
    c_attributes = AuthnRequestType.c_attributes.copy()
    c_child_order = AuthnRequestType.c_child_order[:]

def authn_request_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnRequest, xml_string)

#..................
# ['Status', 'StatusType', 'StatusCode', 'NameIDMappingResponseType', 'StatusCodeType', 'Response', 'ResponseType', 'LogoutResponse', 'ManageNameIDResponse', 'StatusResponseType', 'ArtifactResponse', 'ArtifactResponseType', 'NameIDMappingResponse']
class StatusType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:StatusType element """

    c_tag = 'StatusType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage'] = ('status_message', StatusMessage)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}StatusDetail'] = ('status_detail', StatusDetail)
    c_child_order.extend(['status_code', 'status_message', 'status_detail'])

    def __init__(self,
            status_code=None,
            status_message=None,
            status_detail=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.status_code=status_code
        self.status_message=status_message
        self.status_detail=status_detail

def status_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatusType, xml_string)

class Status(StatusType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:Status element """

    c_tag = 'Status'
    c_namespace = NAMESPACE
    c_children = StatusType.c_children.copy()
    c_attributes = StatusType.c_attributes.copy()
    c_child_order = StatusType.c_child_order[:]

def status_from_string(xml_string):
    return saml2.create_class_from_xml_string(Status, xml_string)

class StatusResponseType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:StatusResponseType element """

    c_tag = 'StatusResponseType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'] = ('issuer', saml.Issuer)
    c_children['{http://www.w3.org/2000/09/xmldsig#}Signature'] = ('signature', ds.Signature)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}Extensions'] = ('extensions', Extensions)
    c_children['{urn:oasis:names:tc:SAML:2.0:protocol}Status'] = ('status', Status)
    c_attributes['ID'] = ('id', 'ID', True)
    c_attributes['InResponseTo'] = ('in_response_to', 'NCName', False)
    c_attributes['Version'] = ('version', 'string', True)
    c_attributes['IssueInstant'] = ('issue_instant', 'dateTime', True)
    c_attributes['Destination'] = ('destination', 'anyURI', False)
    c_attributes['Consent'] = ('consent', 'anyURI', False)
    c_child_order.extend(['issuer', 'signature', 'extensions', 'status'])

    def __init__(self,
            issuer=None,
            signature=None,
            extensions=None,
            status=None,
            id=None,
            in_response_to=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.issuer=issuer
        self.signature=signature
        self.extensions=extensions
        self.status=status
        self.id=id
        self.in_response_to=in_response_to
        self.version=version
        self.issue_instant=issue_instant
        self.destination=destination
        self.consent=consent

def status_response_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatusResponseType, xml_string)

class ResponseType(StatusResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ResponseType element """

    c_tag = 'ResponseType'
    c_namespace = NAMESPACE
    c_children = StatusResponseType.c_children.copy()
    c_attributes = StatusResponseType.c_attributes.copy()
    c_child_order = StatusResponseType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Assertion'] = ('assertion', [saml.Assertion])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion'] = ('encrypted_assertion', [saml.EncryptedAssertion])
    c_child_order.extend(['assertion', 'encrypted_assertion'])

    def __init__(self,
            assertion=None,
            encrypted_assertion=None,
            issuer=None,
            signature=None,
            extensions=None,
            status=None,
            id=None,
            in_response_to=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        StatusResponseType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                status=status,
                id=id,
                in_response_to=in_response_to,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.assertion=assertion or []
        self.encrypted_assertion=encrypted_assertion or []

def response_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ResponseType, xml_string)

class ArtifactResponseType(StatusResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponseType element """

    c_tag = 'ArtifactResponseType'
    c_namespace = NAMESPACE
    c_children = StatusResponseType.c_children.copy()
    c_attributes = StatusResponseType.c_attributes.copy()
    c_child_order = StatusResponseType.c_child_order[:]

def artifact_response_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ArtifactResponseType, xml_string)

class ManageNameIDResponse(StatusResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ManageNameIDResponse element """

    c_tag = 'ManageNameIDResponse'
    c_namespace = NAMESPACE
    c_children = StatusResponseType.c_children.copy()
    c_attributes = StatusResponseType.c_attributes.copy()
    c_child_order = StatusResponseType.c_child_order[:]

def manage_name_id_response_from_string(xml_string):
    return saml2.create_class_from_xml_string(ManageNameIDResponse, xml_string)

class LogoutResponse(StatusResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse element """

    c_tag = 'LogoutResponse'
    c_namespace = NAMESPACE
    c_children = StatusResponseType.c_children.copy()
    c_attributes = StatusResponseType.c_attributes.copy()
    c_child_order = StatusResponseType.c_child_order[:]

def logout_response_from_string(xml_string):
    return saml2.create_class_from_xml_string(LogoutResponse, xml_string)

class NameIDMappingResponseType(StatusResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDMappingResponseType element """

    c_tag = 'NameIDMappingResponseType'
    c_namespace = NAMESPACE
    c_children = StatusResponseType.c_children.copy()
    c_attributes = StatusResponseType.c_attributes.copy()
    c_child_order = StatusResponseType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}NameID'] = ('name_id', saml.NameID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID'] = ('encrypted_id', saml.EncryptedID)
    c_child_order.extend(['name_id', 'encrypted_id'])

    def __init__(self,
            name_id=None,
            encrypted_id=None,
            issuer=None,
            signature=None,
            extensions=None,
            status=None,
            id=None,
            in_response_to=None,
            version=None,
            issue_instant=None,
            destination=None,
            consent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        StatusResponseType.__init__(self, 
                issuer=issuer,
                signature=signature,
                extensions=extensions,
                status=status,
                id=id,
                in_response_to=in_response_to,
                version=version,
                issue_instant=issue_instant,
                destination=destination,
                consent=consent,
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.name_id=name_id
        self.encrypted_id=encrypted_id

def name_id_mapping_response_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDMappingResponseType, xml_string)

class Response(ResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:Response element """

    c_tag = 'Response'
    c_namespace = NAMESPACE
    c_children = ResponseType.c_children.copy()
    c_attributes = ResponseType.c_attributes.copy()
    c_child_order = ResponseType.c_child_order[:]

def response_from_string(xml_string):
    return saml2.create_class_from_xml_string(Response, xml_string)

class ArtifactResponse(ArtifactResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse element """

    c_tag = 'ArtifactResponse'
    c_namespace = NAMESPACE
    c_children = ArtifactResponseType.c_children.copy()
    c_attributes = ArtifactResponseType.c_attributes.copy()
    c_child_order = ArtifactResponseType.c_child_order[:]

def artifact_response_from_string(xml_string):
    return saml2.create_class_from_xml_string(ArtifactResponse, xml_string)

class NameIDMappingResponse(NameIDMappingResponseType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDMappingResponse element """

    c_tag = 'NameIDMappingResponse'
    c_namespace = NAMESPACE
    c_children = NameIDMappingResponseType.c_children.copy()
    c_attributes = NameIDMappingResponseType.c_attributes.copy()
    c_child_order = NameIDMappingResponseType.c_child_order[:]

def name_id_mapping_response_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDMappingResponse, xml_string)

#..................
# ['StatusCode', 'StatusCodeType']
class StatusCodeType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:StatusCodeType element """

    c_tag = 'StatusCodeType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['Value'] = ('value', 'anyURI', True)
    c_child_order.extend(['status_code'])

    def __init__(self,
            status_code=None,
            value=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.status_code=status_code
        self.value=value

def status_code_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatusCodeType, xml_string)

class StatusCode(StatusCodeType):
    """The urn:oasis:names:tc:SAML:2.0:protocol:StatusCode element """

    c_tag = 'StatusCode'
    c_namespace = NAMESPACE
    c_children = StatusCodeType.c_children.copy()
    c_attributes = StatusCodeType.c_attributes.copy()
    c_child_order = StatusCodeType.c_child_order[:]

def status_code_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatusCode, xml_string)

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
StatusType.c_children['{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode'] = ('status_code', StatusCode)
Status.c_children['{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode'] = ('status_code', StatusCode)
StatusCodeType.c_children['{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode'] = ('status_code', StatusCode)
StatusCode.c_children['{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode'] = ('status_code', StatusCode)
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

ELEMENT_FROM_STRING = {
    RequestAbstractType.c_tag: request_abstract_type_from_string,
    Extensions.c_tag: extensions_from_string,
    ExtensionsType.c_tag: extensions_type_from_string,
    StatusResponseType.c_tag: status_response_type_from_string,
    Status.c_tag: status_from_string,
    StatusType.c_tag: status_type_from_string,
    StatusCode.c_tag: status_code_from_string,
    StatusCodeType.c_tag: status_code_type_from_string,
    StatusMessage.c_tag: status_message_from_string,
    StatusDetail.c_tag: status_detail_from_string,
    StatusDetailType.c_tag: status_detail_type_from_string,
    AssertionIDRequest.c_tag: assertion_id_request_from_string,
    AssertionIDRequestType.c_tag: assertion_id_request_type_from_string,
    SubjectQuery.c_tag: subject_query_from_string,
    SubjectQueryAbstractType.c_tag: subject_query_abstract_type_from_string,
    AuthnQuery.c_tag: authn_query_from_string,
    AuthnQueryType.c_tag: authn_query_type_from_string,
    RequestedAuthnContext.c_tag: requested_authn_context_from_string,
    RequestedAuthnContextType.c_tag: requested_authn_context_type_from_string,
    AuthnContextComparisonType.c_tag: authn_context_comparison_type_from_string,
    AttributeQuery.c_tag: attribute_query_from_string,
    AttributeQueryType.c_tag: attribute_query_type_from_string,
    AuthzDecisionQuery.c_tag: authz_decision_query_from_string,
    AuthzDecisionQueryType.c_tag: authz_decision_query_type_from_string,
    AuthnRequest.c_tag: authn_request_from_string,
    AuthnRequestType.c_tag: authn_request_type_from_string,
    NameIDPolicy.c_tag: name_id_policy_from_string,
    NameIDPolicyType.c_tag: name_id_policy_type_from_string,
    Scoping.c_tag: scoping_from_string,
    ScopingType.c_tag: scoping_type_from_string,
    RequesterID.c_tag: requester_id_from_string,
    IDPList.c_tag: idp_list_from_string,
    IDPListType.c_tag: idp_list_type_from_string,
    IDPEntry.c_tag: idp_entry_from_string,
    IDPEntryType.c_tag: idp_entry_type_from_string,
    GetComplete.c_tag: get_complete_from_string,
    Response.c_tag: response_from_string,
    ResponseType.c_tag: response_type_from_string,
    ArtifactResolve.c_tag: artifact_resolve_from_string,
    ArtifactResolveType.c_tag: artifact_resolve_type_from_string,
    Artifact.c_tag: artifact_from_string,
    ArtifactResponse.c_tag: artifact_response_from_string,
    ArtifactResponseType.c_tag: artifact_response_type_from_string,
    ManageNameIDRequest.c_tag: manage_name_id_request_from_string,
    ManageNameIDRequestType.c_tag: manage_name_id_request_type_from_string,
    NewID.c_tag: new_id_from_string,
    NewEncryptedID.c_tag: new_encrypted_id_from_string,
    Terminate.c_tag: terminate_from_string,
    TerminateType.c_tag: terminate_type_from_string,
    ManageNameIDResponse.c_tag: manage_name_id_response_from_string,
    LogoutRequest.c_tag: logout_request_from_string,
    LogoutRequestType.c_tag: logout_request_type_from_string,
    SessionIndex.c_tag: session_index_from_string,
    LogoutResponse.c_tag: logout_response_from_string,
    NameIDMappingRequest.c_tag: name_id_mapping_request_from_string,
    NameIDMappingRequestType.c_tag: name_id_mapping_request_type_from_string,
    NameIDMappingResponse.c_tag: name_id_mapping_response_from_string,
    NameIDMappingResponseType.c_tag: name_id_mapping_response_type_from_string,
}

ELEMENT_BY_TAG = {
    'RequestAbstractType': RequestAbstractType,
    'Extensions': Extensions,
    'ExtensionsType': ExtensionsType,
    'StatusResponseType': StatusResponseType,
    'Status': Status,
    'StatusType': StatusType,
    'StatusCode': StatusCode,
    'StatusCodeType': StatusCodeType,
    'StatusMessage': StatusMessage,
    'StatusDetail': StatusDetail,
    'StatusDetailType': StatusDetailType,
    'AssertionIDRequest': AssertionIDRequest,
    'AssertionIDRequestType': AssertionIDRequestType,
    'SubjectQuery': SubjectQuery,
    'SubjectQueryAbstractType': SubjectQueryAbstractType,
    'AuthnQuery': AuthnQuery,
    'AuthnQueryType': AuthnQueryType,
    'RequestedAuthnContext': RequestedAuthnContext,
    'RequestedAuthnContextType': RequestedAuthnContextType,
    'AuthnContextComparisonType': AuthnContextComparisonType,
    'AttributeQuery': AttributeQuery,
    'AttributeQueryType': AttributeQueryType,
    'AuthzDecisionQuery': AuthzDecisionQuery,
    'AuthzDecisionQueryType': AuthzDecisionQueryType,
    'AuthnRequest': AuthnRequest,
    'AuthnRequestType': AuthnRequestType,
    'NameIDPolicy': NameIDPolicy,
    'NameIDPolicyType': NameIDPolicyType,
    'Scoping': Scoping,
    'ScopingType': ScopingType,
    'RequesterID': RequesterID,
    'IDPList': IDPList,
    'IDPListType': IDPListType,
    'IDPEntry': IDPEntry,
    'IDPEntryType': IDPEntryType,
    'GetComplete': GetComplete,
    'Response': Response,
    'ResponseType': ResponseType,
    'ArtifactResolve': ArtifactResolve,
    'ArtifactResolveType': ArtifactResolveType,
    'Artifact': Artifact,
    'ArtifactResponse': ArtifactResponse,
    'ArtifactResponseType': ArtifactResponseType,
    'ManageNameIDRequest': ManageNameIDRequest,
    'ManageNameIDRequestType': ManageNameIDRequestType,
    'NewID': NewID,
    'NewEncryptedID': NewEncryptedID,
    'Terminate': Terminate,
    'TerminateType': TerminateType,
    'ManageNameIDResponse': ManageNameIDResponse,
    'LogoutRequest': LogoutRequest,
    'LogoutRequestType': LogoutRequestType,
    'SessionIndex': SessionIndex,
    'LogoutResponse': LogoutResponse,
    'NameIDMappingRequest': NameIDMappingRequest,
    'NameIDMappingRequestType': NameIDMappingRequestType,
    'NameIDMappingResponse': NameIDMappingResponse,
    'NameIDMappingResponseType': NameIDMappingResponseType,
}

def factory(tag, **kwargs):
    return ELEMENT_BY_TAG[tag](**kwargs)

