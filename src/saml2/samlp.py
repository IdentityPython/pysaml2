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

"""Contains classes representing Samlp elements.

    Module objective: provide data classes for Samlp constructs. These
    classes hide the XML-ness of Saml and provide a set of native Python
    classes to interact with.

"""

from saml2 import saml, SamlBase, create_class_from_xml_string
import xmldsig as ds

SAMLP_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:protocol'
SAMLP_TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:protocol}%s'

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

class Extensions(SamlBase):
    """The samlp:Extensions element"""

    c_tag = 'Extensions'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def extensions_from_string(xml_string):
    """ Create Extensions instance from an XML string """
    return create_class_from_xml_string(Extensions, xml_string)


class AbstractRequest(SamlBase):
    """The samlp:RequestAbstractType element"""

    c_tag = 'AbstractRequest'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['ID'] = 'identifier'
    c_attributes['Version'] = 'version'
    c_attributes['IssueInstant'] = 'issue_instant'
    c_attributes['Destination'] = 'destination'
    c_attributes['Consent'] = 'consent'
    c_children['{%s}Issuer' % saml.SAML_NAMESPACE] = ('issuer', saml.Issuer)
    c_children['{%s}Signature' % ds.DS_NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Extensions' % SAMLP_NAMESPACE] = ('extensions', Extensions)
    c_child_order = ['issuer', 'signature', 'extensions']

    def __init__(self, identifier=None, version=None, issue_instant=None,
                destination=None, consent=None, issuer=None, signature=None,
                extensions=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for AbstractRequest

        :param identifier: ID attribute
        :param version: Version attribute
        :param issue_instant: IssueInstant attribute
        :param destination: Destination attribute
        :param consent: Consent attribute
        :param issuer: Issuer element
        :param signature: Signature element
        :param extensions: Extensions element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier
        self.version = version
        self.issue_instant = issue_instant
        self.destination = destination
        self.consent = consent
        self.issuer = issuer
        self.signature = signature
        self.extensions = extensions

def abstract_request_from_string(xml_string):
    """ Create AbstractRequest instance from an XML string """
    return create_class_from_xml_string(AbstractRequest, xml_string)

class StatusDetail(SamlBase):
    """The samlp:StatusDetail element"""
    c_tag = 'StatusDetail'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def status_detail_from_string(xml_string):
    """ Create StatusDetail instance from an XML string """
    return create_class_from_xml_string(StatusDetail, xml_string)

class StatusMessage(SamlBase):
    """The samlp:StatusMessage element"""
    c_tag = 'StatusMessage'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def status_message_from_string(xml_string):
    """ Create StatusMessage instance from an XML string """
    return create_class_from_xml_string(StatusMessage, xml_string)

class StatusCode(SamlBase):
    """The samlp:StatusCode element"""
    c_tag = 'StatusCode'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Value'] = 'value'
    
    def __init__(self, value=None, status_code=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for Status

        :param value: Value attribute
        :param status_code: StatusCode element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.value = value
        self.status_code = status_code

def status_code_from_string(xml_string):
    """ Create StatusCode instance from an XML string """
    return create_class_from_xml_string(StatusCode, xml_string)

StatusCode.c_children['{%s}StatusCode' % SAMLP_NAMESPACE] = (
    'status_code', StatusCode)


class Status(SamlBase):
    """The samlp:Status element"""

    c_tag = 'Status'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}StatusCode' % SAMLP_NAMESPACE] = ('status_code', StatusCode)
    c_children['{%s}StatusMessage' % SAMLP_NAMESPACE] = (
        'status_message', StatusMessage)
    c_children['{%s}StatusDetail' % SAMLP_NAMESPACE] = (
        'status_detail', StatusDetail)
    c_child_order = ['status_code', 'status_message', 'status_detail']

    def __init__(self, status_code=None, status_message=None, 
                status_detail=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for Status

        :param status_code: StatusCode element
        :param status_message: StatusMessage element
        :param status_detail: StatusDetail element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.status_code = status_code
        self.status_message = status_message
        self.status_detail = status_detail

def status_from_string(xml_string):
    """ Create Status instance from an XML string """
    return create_class_from_xml_string(Status, xml_string)


class StatusResponse(SamlBase):
    """The samlp:StatusResponse element"""

    c_tag = 'StatusResponse'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['ID'] = 'identifier'
    c_attributes['InResponseTo'] = 'in_response_to'
    c_attributes['Version'] = 'version'
    c_attributes['IssueInstant'] = 'issue_instant'
    c_attributes['Destination'] = 'destination'
    c_attributes['Consent'] = 'consent'
    c_children['{%s}Issuer' % saml.SAML_NAMESPACE] = ('issuer', saml.Issuer)
    c_children['{%s}Signature' % ds.DS_NAMESPACE] = ('signature', ds.Signature)
    c_children['{%s}Extensions' % SAMLP_NAMESPACE] = ('extensions', Extensions)
    c_children['{%s}Status' % SAMLP_NAMESPACE] = ('status', Status)
    c_child_order = ['issuer', 'signature', 'extensions', 'status']

    def __init__(self, identifier=None, in_response_to=None, version=None,
                issue_instant=None, destination=None, consent=None,
                issuer=None, signature=None, extensions=None, status=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for StatusResponse

        :param identifier: ID attribute
        :param in_respones_to: InResponseTo attribute
        :param version: Version attribute
        :param issue_instant: IssueInstant attribute
        :param destination: Destination attribute
        :param consent: Consent attribute
        :param issuer: Issuer element
        :param signature: Signature element
        :param extensions: Extensions element
        :param status: Status element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier
        self.in_response_to = in_response_to
        self.version = version
        self.issue_instant = issue_instant
        self.destination = destination
        self.consent = consent
        self.issuer = issuer
        self.signature = signature
        self.extensions = extensions
        self.status = status

def status_response_from_string(xml_string):
    """ Create StatusResponse instance from an XML string """
    return create_class_from_xml_string(StatusResponse, xml_string)


class Response(StatusResponse):
    """The samlp:Response element"""

    c_tag = 'Response'
    c_namespace = SAMLP_NAMESPACE
    c_children = StatusResponse.c_children.copy()
    c_attributes = StatusResponse.c_attributes.copy()
    c_children['{%s}Assertion' % saml.SAML_NAMESPACE] = (
        'assertion', [saml.Assertion])
    c_children['{%s}EncryptedAssertion' % saml.SAML_NAMESPACE] = (
        'encrypted_assertion', [saml.EncryptedAssertion])
    c_child_order = ['issuer', 'signature', 'extensions', 'status', 'assertion',
                    'encrypted_assertion']

    def __init__(self, identifier=None, in_response_to=None, version=None,
                issue_instant=None, destination=None, consent=None,
                issuer=None, signature=None, extensions=None, status=None,
                assertion=None, encrypted_assertion=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for Response

        :param identifier: ID attribute
        :param in_respones_to: InResponseTo attribute
        :param version: Version attribute
        :param issue_instant: IssueInstant attribute
        :param destination: Destination attribute
        :param consent: Consent attribute
        :param issuer: Issuer element
        :param signature: Signature element
        :param extensions: Extensions element
        :param status: Status element
        :param assertion: Assertion elements
        :param encrypted_assertion: EncryptedAssertion elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        StatusResponse.__init__(self, identifier, in_response_to,
                                version, issue_instant,
                                destination, consent,
                                issuer, signature,
                                extensions, status, text,
                                extension_elements, extension_attributes)
        self.assertion = assertion or []
        self.encrypted_assertion = encrypted_assertion or []

def response_from_string(xml_string):
    """ Create Response instance from an XML string """
    return create_class_from_xml_string(Response, xml_string)


class NameIDPolicy(SamlBase):
    """The samlp:NameIDPolicy element"""

    c_tag = 'NameIDPolicy'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Format'] = 'format'
    c_attributes['SPNameQualifier'] = 'sp_name_qualifier'
    c_attributes['AllowCreate'] = 'allow_create'

    def __init__(self, format=None, sp_name_qualifier=None, allow_create=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for NameIDPolicy

        :param format: Format attribute
        :param sp_name_qualifier: SPNameQualifier attribute
        :param allow_create: AllowCreate attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.format = format
        self.sp_name_qualifier = sp_name_qualifier
        self.allow_create = allow_create

def name_id_policy_from_string(xml_string):
    """ Create NameIDPolicy instance from an XML string """
    return create_class_from_xml_string(NameIDPolicy, xml_string)


class IDPEntry(SamlBase):
    """The samlp:IDPEntry element"""

    c_tag = 'IDPEntry'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['ProviderID'] = 'provider_id'
    c_attributes['Name'] = 'name'
    c_attributes['Loc'] = 'loc'

    def __init__(self, provider_id=None, name=None, loc=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for IDPEntry

        :param provider_id: ProviderID attribute
        :param name: Name attribute
        :param loc: Loc attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.provider_id = provider_id
        self.name = name
        self.loc = loc

def idp_entry_from_string(xml_string):
    """ Create IDPEntry instance from an XML string """
    return create_class_from_xml_string(IDPEntry, xml_string)


class GetComplete(SamlBase):
    """The samlp:GetComplete element"""

    c_tag = 'GetComplete'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def get_complete_from_string(xml_string):
    """ Create GetComplete instance from an XML string """
    return create_class_from_xml_string(GetComplete, xml_string)


class IDPList(SamlBase):
    """The samlp:IDPList element"""

    c_tag = 'IDPList'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_children['{%s}IDPEntry' % SAMLP_NAMESPACE] = ('idp_entry', [IDPEntry])
    c_children['{%s}GetComplete' % SAMLP_NAMESPACE] = (
        'get_complete', GetComplete)
    c_child_order = ['idp_entry', 'get_complete']

    def __init__(self, idp_entry=None, get_complete=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for IDPList

        :param idp_entry: IDPEntry elements
        :param get_complete: GetComplete element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.idp_entry = idp_entry or []
        self.get_complete = get_complete

def idp_list_from_string(xml_string):
    """ Create IDPList instance from an XML string """
    return create_class_from_xml_string(IDPList, xml_string)


class RequesterID(SamlBase):
    """The samlp:RequesterID element"""
    c_tag = 'RequesterID'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def requester_id_from_string(xml_string):
    """ Create RequesterID instance from an XML string """
    return create_class_from_xml_string(RequesterID, xml_string)


class Scoping(SamlBase):
    """The samlp:Scoping element"""

    c_tag = 'Scoping'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['ProxyCount'] = 'proxy_count'
    c_children['{%s}IDPList' % SAMLP_NAMESPACE] = ('idp_list', IDPList)
    c_children['{%s}RequesterID' % SAMLP_NAMESPACE] = (
        'requester_id', [RequesterID])
    c_child_order = ['idp_list', 'requester_id']

    def __init__(self, proxy_count=None, idp_list=None, requester_id=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for Scoping

        :param proxy_count: ProxyCount attribute
        :param idp_list: IDPList element
        :param requester_id: list A list of RequesterID instances
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.proxy_count = proxy_count
        self.idp_list = idp_list
        self.requester_id = requester_id or []

def scoping_from_string(xml_string):
    """ Create Scoping instance from an XML string """
    return create_class_from_xml_string(Scoping, xml_string)


class RequestedAuthnContext(SamlBase):
    """The samlp:RequestedAuthnContext element"""

    c_tag = 'RequestedAuthnContext'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Comparison'] = 'comparison'
    c_children['{%s}AuthnContextClassRef' % saml.SAML_NAMESPACE] = (
        'authn_context_class_ref', [saml.AuthnContextClassRef])
    c_children['{%s}AuthnContextDeclRef' % saml.SAML_NAMESPACE] = (
        'authn_context_decl_ref', [saml.AuthnContextDeclRef])

    def __init__(self, comparison=None, authn_context_class_ref=None,
                authn_context_decl_ref=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for RequestedAuthnContext

        :param comparison: Comparison attribute
        :param authn_context_class_ref: list A list of AuthnContextClassRef instances
        :param authn_context_decl_ref: list A list of AuthnContextDeclRef instances
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        SamlBase.__init__(self, text, extension_elements, extension_attributes)
        self.comparison = comparison
        self.authn_context_class_ref = authn_context_class_ref or []
        self.authn_context_decl_ref = authn_context_decl_ref or []

def requested_authn_context_from_string(xml_string):
    """ Create RequestedAuthnContext instance from an XML string """
    return create_class_from_xml_string(RequestedAuthnContext, xml_string)


class AuthnRequest(AbstractRequest):
    """The samlp:AuthnRequest element"""

    c_tag = 'AuthnRequest'
    c_namespace = SAMLP_NAMESPACE
    c_children = AbstractRequest.c_children.copy()
    c_attributes = AbstractRequest.c_attributes.copy()
    c_attributes['ForceAuthn'] = 'force_authn'
    c_attributes['IsPassive'] = 'is_passive'
    c_attributes['AssertionConsumerServiceIndex'] = \
                            'assertion_consumer_service_index'
    c_attributes['AssertionConsumerServiceURL'] = \
                            'assertion_consumer_service_url'
    c_attributes['ProtocolBinding'] = 'protocol_binding'
    c_attributes['AssertionConsumingServiceIndex'] = \
                            'assertion_consuming_service_index'
    c_attributes['ProviderName'] = 'provider_name'
    c_children['{%s}Subject' % saml.SAML_NAMESPACE] = ('subject', saml.Subject)
    c_children['{%s}NameIDPolicy' % SAMLP_NAMESPACE] = (
                            'name_id_policy', NameIDPolicy)
    c_children['{%s}Conditions' % saml.SAML_NAMESPACE] = (
                            'conditions', saml.Conditions)
    c_children['{%s}RequestedAuthnContext' % SAMLP_NAMESPACE] = (
                            'requested_authn_context', RequestedAuthnContext)
    c_children['{%s}Scoping' % SAMLP_NAMESPACE] = ('scoping', Scoping)
    c_child_order = ['issuer', 'signature', 'extensions', 'subject',
                    'name_id_policy', 'conditions', 'requested_authn_context',
                    'scoping']

    def __init__(self, identifier=None, version=None, issue_instant=None,
                destination=None, consent=None, issuer=None, signature=None,
                extensions=None, subject=None, name_id_policy=None,
                conditions=None, requested_authn_context=None, scoping=None,
                force_authn=None, is_passive=None,
                assertion_consumer_service_index=None,
                assertion_consumer_service_url=None,
                protocol_binding=None, assertion_consuming_service_index=None,
                provider_name=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for AuthnRequest

        :param identifier: ID attribute
        :param version: Version attribute
        :param issue_instant: IssueInstant attribute
        :param destination: Destination attribute
        :param consent: Consent attribute
        :param issuer: Issuer element
        :param signature: Signature element
        :param extensions: Extensions element
        :param subject: Subject element
        :param name_id_policy: NameIDPolicy element
        :param conditions: Conditions element
        :param requested_authn_context: RequestedAuthnContext element
        :param scoping: Scoping element
        :param force_authn: ForceAuthn attribute
        :param is_passive: IsPassive attribute
        :param assertion_consumer_service_index: AssertionConsumerServiceIndex 
                element
        :param assertion_consumer_service_url: AssertionConsumerServiceURL 
                element
        :param protocol_binding: ProtocolBinding element
        :param assertion_consuming_service_index: 
                AssertionConsumingServiceIndex element
        :param provider_name: ProviderName element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """
        AbstractRequest.__init__(self, identifier, version, issue_instant, 
                                destination, consent, issuer, signature, 
                                extensions, text, extension_elements, 
                                extension_attributes)
        self.subject = subject
        self.name_id_policy = name_id_policy
        self.conditions = conditions
        self.requested_authn_context = requested_authn_context
        self.conditions = conditions
        self.requested_authn_context = requested_authn_context
        self.scoping = scoping
        self.force_authn = force_authn
        self.is_passive = is_passive
        self.assertion_consumer_service_index = assertion_consumer_service_index
        self.assertion_consumer_service_url = assertion_consumer_service_url
        self.protocol_binding = protocol_binding
        self.assertion_consuming_service_index = \
                    assertion_consuming_service_index
        self.provider_name = provider_name

def authn_request_from_string(xml_string):
    """ Create AuthnRequest instance from an XML string """
    return create_class_from_xml_string(AuthnRequest, xml_string)


class SessionIndex(SamlBase):
    """The samlp:SessionIndex element"""
    c_tag = 'SessionIndex'
    c_namespace = SAMLP_NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()

def session_index_from_string(xml_string):
    """ Create SessionIndex instance from an XML string """
    return create_class_from_xml_string(SessionIndex, xml_string)


class LogoutRequest(AbstractRequest):
    """The samlp:LogoutRequest element"""

    c_tag = 'LogoutRequest'
    c_namespace = SAMLP_NAMESPACE
    c_children = AbstractRequest.c_children.copy()
    c_attributes = AbstractRequest.c_attributes.copy()
    c_attributes['NotOnOrAfter'] = 'not_on_or_after'
    c_attributes['Reason'] = 'reason'
    c_children['{%s}BaseID' % saml.SAML_NAMESPACE] = ('base_id', saml.BaseID)
    c_children['{%s}NameID' % saml.SAML_NAMESPACE] = ('name_id', saml.NameID)
    c_children['{%s}EncryptedID' % saml.SAML_NAMESPACE] = (
        'encrypted_id', saml.EncryptedID)
    c_children['{%s}SessionIndex' % SAMLP_NAMESPACE] = (
        'session_index', SessionIndex)
    c_child_order = ['issuer', 'signature', 'extensions', 'base_id', 'name_id',
                                    'encrypted_id', 'session_index']

    def __init__(self, identifier=None, version=None, issue_instant=None,
                destination=None, consent=None, issuer=None, signature=None,
                extensions=None, not_on_or_after=None, reason=None,
                base_id=None, name_id=None, encrypted_id=None,
                session_index=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for LogoutRequest

        :param identifier: ID attribute
        :param version: Version attribute
        :param issue_instant: IssueInstant attribute
        :param destination: Destination attribute
        :param consent: Consent attribute
        :param issuer: Issuer element
        :param signature: Signature element
        :param extensions: Extensions element
        :param not_on_or_after: NotOnOrAfter attribute
        :param reason: Reason attribute
        :param base_id: BaseID element
        :param name_id: NameID element
        :param encrypted_id: EncryptedID element
        :param session_index: SessionIndex element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """
        AbstractRequest.__init__(self, identifier, version, issue_instant, 
                                destination, consent, issuer, signature, 
                                extensions, text, extension_elements, 
                                extension_attributes)
        self.not_on_or_after = not_on_or_after
        self.reason = reason
        self.base_id = base_id
        self.name_id = name_id
        self.encrypted_id = encrypted_id
        self.session_index = session_index

def logout_request_from_string(xml_string):
    """ Create LogoutRequest instance from an XML string """
    return create_class_from_xml_string(LogoutRequest, xml_string)


class LogoutResponse(StatusResponse):
    """The samlp:LogoutResponse element"""

    c_tag = 'LogoutResponse'
    c_namespace = SAMLP_NAMESPACE
    c_children = StatusResponse.c_children.copy()
    c_attributes = StatusResponse.c_attributes.copy()

def logout_response_from_string(xml_string):
    """ Create LogoutResponse instance from an XML string """
    return create_class_from_xml_string(LogoutResponse, xml_string)
