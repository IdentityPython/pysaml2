#!/usr/bin/env python

#
# Generated Thu Jul 15 21:01:26 2010 by parse_xsd.py version 0.3.
#

import saml2
from saml2 import SamlBase

import xmldsig as ds
import xmlenc as xenc

NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'

XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'
XS_NAMESPACE = 'http://www.w3.org/2001/XMLSchema'

XSI_TYPE = '{%s}type' % XSI_NAMESPACE

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
NAMEID_FORMAT_ENTITY = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")

PROFILE_ATTRIBUTE_BASIC = (
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic")

AUTHN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
AUTHN_PASSWORD_PROTECTED = \
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        
NAME_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

CONSENT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"


class BaseIDAbstractType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:BaseIDAbstractType element """

    c_tag = 'BaseIDAbstractType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['NameQualifier'] = ('name_qualifier', 'string', False)
    c_attributes['SPNameQualifier'] = ('sp_name_qualifier', 'string', False)

    def __init__(self,
            name_qualifier=None,
            sp_name_qualifier=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.name_qualifier=name_qualifier
        self.sp_name_qualifier=sp_name_qualifier

def base_id_abstract_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(BaseIDAbstractType, xml_string)

class NameIDType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:NameIDType element """

    c_tag = 'NameIDType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['NameQualifier'] = ('name_qualifier', 'string', False)
    c_attributes['SPNameQualifier'] = ('sp_name_qualifier', 'string', False)
    c_attributes['Format'] = ('format', 'anyURI', False)
    c_attributes['SPProvidedID'] = ('sp_provided_id', 'string', False)

    def __init__(self,
            name_qualifier=None,
            sp_name_qualifier=None,
            format=None,
            sp_provided_id=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.name_qualifier=name_qualifier
        self.sp_name_qualifier=sp_name_qualifier
        self.format=format
        self.sp_provided_id=sp_provided_id

def name_id_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameIDType, xml_string)

class EncryptedElementType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:EncryptedElementType element """

    c_tag = 'EncryptedElementType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{http://www.w3.org/2001/04/xmlenc#}EncryptedData'] = ('encrypted_data', xenc.EncryptedData)
    c_children['{http://www.w3.org/2001/04/xmlenc#}EncryptedKey'] = ('encrypted_key', [xenc.EncryptedKey])
    c_child_order.extend(['encrypted_data', 'encrypted_key'])

    def __init__(self,
            encrypted_data=None,
            encrypted_key=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.encrypted_data=encrypted_data
        self.encrypted_key=encrypted_key or []

def encrypted_element_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(EncryptedElementType, xml_string)

class EncryptedID(EncryptedElementType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:EncryptedID element """

    c_tag = 'EncryptedID'
    c_namespace = NAMESPACE
    c_children = EncryptedElementType.c_children.copy()
    c_attributes = EncryptedElementType.c_attributes.copy()
    c_child_order = EncryptedElementType.c_child_order[:]

def encrypted_id_from_string(xml_string):
    return saml2.create_class_from_xml_string(EncryptedID, xml_string)

class Issuer(NameIDType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Issuer element """

    c_tag = 'Issuer'
    c_namespace = NAMESPACE
    c_children = NameIDType.c_children.copy()
    c_attributes = NameIDType.c_attributes.copy()
    c_child_order = NameIDType.c_child_order[:]

def issuer_from_string(xml_string):
    return saml2.create_class_from_xml_string(Issuer, xml_string)

class AssertionIDRef(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AssertionIDRef element """

    c_tag = 'AssertionIDRef'
    c_namespace = NAMESPACE
    c_value_type = 'NCName'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def assertion_id_ref_from_string(xml_string):
    return saml2.create_class_from_xml_string(AssertionIDRef, xml_string)

class AssertionURIRef(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AssertionURIRef element """

    c_tag = 'AssertionURIRef'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def assertion_uri_ref_from_string(xml_string):
    return saml2.create_class_from_xml_string(AssertionURIRef, xml_string)

class SubjectConfirmationDataType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:SubjectConfirmationDataType element """

    c_tag = 'SubjectConfirmationDataType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['NotBefore'] = ('not_before', 'dateTime', False)
    c_attributes['NotOnOrAfter'] = ('not_on_or_after', 'dateTime', False)
    c_attributes['Recipient'] = ('recipient', 'anyURI', False)
    c_attributes['InResponseTo'] = ('in_response_to', 'NCName', False)
    c_attributes['Address'] = ('address', 'string', False)

    def __init__(self,
            not_before=None,
            not_on_or_after=None,
            recipient=None,
            in_response_to=None,
            address=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.not_before=not_before
        self.not_on_or_after=not_on_or_after
        self.recipient=recipient
        self.in_response_to=in_response_to
        self.address=address

def subject_confirmation_data_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectConfirmationDataType, xml_string)

class KeyInfoConfirmationDataType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:KeyInfoConfirmationDataType element """

    c_tag = 'KeyInfoConfirmationDataType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{http://www.w3.org/2000/09/xmldsig#}KeyInfo'] = ('key_info', [ds.KeyInfo])
    c_child_order.extend(['key_info'])

    def __init__(self,
            key_info=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.key_info=key_info or []

def key_info_confirmation_data_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyInfoConfirmationDataType, xml_string)

class ConditionAbstractType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:ConditionAbstractType element """

    c_tag = 'ConditionAbstractType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def condition_abstract_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ConditionAbstractType, xml_string)

class Audience(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Audience element """

    c_tag = 'Audience'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def audience_from_string(xml_string):
    return saml2.create_class_from_xml_string(Audience, xml_string)

class OneTimeUseType(ConditionAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:OneTimeUseType element """

    c_tag = 'OneTimeUseType'
    c_namespace = NAMESPACE
    c_children = ConditionAbstractType.c_children.copy()
    c_attributes = ConditionAbstractType.c_attributes.copy()
    c_child_order = ConditionAbstractType.c_child_order[:]

def one_time_use_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(OneTimeUseType, xml_string)

class ProxyRestrictionType(ConditionAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:ProxyRestrictionType element """

    c_tag = 'ProxyRestrictionType'
    c_namespace = NAMESPACE
    c_children = ConditionAbstractType.c_children.copy()
    c_attributes = ConditionAbstractType.c_attributes.copy()
    c_child_order = ConditionAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Audience'] = ('audience', [Audience])
    c_attributes['Count'] = ('count', 'nonNegativeInteger', False)
    c_child_order.extend(['audience'])

    def __init__(self,
            audience=None,
            count=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        ConditionAbstractType.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.audience=audience or []
        self.count=count

def proxy_restriction_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ProxyRestrictionType, xml_string)

class EncryptedAssertion(EncryptedElementType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:EncryptedAssertion element """

    c_tag = 'EncryptedAssertion'
    c_namespace = NAMESPACE
    c_children = EncryptedElementType.c_children.copy()
    c_attributes = EncryptedElementType.c_attributes.copy()
    c_child_order = EncryptedElementType.c_child_order[:]

def encrypted_assertion_from_string(xml_string):
    return saml2.create_class_from_xml_string(EncryptedAssertion, xml_string)

class StatementAbstractType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:StatementAbstractType element """

    c_tag = 'StatementAbstractType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def statement_abstract_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(StatementAbstractType, xml_string)

class SubjectLocalityType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:SubjectLocalityType element """

    c_tag = 'SubjectLocalityType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['Address'] = ('address', 'string', False)
    c_attributes['DNSName'] = ('dns_name', 'string', False)

    def __init__(self,
            address=None,
            dns_name=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.address=address
        self.dns_name=dns_name

def subject_locality_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectLocalityType, xml_string)

class AuthnContextClassRef(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextClassRef element """

    c_tag = 'AuthnContextClassRef'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def authn_context_class_ref_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnContextClassRef, xml_string)

class AuthnContextDeclRef(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextDeclRef element """

    c_tag = 'AuthnContextDeclRef'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def authn_context_decl_ref_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnContextDeclRef, xml_string)

class AuthnContextDecl(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextDecl element """

    c_tag = 'AuthnContextDecl'
    c_namespace = NAMESPACE
    c_value_type = 'anyType'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def authn_context_decl_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnContextDecl, xml_string)

class AuthenticatingAuthority(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthenticatingAuthority element """

    c_tag = 'AuthenticatingAuthority'
    c_namespace = NAMESPACE
    c_value_type = 'anyURI'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def authenticating_authority_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthenticatingAuthority, xml_string)

class DecisionType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:DecisionType element """

    c_tag = 'DecisionType'
    c_namespace = NAMESPACE
    c_value_type = {'base': 'string', 'enumeration': ['Permit', 'Deny', 'Indeterminate']}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

def decision_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(DecisionType, xml_string)

class ActionType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:ActionType element """

    c_tag = 'ActionType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_attributes['Namespace'] = ('namespace', 'anyURI', True)

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

def action_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ActionType, xml_string)

# -------------------- AttributeValue --------------------
XSD = "xs:"
NS_SOAP_ENC = "http://schemas.xmlsoap.org/soap/encoding/"

def _decode_attribute_value(typ, text):

    if typ == XSD + "string":
        return text or ""
    if typ == XSD + "integer" or typ == XSD + "int":
        return str(int(text))
    if typ == XSD + "float" or typ == XSD + "double":
        return str(float(text))
    if typ == XSD + "boolean":
        return "%s" % (text == "true" or text == "True")
    if typ == XSD + "base64Binary":
        import base64
        return base64.decodestring(text)
    raise ValueError("type %s not supported" % type)

def _verify_value_type(typ, val):
    #print "verify value type: %s, %s" % (typ, val)
    if typ == XSD + "string":
        try:
            return str(val)
        except UnicodeEncodeError:
            return unicode(val)
    if typ == XSD + "integer" or typ == XSD + "int":
        return int(val)
    if typ == XSD + "float" or typ == XSD + "double":
        return float(val)
    if typ == XSD + "boolean":
        if (val.lower() == "true" or val.lower() == "false"):
            pass
        else:
            raise ValueError("Faulty boolean value")
    if typ == XSD + "base64Binary":
        import base64
        return base64.decodestring(val)

TYPE_EXTENSION = '{%s}type' % XSI_NAMESPACE

class AttributeValue(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AttributeValue element """

    c_tag = 'AttributeValue'
    c_namespace = NAMESPACE
    c_value_type = 'anyType'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]

    def set_type(self, typ):
        self.extension_attributes[TYPE_EXTENSION] = typ

    def get_type(self):
        try:
            return self.extension_attributes[TYPE_EXTENSION]
        except KeyError:
            return ""
        
    def set_text(self, val, base64encode=False):
        typ = self.get_type()
        if base64encode:
            import base64
            val = base64.encodestring(val)
            self.set_type("xs:base64Binary")
        else:
            if isinstance(val, basestring):
                if not typ:
                    self.set_type("xs:string")
            elif isinstance(val, bool):
                if val:
                    val = "true"
                else:
                    val = "false"
                if not typ:
                    self.set_type("xs:boolean")
            elif isinstance(val, int):
                val = str(val)
                if not typ:
                    self.set_type("xs:integer")
            elif isinstance(val, float):
                val = str(val)
                if not typ:
                    self.set_type("xs:float")
            elif val == None:
                val = ""
            else:
                raise ValueError
                
        setattr(self, "text", val)
        return self

    def harvest_element_tree(self, tree):
        # Fill in the instance members from the contents of the XML tree.
        for child in tree:
            self._convert_element_tree_to_member(child)
        for attribute, value in tree.attrib.iteritems():
            self._convert_element_attribute_to_member(attribute, value)
        if tree.text:
            #print "set_text:", tree.text
            self.set_text(tree.text)
            try:
                typ = self.extension_attributes[TYPE_EXTENSION]
                _x = _verify_value_type(typ, getattr(self,"text"))
            except KeyError:
                pass
            #print _x
            
def attribute_value_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeValue, xml_string)

class EncryptedAttribute(EncryptedElementType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:EncryptedAttribute element """

    c_tag = 'EncryptedAttribute'
    c_namespace = NAMESPACE
    c_children = EncryptedElementType.c_children.copy()
    c_attributes = EncryptedElementType.c_attributes.copy()
    c_child_order = EncryptedElementType.c_child_order[:]

def encrypted_attribute_from_string(xml_string):
    return saml2.create_class_from_xml_string(EncryptedAttribute, xml_string)

class BaseID(BaseIDAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:BaseID element """

    c_tag = 'BaseID'
    c_namespace = NAMESPACE
    c_children = BaseIDAbstractType.c_children.copy()
    c_attributes = BaseIDAbstractType.c_attributes.copy()
    c_child_order = BaseIDAbstractType.c_child_order[:]

def base_id_from_string(xml_string):
    return saml2.create_class_from_xml_string(BaseID, xml_string)

class NameID(NameIDType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:NameID element """

    c_tag = 'NameID'
    c_namespace = NAMESPACE
    c_children = NameIDType.c_children.copy()
    c_attributes = NameIDType.c_attributes.copy()
    c_child_order = NameIDType.c_child_order[:]

def name_id_from_string(xml_string):
    return saml2.create_class_from_xml_string(NameID, xml_string)

class SubjectConfirmationData(SubjectConfirmationDataType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:SubjectConfirmationData element """

    c_tag = 'SubjectConfirmationData'
    c_namespace = NAMESPACE
    c_children = SubjectConfirmationDataType.c_children.copy()
    c_attributes = SubjectConfirmationDataType.c_attributes.copy()
    c_child_order = SubjectConfirmationDataType.c_child_order[:]

def subject_confirmation_data_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectConfirmationData, xml_string)

class Condition(ConditionAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Condition element """

    c_tag = 'Condition'
    c_namespace = NAMESPACE
    c_children = ConditionAbstractType.c_children.copy()
    c_attributes = ConditionAbstractType.c_attributes.copy()
    c_child_order = ConditionAbstractType.c_child_order[:]

def condition_from_string(xml_string):
    return saml2.create_class_from_xml_string(Condition, xml_string)

class AudienceRestrictionType(ConditionAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AudienceRestrictionType element """

    c_tag = 'AudienceRestrictionType'
    c_namespace = NAMESPACE
    c_children = ConditionAbstractType.c_children.copy()
    c_attributes = ConditionAbstractType.c_attributes.copy()
    c_child_order = ConditionAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Audience'] = ('audience', [Audience])
    c_child_order.extend(['audience'])

    def __init__(self,
            audience=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        ConditionAbstractType.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.audience=audience or []

def audience_restriction_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AudienceRestrictionType, xml_string)

class OneTimeUse(OneTimeUseType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:OneTimeUse element """

    c_tag = 'OneTimeUse'
    c_namespace = NAMESPACE
    c_children = OneTimeUseType.c_children.copy()
    c_attributes = OneTimeUseType.c_attributes.copy()
    c_child_order = OneTimeUseType.c_child_order[:]

def one_time_use_from_string(xml_string):
    return saml2.create_class_from_xml_string(OneTimeUse, xml_string)

class ProxyRestriction(ProxyRestrictionType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:ProxyRestriction element """

    c_tag = 'ProxyRestriction'
    c_namespace = NAMESPACE
    c_children = ProxyRestrictionType.c_children.copy()
    c_attributes = ProxyRestrictionType.c_attributes.copy()
    c_child_order = ProxyRestrictionType.c_child_order[:]

def proxy_restriction_from_string(xml_string):
    return saml2.create_class_from_xml_string(ProxyRestriction, xml_string)

class Statement(StatementAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Statement element """

    c_tag = 'Statement'
    c_namespace = NAMESPACE
    c_children = StatementAbstractType.c_children.copy()
    c_attributes = StatementAbstractType.c_attributes.copy()
    c_child_order = StatementAbstractType.c_child_order[:]

def statement_from_string(xml_string):
    return saml2.create_class_from_xml_string(Statement, xml_string)

class SubjectLocality(SubjectLocalityType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:SubjectLocality element """

    c_tag = 'SubjectLocality'
    c_namespace = NAMESPACE
    c_children = SubjectLocalityType.c_children.copy()
    c_attributes = SubjectLocalityType.c_attributes.copy()
    c_child_order = SubjectLocalityType.c_child_order[:]

def subject_locality_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectLocality, xml_string)

class AuthnContextType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextType element """

    c_tag = 'AuthnContextType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef'] = ('authn_context_class_ref', AuthnContextClassRef)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDecl'] = ('authn_context_decl', AuthnContextDecl)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDeclRef'] = ('authn_context_decl_ref', AuthnContextDeclRef)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthenticatingAuthority'] = ('authenticating_authority', [AuthenticatingAuthority])
    c_child_order.extend(['authn_context_class_ref', 'authn_context_decl', 'authn_context_decl_ref', 'authenticating_authority'])

    def __init__(self,
            authn_context_class_ref=None,
            authn_context_decl=None,
            authn_context_decl_ref=None,
            authenticating_authority=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.authn_context_class_ref=authn_context_class_ref
        self.authn_context_decl=authn_context_decl
        self.authn_context_decl_ref=authn_context_decl_ref
        self.authenticating_authority=authenticating_authority or []

def authn_context_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnContextType, xml_string)

class Action(ActionType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Action element """

    c_tag = 'Action'
    c_namespace = NAMESPACE
    c_children = ActionType.c_children.copy()
    c_attributes = ActionType.c_attributes.copy()
    c_child_order = ActionType.c_child_order[:]

def action_from_string(xml_string):
    return saml2.create_class_from_xml_string(Action, xml_string)

class AttributeType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AttributeType element """

    c_tag = 'AttributeType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'] = ('attribute_value', [AttributeValue])
    c_attributes['Name'] = ('name', 'string', True)
    c_attributes['NameFormat'] = ('name_format', 'anyURI', False)
    c_attributes['FriendlyName'] = ('friendly_name', 'string', False)
    c_child_order.extend(['attribute_value'])

    def __init__(self,
            attribute_value=None,
            name=None,
            name_format=None,
            friendly_name=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.attribute_value=attribute_value or []
        self.name=name
        self.name_format=name_format
        self.friendly_name=friendly_name

def attribute_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeType, xml_string)

class SubjectConfirmationType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:SubjectConfirmationType element """

    c_tag = 'SubjectConfirmationType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}BaseID'] = ('base_id', BaseID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}NameID'] = ('name_id', NameID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID'] = ('encrypted_id', EncryptedID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData'] = ('subject_confirmation_data', SubjectConfirmationData)
    c_attributes['Method'] = ('method', 'anyURI', True)
    c_child_order.extend(['base_id', 'name_id', 'encrypted_id', 'subject_confirmation_data'])

    def __init__(self,
            base_id=None,
            name_id=None,
            encrypted_id=None,
            subject_confirmation_data=None,
            method=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.base_id=base_id
        self.name_id=name_id
        self.encrypted_id=encrypted_id
        self.subject_confirmation_data=subject_confirmation_data
        self.method=method

def subject_confirmation_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectConfirmationType, xml_string)

class AudienceRestriction(AudienceRestrictionType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AudienceRestriction element """

    c_tag = 'AudienceRestriction'
    c_namespace = NAMESPACE
    c_children = AudienceRestrictionType.c_children.copy()
    c_attributes = AudienceRestrictionType.c_attributes.copy()
    c_child_order = AudienceRestrictionType.c_child_order[:]

def audience_restriction_from_string(xml_string):
    return saml2.create_class_from_xml_string(AudienceRestriction, xml_string)

class AuthnContext(AuthnContextType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthnContext element """

    c_tag = 'AuthnContext'
    c_namespace = NAMESPACE
    c_children = AuthnContextType.c_children.copy()
    c_attributes = AuthnContextType.c_attributes.copy()
    c_child_order = AuthnContextType.c_child_order[:]

def authn_context_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnContext, xml_string)

class Attribute(AttributeType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Attribute element """

    c_tag = 'Attribute'
    c_namespace = NAMESPACE
    c_children = AttributeType.c_children.copy()
    c_attributes = AttributeType.c_attributes.copy()
    c_child_order = AttributeType.c_child_order[:]

def attribute_from_string(xml_string):
    return saml2.create_class_from_xml_string(Attribute, xml_string)

class SubjectConfirmation(SubjectConfirmationType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:SubjectConfirmation element """

    c_tag = 'SubjectConfirmation'
    c_namespace = NAMESPACE
    c_children = SubjectConfirmationType.c_children.copy()
    c_attributes = SubjectConfirmationType.c_attributes.copy()
    c_child_order = SubjectConfirmationType.c_child_order[:]

def subject_confirmation_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectConfirmation, xml_string)

class ConditionsType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:ConditionsType element """

    c_tag = 'ConditionsType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Condition'] = ('condition', [Condition])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction'] = ('audience_restriction', [AudienceRestriction])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}OneTimeUse'] = ('one_time_use', [OneTimeUse])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}ProxyRestriction'] = ('proxy_restriction', [ProxyRestriction])
    c_attributes['NotBefore'] = ('not_before', 'dateTime', False)
    c_attributes['NotOnOrAfter'] = ('not_on_or_after', 'dateTime', False)
    c_child_order.extend(['condition', 'audience_restriction', 'one_time_use', 'proxy_restriction'])

    def __init__(self,
            condition=None,
            audience_restriction=None,
            one_time_use=None,
            proxy_restriction=None,
            not_before=None,
            not_on_or_after=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.condition=condition or []
        self.audience_restriction=audience_restriction or []
        self.one_time_use=one_time_use or []
        self.proxy_restriction=proxy_restriction or []
        self.not_before=not_before
        self.not_on_or_after=not_on_or_after

def conditions_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ConditionsType, xml_string)

class AuthnStatementType(StatementAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthnStatementType element """

    c_tag = 'AuthnStatementType'
    c_namespace = NAMESPACE
    c_children = StatementAbstractType.c_children.copy()
    c_attributes = StatementAbstractType.c_attributes.copy()
    c_child_order = StatementAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}SubjectLocality'] = ('subject_locality', SubjectLocality)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext'] = ('authn_context', AuthnContext)
    c_attributes['AuthnInstant'] = ('authn_instant', 'dateTime', True)
    c_attributes['SessionIndex'] = ('session_index', 'string', False)
    c_attributes['SessionNotOnOrAfter'] = ('session_not_on_or_after', 'dateTime', False)
    c_child_order.extend(['subject_locality', 'authn_context'])

    def __init__(self,
            subject_locality=None,
            authn_context=None,
            authn_instant=None,
            session_index=None,
            session_not_on_or_after=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        StatementAbstractType.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.subject_locality=subject_locality
        self.authn_context=authn_context
        self.authn_instant=authn_instant
        self.session_index=session_index
        self.session_not_on_or_after=session_not_on_or_after

def authn_statement_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnStatementType, xml_string)

class AttributeStatementType(StatementAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AttributeStatementType element """

    c_tag = 'AttributeStatementType'
    c_namespace = NAMESPACE
    c_children = StatementAbstractType.c_children.copy()
    c_attributes = StatementAbstractType.c_attributes.copy()
    c_child_order = StatementAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'] = ('attribute', [Attribute])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAttribute'] = ('encrypted_attribute', [EncryptedAttribute])
    c_child_order.extend(['attribute', 'encrypted_attribute'])

    def __init__(self,
            attribute=None,
            encrypted_attribute=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        StatementAbstractType.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.attribute=attribute or []
        self.encrypted_attribute=encrypted_attribute or []

def attribute_statement_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeStatementType, xml_string)

class SubjectType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:SubjectType element """

    c_tag = 'SubjectType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}BaseID'] = ('base_id', BaseID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}NameID'] = ('name_id', NameID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID'] = ('encrypted_id', EncryptedID)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation'] = ('subject_confirmation', [SubjectConfirmation])
    c_child_order.extend(['base_id', 'name_id', 'encrypted_id', 'subject_confirmation'])

    def __init__(self,
            base_id=None,
            name_id=None,
            encrypted_id=None,
            subject_confirmation=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.base_id=base_id
        self.name_id=name_id
        self.encrypted_id=encrypted_id
        self.subject_confirmation=subject_confirmation or []

def subject_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SubjectType, xml_string)

class Conditions(ConditionsType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Conditions element """

    c_tag = 'Conditions'
    c_namespace = NAMESPACE
    c_children = ConditionsType.c_children.copy()
    c_attributes = ConditionsType.c_attributes.copy()
    c_child_order = ConditionsType.c_child_order[:]

def conditions_from_string(xml_string):
    return saml2.create_class_from_xml_string(Conditions, xml_string)

class AuthnStatement(AuthnStatementType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthnStatement element """

    c_tag = 'AuthnStatement'
    c_namespace = NAMESPACE
    c_children = AuthnStatementType.c_children.copy()
    c_attributes = AuthnStatementType.c_attributes.copy()
    c_child_order = AuthnStatementType.c_child_order[:]

def authn_statement_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthnStatement, xml_string)

class AttributeStatement(AttributeStatementType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AttributeStatement element """

    c_tag = 'AttributeStatement'
    c_namespace = NAMESPACE
    c_children = AttributeStatementType.c_children.copy()
    c_attributes = AttributeStatementType.c_attributes.copy()
    c_child_order = AttributeStatementType.c_child_order[:]

def attribute_statement_from_string(xml_string):
    return saml2.create_class_from_xml_string(AttributeStatement, xml_string)

class Subject(SubjectType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Subject element """

    c_tag = 'Subject'
    c_namespace = NAMESPACE
    c_children = SubjectType.c_children.copy()
    c_attributes = SubjectType.c_attributes.copy()
    c_child_order = SubjectType.c_child_order[:]

def subject_from_string(xml_string):
    return saml2.create_class_from_xml_string(Subject, xml_string)

#..................
# ['AssertionType', 'Advice', 'Assertion', 'AuthzDecisionStatementType', 'AuthzDecisionStatement', 'EvidenceType', 'Evidence', 'AdviceType']
class AuthzDecisionStatementType(StatementAbstractType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthzDecisionStatementType element """

    c_tag = 'AuthzDecisionStatementType'
    c_namespace = NAMESPACE
    c_children = StatementAbstractType.c_children.copy()
    c_attributes = StatementAbstractType.c_attributes.copy()
    c_child_order = StatementAbstractType.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Action'] = ('action', [Action])
    c_attributes['Resource'] = ('resource', 'anyURI', True)
    c_attributes['Decision'] = ('decision', 'DecisionType', True)
    c_child_order.extend(['action', 'evidence'])

    def __init__(self,
            action=None,
            evidence=None,
            resource=None,
            decision=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        StatementAbstractType.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.action=action or []
        self.evidence=evidence
        self.resource=resource
        self.decision=decision

def authz_decision_statement_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthzDecisionStatementType, xml_string)

class AuthzDecisionStatement(AuthzDecisionStatementType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AuthzDecisionStatement element """

    c_tag = 'AuthzDecisionStatement'
    c_namespace = NAMESPACE
    c_children = AuthzDecisionStatementType.c_children.copy()
    c_attributes = AuthzDecisionStatementType.c_attributes.copy()
    c_child_order = AuthzDecisionStatementType.c_child_order[:]

def authz_decision_statement_from_string(xml_string):
    return saml2.create_class_from_xml_string(AuthzDecisionStatement, xml_string)

#..................
# ['AssertionType', 'Advice', 'Assertion', 'EvidenceType', 'AdviceType', 'Evidence']
class AssertionType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AssertionType element """

    c_tag = 'AssertionType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'] = ('issuer', Issuer)
    c_children['{http://www.w3.org/2000/09/xmldsig#}Signature'] = ('signature', ds.Signature)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Subject'] = ('subject', Subject)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'] = ('conditions', Conditions)
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Statement'] = ('statement', [Statement])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement'] = ('authn_statement', [AuthnStatement])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AuthzDecisionStatement'] = ('authz_decision_statement', [AuthzDecisionStatement])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement'] = ('attribute_statement', [AttributeStatement])
    c_attributes['Version'] = ('version', 'string', True)
    c_attributes['ID'] = ('id', 'ID', True)
    c_attributes['IssueInstant'] = ('issue_instant', 'dateTime', True)
    c_child_order.extend(['issuer', 'signature', 'subject', 'conditions', 'advice', 'statement', 'authn_statement', 'authz_decision_statement', 'attribute_statement'])

    def __init__(self,
            issuer=None,
            signature=None,
            subject=None,
            conditions=None,
            advice=None,
            statement=None,
            authn_statement=None,
            authz_decision_statement=None,
            attribute_statement=None,
            version=None,
            id=None,
            issue_instant=None,
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
        self.subject=subject
        self.conditions=conditions
        self.advice=advice
        self.statement=statement or []
        self.authn_statement=authn_statement or []
        self.authz_decision_statement=authz_decision_statement or []
        self.attribute_statement=attribute_statement or []
        self.version=version
        self.id=id
        self.issue_instant=issue_instant

def assertion_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AssertionType, xml_string)

class Assertion(AssertionType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Assertion element """

    c_tag = 'Assertion'
    c_namespace = NAMESPACE
    c_children = AssertionType.c_children.copy()
    c_attributes = AssertionType.c_attributes.copy()
    c_child_order = AssertionType.c_child_order[:]

def assertion_from_string(xml_string):
    return saml2.create_class_from_xml_string(Assertion, xml_string)

class AdviceType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:AdviceType element """

    c_tag = 'AdviceType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AssertionIDRef'] = ('assertion_id_ref', [AssertionIDRef])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AssertionURIRef'] = ('assertion_uri_ref', [AssertionURIRef])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Assertion'] = ('assertion', [Assertion])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion'] = ('encrypted_assertion', [EncryptedAssertion])
    c_child_order.extend(['assertion_id_ref', 'assertion_uri_ref', 'assertion', 'encrypted_assertion'])

    def __init__(self,
            assertion_id_ref=None,
            assertion_uri_ref=None,
            assertion=None,
            encrypted_assertion=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.assertion_id_ref=assertion_id_ref or []
        self.assertion_uri_ref=assertion_uri_ref or []
        self.assertion=assertion or []
        self.encrypted_assertion=encrypted_assertion or []

def advice_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(AdviceType, xml_string)

class EvidenceType(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:assertion:EvidenceType element """

    c_tag = 'EvidenceType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AssertionIDRef'] = ('assertion_id_ref', [AssertionIDRef])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}AssertionURIRef'] = ('assertion_uri_ref', [AssertionURIRef])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Assertion'] = ('assertion', [Assertion])
    c_children['{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion'] = ('encrypted_assertion', [EncryptedAssertion])
    c_child_order.extend(['assertion_id_ref', 'assertion_uri_ref', 'assertion', 'encrypted_assertion'])

    def __init__(self,
            assertion_id_ref=None,
            assertion_uri_ref=None,
            assertion=None,
            encrypted_assertion=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.assertion_id_ref=assertion_id_ref or []
        self.assertion_uri_ref=assertion_uri_ref or []
        self.assertion=assertion or []
        self.encrypted_assertion=encrypted_assertion or []

def evidence_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(EvidenceType, xml_string)

class Advice(AdviceType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Advice element """

    c_tag = 'Advice'
    c_namespace = NAMESPACE
    c_children = AdviceType.c_children.copy()
    c_attributes = AdviceType.c_attributes.copy()
    c_child_order = AdviceType.c_child_order[:]

def advice_from_string(xml_string):
    return saml2.create_class_from_xml_string(Advice, xml_string)

class Evidence(EvidenceType):
    """The urn:oasis:names:tc:SAML:2.0:assertion:Evidence element """

    c_tag = 'Evidence'
    c_namespace = NAMESPACE
    c_children = EvidenceType.c_children.copy()
    c_attributes = EvidenceType.c_attributes.copy()
    c_child_order = EvidenceType.c_child_order[:]

def evidence_from_string(xml_string):
    return saml2.create_class_from_xml_string(Evidence, xml_string)

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
AuthzDecisionStatementType.c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Evidence'] = ('evidence', Evidence)
AuthzDecisionStatement.c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Evidence'] = ('evidence', Evidence)
AssertionType.c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Advice'] = ('advice', Advice)
Assertion.c_children['{urn:oasis:names:tc:SAML:2.0:assertion}Advice'] = ('advice', Advice)
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

ELEMENT_FROM_STRING = {
    BaseID.c_tag: base_id_from_string,
    BaseIDAbstractType.c_tag: base_id_abstract_type_from_string,
    NameID.c_tag: name_id_from_string,
    NameIDType.c_tag: name_id_type_from_string,
    EncryptedElementType.c_tag: encrypted_element_type_from_string,
    EncryptedID.c_tag: encrypted_id_from_string,
    Issuer.c_tag: issuer_from_string,
    AssertionIDRef.c_tag: assertion_id_ref_from_string,
    AssertionURIRef.c_tag: assertion_uri_ref_from_string,
    Assertion.c_tag: assertion_from_string,
    AssertionType.c_tag: assertion_type_from_string,
    Subject.c_tag: subject_from_string,
    SubjectType.c_tag: subject_type_from_string,
    SubjectConfirmation.c_tag: subject_confirmation_from_string,
    SubjectConfirmationType.c_tag: subject_confirmation_type_from_string,
    SubjectConfirmationData.c_tag: subject_confirmation_data_from_string,
    SubjectConfirmationDataType.c_tag: subject_confirmation_data_type_from_string,
    KeyInfoConfirmationDataType.c_tag: key_info_confirmation_data_type_from_string,
    Conditions.c_tag: conditions_from_string,
    ConditionsType.c_tag: conditions_type_from_string,
    Condition.c_tag: condition_from_string,
    ConditionAbstractType.c_tag: condition_abstract_type_from_string,
    AudienceRestriction.c_tag: audience_restriction_from_string,
    AudienceRestrictionType.c_tag: audience_restriction_type_from_string,
    Audience.c_tag: audience_from_string,
    OneTimeUse.c_tag: one_time_use_from_string,
    OneTimeUseType.c_tag: one_time_use_type_from_string,
    ProxyRestriction.c_tag: proxy_restriction_from_string,
    ProxyRestrictionType.c_tag: proxy_restriction_type_from_string,
    Advice.c_tag: advice_from_string,
    AdviceType.c_tag: advice_type_from_string,
    EncryptedAssertion.c_tag: encrypted_assertion_from_string,
    Statement.c_tag: statement_from_string,
    StatementAbstractType.c_tag: statement_abstract_type_from_string,
    AuthnStatement.c_tag: authn_statement_from_string,
    AuthnStatementType.c_tag: authn_statement_type_from_string,
    SubjectLocality.c_tag: subject_locality_from_string,
    SubjectLocalityType.c_tag: subject_locality_type_from_string,
    AuthnContext.c_tag: authn_context_from_string,
    AuthnContextType.c_tag: authn_context_type_from_string,
    AuthnContextClassRef.c_tag: authn_context_class_ref_from_string,
    AuthnContextDeclRef.c_tag: authn_context_decl_ref_from_string,
    AuthnContextDecl.c_tag: authn_context_decl_from_string,
    AuthenticatingAuthority.c_tag: authenticating_authority_from_string,
    AuthzDecisionStatement.c_tag: authz_decision_statement_from_string,
    AuthzDecisionStatementType.c_tag: authz_decision_statement_type_from_string,
    DecisionType.c_tag: decision_type_from_string,
    Action.c_tag: action_from_string,
    ActionType.c_tag: action_type_from_string,
    Evidence.c_tag: evidence_from_string,
    EvidenceType.c_tag: evidence_type_from_string,
    AttributeStatement.c_tag: attribute_statement_from_string,
    AttributeStatementType.c_tag: attribute_statement_type_from_string,
    Attribute.c_tag: attribute_from_string,
    AttributeType.c_tag: attribute_type_from_string,
    AttributeValue.c_tag: attribute_value_from_string,
    EncryptedAttribute.c_tag: encrypted_attribute_from_string,
}

ELEMENT_BY_TAG = {
    'BaseID': BaseID,
    'BaseIDAbstractType': BaseIDAbstractType,
    'NameID': NameID,
    'NameIDType': NameIDType,
    'EncryptedElementType': EncryptedElementType,
    'EncryptedID': EncryptedID,
    'Issuer': Issuer,
    'AssertionIDRef': AssertionIDRef,
    'AssertionURIRef': AssertionURIRef,
    'Assertion': Assertion,
    'AssertionType': AssertionType,
    'Subject': Subject,
    'SubjectType': SubjectType,
    'SubjectConfirmation': SubjectConfirmation,
    'SubjectConfirmationType': SubjectConfirmationType,
    'SubjectConfirmationData': SubjectConfirmationData,
    'SubjectConfirmationDataType': SubjectConfirmationDataType,
    'KeyInfoConfirmationDataType': KeyInfoConfirmationDataType,
    'Conditions': Conditions,
    'ConditionsType': ConditionsType,
    'Condition': Condition,
    'ConditionAbstractType': ConditionAbstractType,
    'AudienceRestriction': AudienceRestriction,
    'AudienceRestrictionType': AudienceRestrictionType,
    'Audience': Audience,
    'OneTimeUse': OneTimeUse,
    'OneTimeUseType': OneTimeUseType,
    'ProxyRestriction': ProxyRestriction,
    'ProxyRestrictionType': ProxyRestrictionType,
    'Advice': Advice,
    'AdviceType': AdviceType,
    'EncryptedAssertion': EncryptedAssertion,
    'Statement': Statement,
    'StatementAbstractType': StatementAbstractType,
    'AuthnStatement': AuthnStatement,
    'AuthnStatementType': AuthnStatementType,
    'SubjectLocality': SubjectLocality,
    'SubjectLocalityType': SubjectLocalityType,
    'AuthnContext': AuthnContext,
    'AuthnContextType': AuthnContextType,
    'AuthnContextClassRef': AuthnContextClassRef,
    'AuthnContextDeclRef': AuthnContextDeclRef,
    'AuthnContextDecl': AuthnContextDecl,
    'AuthenticatingAuthority': AuthenticatingAuthority,
    'AuthzDecisionStatement': AuthzDecisionStatement,
    'AuthzDecisionStatementType': AuthzDecisionStatementType,
    'DecisionType': DecisionType,
    'Action': Action,
    'ActionType': ActionType,
    'Evidence': Evidence,
    'EvidenceType': EvidenceType,
    'AttributeStatement': AttributeStatement,
    'AttributeStatementType': AttributeStatementType,
    'Attribute': Attribute,
    'AttributeType': AttributeType,
    'AttributeValue': AttributeValue,
    'EncryptedAttribute': EncryptedAttribute,
}

def factory(tag, **kwargs):
    return ELEMENT_BY_TAG[tag](**kwargs)

