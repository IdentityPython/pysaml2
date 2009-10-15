#!/usr/bin/python
#
# Copyright (C) 2009 Umea Universitet.
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

"""Contains classes representing xmlenc elements.

    Module objective: provide data classes for xmlenc constructs. These
    classes hide the XML-ness of Saml and provide a set of native Python
    classes to interact with.

    Classes in this module inherits saml.SamlBase now.

"""

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        from elementtree import ElementTree
        
import saml2
from saml2 import create_class_from_xml_string

import xmldsig as ds

NAMESPACE = 'http://www.w3.org/2001/04/xmlenc#'
#TEMPLATE = '{http://www.w3.org/2001/04/xmlenc#}%s'

class EncBase(saml2.SamlBase):
    """The enc:EncBase element"""

    c_children = {}
    c_attributes = {}

# ---------------------------------------------------------------------------
# KeySize
# ---------------------------------------------------------------------------

class KeySize(EncBase):

    c_tag = 'KeySize'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()

def key_size_from_string(xml_string):
    """ Create KeySize instance from an XML string """
    return create_class_from_xml_string(KeySize, xml_string)

# ---------------------------------------------------------------------------
# OAEPparams
# ---------------------------------------------------------------------------

class OAEPparams(EncBase):

    c_tag = 'OAEPparams'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()

def oaep_params_from_string(xml_string):
    """ Create OAEPparams instance from an XML string """
    return create_class_from_xml_string(OAEPparams, xml_string)

# ---------------------------------------------------------------------------
# EncryptionMethod
# ---------------------------------------------------------------------------

class EncryptionMethod(EncBase):
    """The enc:EncryptionMethod element"""

    c_tag = 'EncryptionMethod'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_attributes['Algorithm'] = 'algorithm'
    c_children['{%s}KeySize' % NAMESPACE] = (
        'key_size', [KeySize])
    c_children['{%s}OAEPparams' % NAMESPACE] = (
        'oaep_params', [OAEPparams])

    def __init__(self, algorithm=None, key_size=None, oaep_params=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for EncryptedType

        :param algorithm: Algorithm attribute
        :param key_size: KeySize attribute
        :param oaep_params: OAEPparams attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.algorithm = algorithm
        self.key_size = key_size
        self.oaep_params = oaep_params

def encryption_method_from_string(xml_string):
    """ Create EncryptionMethod instance from an XML string """
    return create_class_from_xml_string(EncryptionMethod, xml_string)

# ---------------------------------------------------------------------------
# CipherValue
# ---------------------------------------------------------------------------

class CipherValue(EncBase):

    c_tag = 'CipherValue'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()

def cipher_value_from_string(xml_string):
    """ Create CipherValue instance from an XML string """
    return create_class_from_xml_string(CipherValue, xml_string)

# ---------------------------------------------------------------------------
# Transforms
# NOTICE: There is an element in ds that is also named Transforms, with a very
# similar definition. Confusing!!!
# ---------------------------------------------------------------------------

class Transforms(EncBase):

    c_tag = 'Transforms'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_children['{%s}Transform' % ds.NAMESPACE] = (
        'transform', [ds.Transform])

    def __init__(self, transform=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for Transforms

        :param transform: Transform element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.transform = transform or []

def transforms_from_string(xml_string):
    """ Create Transforms instance from an XML string """
    return create_class_from_xml_string(Transforms, xml_string)

# ---------------------------------------------------------------------------
# CipherReference
# ---------------------------------------------------------------------------

class CipherReference(EncBase):

    c_tag = 'CipherReference'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_attributes['URI'] = 'uri'    
    c_children['{%s}Transforms' % NAMESPACE] = (
        'transforms', [Transforms])
    
    def __init__(self, uri=None, transforms=None, 
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for CipherReference

        :param uri: URI attribute
        :param transforms: Transforms attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.uri = uri
        self.transforms = transforms or []

def cipher_reference_from_string(xml_string):
    """ Create CipherReference instance from an XML string """
    return create_class_from_xml_string(CipherReference, xml_string)

# ---------------------------------------------------------------------------
# CipherData
# ---------------------------------------------------------------------------

class CipherData(EncBase):
    """The enc:CipherData element"""

    c_tag = 'CipherData'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_children['{%s}CipherValue' % NAMESPACE] = (
        'cipher_value', [CipherValue])
    c_children['{%s}CipherReference' % NAMESPACE] = (
        'cipher_reference', [CipherReference])
    c_child_order = ['cipher_value', 'cipher_reference']

    def __init__(self, algorithm=None, cipher_value=None, 
                cipher_reference=None, 
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for CipherData

        :param cipher_value: CipherValue attribute
        :param cipher_reference: CipherReference attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.cipher_value = cipher_value
        self.cipher_reference = cipher_reference

def cipher_data_from_string(xml_string):
    """ Create CipherData instance from an XML string """
    return create_class_from_xml_string(CipherData, xml_string)

# ---------------------------------------------------------------------------
# EncryptionProperty
# ---------------------------------------------------------------------------

class EncryptionProperty(EncBase):

    c_tag = 'EncryptionProperty'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_attributes['Target'] = 'target'
    c_attributes['Id'] = 'identifier'

    def __init__(self, target=None, identifier=None, 
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for EncryptedKey

        :param target: Target attribute
        :param identifier: Id attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.target = target
        self.identifier = identifier or []

def encryption_property_from_string(xml_string):
    """ Create EncryptionProperty instance from an XML string """
    return create_class_from_xml_string(EncryptionProperty, xml_string)

# ---------------------------------------------------------------------------
# EncryptionProperties
# ---------------------------------------------------------------------------

class EncryptionProperties(EncBase):

    c_tag = 'EncryptionProperties'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_attributes['Id'] = 'identifier'
    c_children['{%s}EncryptionProperty' % NAMESPACE] = (
        'encryption_property', [EncryptionProperty])

    def __init__(self, identifier=None, encryption_property=None, 
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for EncryptedKey

        :param identifier: Id attribute
        :param encryption_property: EncryptionProperty attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier
        self.encryption_property = encryption_property or []

def encryption_properties_from_string(xml_string):
    """ Create EncryptionProperties instance from an XML string """
    return create_class_from_xml_string(EncryptionProperties, xml_string)

# ---------------------------------------------------------------------------
# EncryptedType
# ---------------------------------------------------------------------------

class EncryptedType(EncBase):
    """The enc:EncryptedType element"""

    c_tag = 'EncryptedType'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_attributes['Id'] = 'identifier'
    c_attributes['Type'] = 'typ'
    c_attributes['MimeType'] = 'mime_type'
    c_attributes['Encoding'] = 'encoding'
    c_children['{%s}EncryptionMethod' % NAMESPACE] = (
        'encryption_method', [EncryptionMethod])
    c_children['{%s}KeyInfo' % ds.NAMESPACE] = (
        'key_info', [ds.KeyInfo])
    c_children['{%s}CipherData' % NAMESPACE] = (
        'cipher_data', [CipherData])
    c_children['{%s}EncryptionProperties' % NAMESPACE] = (
        'encryption_properties', [EncryptionProperties])
    c_child_order = ['encryption_method', 'key_info',
                    'cipher_data','encryption_properties']

    def __init__(self, identifier=None, typ=None, mime_type=None, 
                encoding=None, encryption_method=None, key_info=None,
                cipher_data=None, encryption_properties=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for EncryptedType

        :param identifier: Id attribute
        :param typ: Type attribute
        :param mime_type: MimeType attribute
        :param encoding: Encoding attribute
        :param encryption_method: EncryptionMethod attribute
        :param key_info: KeyInfo attribute
        :param cipher_data: CipherData attribute
        :param encryption_properties: EncryptionProperties attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier
        self.typ = typ
        self.mime_type = mime_type
        self.encoding = encoding
        self.encryption_method = encryption_method
        self.key_info = key_info
        self.cipher_data = cipher_data
        self.encryption_properties = encryption_properties

def encrypted_type_from_string(xml_string):
    """ Create EncryptedType instance from an XML string """
    return create_class_from_xml_string(EncryptedType, xml_string)

# ---------------------------------------------------------------------------
# EncryptedData
# ---------------------------------------------------------------------------

class EncryptedData(EncryptedType):
    """The enc:EncryptedData element"""

    c_tag = 'EncryptedData'
    c_namespace = NAMESPACE
    c_children = EncryptedType.c_children.copy()
    c_attributes = EncryptedType.c_attributes.copy()

def encrypted_data_from_string(xml_string):
    """ Create EncryptedData instance from an XML string """
    return create_class_from_xml_string(EncryptedData, xml_string)

# ---------------------------------------------------------------------------
# ReferenceType
# ---------------------------------------------------------------------------

class ReferenceType(EncBase):

    c_tag = 'ReferenceType'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_attributes['URI'] = 'uri'

    def __init__(self, uri=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for ReferenceType

        :param uri: URI attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.uri = uri
        
def reference_type_from_string(xml_string):
    """ Create ReferenceType instance from an XML string """
    return create_class_from_xml_string(ReferenceType, xml_string)

# ---------------------------------------------------------------------------
# DataReference
# ---------------------------------------------------------------------------

class DataReference(ReferenceType):

    c_tag = 'DataReference'
    c_namespace = NAMESPACE
    c_children = ReferenceType.c_children.copy()
    c_attributes = ReferenceType.c_attributes.copy()

def data_reference_from_string(xml_string):
    """ Create DataReference instance from an XML string """
    return create_class_from_xml_string(DataReference, xml_string)

# ---------------------------------------------------------------------------
# KeyReference
# ---------------------------------------------------------------------------

class KeyReference(ReferenceType):

    c_tag = 'KeyReference'
    c_namespace = NAMESPACE
    c_children = ReferenceType.c_children.copy()
    c_attributes = ReferenceType.c_attributes.copy()

def key_reference_from_string(xml_string):
    """ Create KeyReference instance from an XML string """
    return create_class_from_xml_string(KeyReference, xml_string)

# ---------------------------------------------------------------------------
# ReferenceList
# ---------------------------------------------------------------------------

class ReferenceList(EncBase):

    c_tag = 'ReferenceList'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()
    c_children['{%s}DataReference' % NAMESPACE] = (
        'data_reference', [DataReference])
    c_children['{%s}KeyReference' % NAMESPACE] = (
        'key_reference', [KeyReference])

    def __init__(self, data_reference=None, key_reference=None, 
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for EncryptedKey

        :param data_reference: DataReference attribute
        :param key_reference: KeyReference attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncBase.__init__(self, text, extension_elements, extension_attributes)
        self.data_reference = data_reference or []
        self.key_reference = key_reference or []
            
def reference_list_from_string(xml_string):
    """ Create ReferenceList instance from an XML string """
    return create_class_from_xml_string(ReferenceList, xml_string)

# ---------------------------------------------------------------------------
# CarriedKeyName
# ---------------------------------------------------------------------------

class CarriedKeyName(EncBase):

    c_tag = 'CarriedKeyName'
    c_namespace = NAMESPACE
    c_children = EncBase.c_children.copy()
    c_attributes = EncBase.c_attributes.copy()

def carried_key_name_from_string(xml_string):
    """ Create CarriedKeyName instance from an XML string """
    return create_class_from_xml_string(CarriedKeyName, xml_string)

# ---------------------------------------------------------------------------
# EncryptedKey
# ---------------------------------------------------------------------------

class EncryptedKey(EncryptedType):
    """The enc:EncryptedKey element"""

    c_tag = 'EncryptedKey'
    c_namespace = NAMESPACE
    c_children = EncryptedType.c_children.copy()
    c_attributes = EncryptedType.c_attributes.copy()
    c_attributes['Recipient'] = 'recipient'
    c_children['{%s}ReferenceList' % NAMESPACE] = (
        'reference_list', [ReferenceList])
    c_children['{%s}CarriedKeyName' % NAMESPACE] = (
        'carried_key_name', [CarriedKeyName])

    def __init__(self, recipient=None, reference_list=None, 
                carried_key_name=None,identifier=None, typ=None, 
                mime_type=None, encoding=None, encryption_method=None, 
                key_info=None, cipher_data=None, encryption_properties=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for EncryptedType

        :param recipient: Id attribute
        :param reference_list: Type attribute
        :param carried_key_name: MimeType attribute
        :param identifier: Id attribute
        :param typ: Type attribute
        :param mime_type: MimeType attribute
        :param encoding: Encoding attribute
        :param encryption_method: EncryptionMethod attribute
        :param key_info: KeyInfo attribute
        :param cipher_data: CipherData attribute
        :param encryption_properties: EncryptionProperties attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        EncryptedType.__init__(self, identifier, typ, mime_type, 
                    encoding, encryption_method, key_info,
                    cipher_data, encryption_properties,
                    text, extension_elements, extension_attributes)
        self.recipient = recipient
        self.reference_list = reference_list or []
        self.carried_key_name = carried_key_name or []

def encrypted_key_from_string(xml_string):
    """ Create EncryptedKey instance from an XML string """
    return create_class_from_xml_string(EncryptedKey, xml_string)

ELEMENT_TO_STRING = {
    KeySize: key_size_from_string,
    OAEPparams: oaep_params_from_string,
    EncryptionMethod: encryption_method_from_string,
    CipherValue: cipher_value_from_string,
    Transforms: transforms_from_string,
    CipherReference: cipher_reference_from_string,
    CipherData: cipher_data_from_string,
    EncryptionProperty: encryption_property_from_string,
    EncryptionProperties: encryption_properties_from_string,
    EncryptedType: encrypted_type_from_string,
    EncryptedData: encrypted_data_from_string,
    ReferenceType: reference_type_from_string,
    DataReference: data_reference_from_string,
    KeyReference: key_reference_from_string,
    ReferenceList: reference_list_from_string,
    CarriedKeyName: carried_key_name_from_string,
    EncryptedKey: encrypted_key_from_string,
}