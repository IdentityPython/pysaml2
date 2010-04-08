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
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains classes representing xmldsig elements.

    Module objective: provide data classes for xmldsig constructs. These
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
#import xmlenc
from saml2 import create_class_from_xml_string

NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'
TEMPLATE = '{http://www.w3.org/2000/09/xmldsig#}%s'

ENCODING_BASE64 = 'http://www.w3.org/2000/09/xmldsig#base64'
DIGEST_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
ALG_EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
SIG_DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
SIG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
MAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'

C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
C14N_WITH_C = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments'

TRANSFORM_XSLT = 'http://www.w3.org/TR/1999/REC-xslt-19991116'
TRANSFORM_XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116'
TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'


class DsBase(saml2.SamlBase):
    """The ds:DsBase element"""

    c_children = {}
    c_attributes = {}

class Object(DsBase):
    """The ds:Object element"""

    c_tag = 'Object'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Id'] = 'identifier'
    c_attributes['MimeType'] = 'mime_type'
    c_attributes['Encoding'] = 'encoding'

    def __init__(self, identifier=None, mime_type=None, encoding=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for Object

        :param identifier: Id attribute
        :param mime_type: MimeType attribute
        :param encoding: Encoding attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier
        self.mime_type = mime_type
        self.encoding = encoding

def object_from_string(xml_string):
    """ Create Object instance from an XML string """
    return create_class_from_xml_string(Object, xml_string)

class MgmtData(DsBase):
    """The ds:MgmtData element"""

    c_tag = 'MgmtData'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def mgmt_data_from_string(xml_string):
    """ Create MgmtData instance from an XML string """
    return create_class_from_xml_string(MgmtData, xml_string)


class SPKISexp(DsBase):
    """The ds:SPKISexp element"""

    c_tag = 'SPKISexp'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def spki_sexp_from_string(xml_string):
    """ Create SPKISexp instance from an XML string """
    return create_class_from_xml_string(SPKISexp, xml_string)


class SPKIData(DsBase):
    """The ds:SPKIData element"""

    c_tag = 'SPKIData'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}SPKISexp' % NAMESPACE] = ('spki_sexp', [SPKISexp])

    def __init__(self, spki_sexp=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for SPKIData

        :param spki_sexp: SPKISexp elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.spki_sexp = spki_sexp or []

def spki_data_from_string(xml_string):
    """ Create SPKIData instance from an XML string """
    return create_class_from_xml_string(SPKIData, xml_string)


class PGPKeyID(DsBase):
    """The ds:PGPKeyID element"""

    c_tag = 'PGPKeyID'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def pgp_key_id_from_string(xml_string):
    """ Create PGPKeyID instance from an XML string """
    return create_class_from_xml_string(PGPKeyID, xml_string)


class PGPKeyPacket(DsBase):
    """The ds:PGPKeyPacket element"""

    c_tag = 'PGPKeyPacket'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def pgp_key_packet_from_string(xml_string):
    """ Create PGPKeyPacket instance from an XML string """
    return create_class_from_xml_string(PGPKeyPacket, xml_string)


class PGPData(DsBase):
    """The ds:PGPData element"""

    c_tag = 'PGPData'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}PGPKeyID' % NAMESPACE] = ('pgp_key_id', PGPKeyID)
    c_children['{%s}PGPKeyPacket' % NAMESPACE] = (
        'pgp_key_packet', PGPKeyPacket)
    c_child_order = ['pgp_key_id', 'pgp_key_packet']

    def __init__(self, pgp_key_id=None, pgp_key_packet=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for PGPKeyINfo

        :param pgp_key_id: PGPKeyID element
        :param pgp_key_packet: PGPKeyPacket element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.pgp_key_id = pgp_key_id
        self.pgp_key_packet = pgp_key_packet

def pgp_data_from_string(xml_string):
    """ Create PGPData instance from an XML string """
    return create_class_from_xml_string(PGPData, xml_string)


class X509IssuerName(DsBase):
    """The ds:X509IssuerName element"""

    c_tag = 'X509IssuerName'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def x509_issuer_name_from_string(xml_string):
    """ Create X509IssuerName instance from an XML string """
    return create_class_from_xml_string(X509IssuerName, xml_string)


class X509IssuerNumber(DsBase):
    """The ds:X509IssuerNumber element"""

    c_tag = 'X509IssuerNumber'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def x509_issuer_number_from_string(xml_string):
    """ Create X509IssuerNumber instance from an XML string """
    return create_class_from_xml_string(X509IssuerNumber, xml_string)


class X509IssuerSerial(DsBase):
    """The ds:X509IssuerSerial element"""

    c_tag = 'X509IssuerSerial'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}X509IssuerName' % NAMESPACE] = (
        'x509_issuer_name', X509IssuerName)
    c_children['{%s}X509IssuerNumber' % NAMESPACE] = (
        'x509_issuer_number', X509IssuerNumber)
    c_child_order = ['x509_issuer_name', 'x509_issuer_number']

    def __init__(self, x509_issuer_name=None, x509_issuer_number=None, 
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for X509IssuerSerial

        :param x509_issuer_name: X509IssuerName
        :param x509_issuer_number: X509IssuerNumber
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.x509_issuer_name = x509_issuer_name
        self.x509_issuer_number = x509_issuer_number


def x509_issuer_serial_from_string(xml_string):
    """ Create X509IssuerSerial instance from an XML string """
    return create_class_from_xml_string(X509IssuerSerial, xml_string)


class X509SKI(DsBase):
    """The ds:X509SKI element"""

    c_tag = 'X509SKI'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def x509_ski_from_string(xml_string):
    """ Create X509SKI instance from an XML string """
    return create_class_from_xml_string(X509SKI, xml_string)


class X509SubjectName(DsBase):
    """The ds:X509SubjectName element"""

    c_tag = 'X509SubjectName'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def x509_subject_name_from_string(xml_string):
    """ Create X509SubjectName instance from an XML string """
    return create_class_from_xml_string(X509SubjectName, xml_string)


class X509Certificate(DsBase):
    """The ds:X509Certificate element"""

    c_tag = 'X509Certificate'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def x509_certificate_from_string(xml_string):
    """ Create X509Certificate instance from an XML string """
    return create_class_from_xml_string(X509Certificate, xml_string)


class X509CRL(DsBase):
    """The ds:X509CRL element"""

    c_tag = 'X509CRL'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def x509_crl_from_string(xml_string):
    """ Create X509CRL instance from an XML string """
    return create_class_from_xml_string(X509CRL, xml_string)


class X509Data(DsBase):
    """The ds:X509Data element"""

    c_tag = 'X509Data'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}X509IssuerSerial' % NAMESPACE] = (
        'x509_issuer_serial', [X509IssuerSerial])
    c_children['{%s}X509SKI' % NAMESPACE] = ('x509_ski', [X509SKI])
    c_children['{%s}X509SubjectName' % NAMESPACE] = (
        'x509_subject_name', [X509SubjectName])
    c_children['{%s}X509Certificate' % NAMESPACE] = (
        'x509_certificate', [X509Certificate])
    c_children['{%s}X509CRL' % NAMESPACE] = ('x509_crl', [X509CRL])
    c_child_order = ['x509_issuer_serial', 'x509_ski', 'x509_subject_name',
                                    'x509_certificate', 'x509_crl']

    def __init__(self, x509_issuer_serial=None, x509_ski=None,
                x509_subject_name=None, x509_certificate=None, x509_crl=None,
                text=None, extension_elements=None, extension_attributes=None):
        """Constructor for X509Data

        :param x509_issuer_serial: X509IssuerSerial element
        :param x509_ski: X509SKI element
        :param x509_subject_name: X509SubjectName element
        :param x509_certificate: X509Certificate element
        :param x509_crl: X509CRL element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
                pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.x509_issuer_serial = x509_issuer_serial or []
        self.x509_ski = x509_ski or []
        self.x509_subject_name = x509_subject_name or []
        self.x509_certificate = x509_certificate or []
        self.x509_crl = x509_crl or []


def x509_data_from_string(xml_string):
    """ Create X509Data instance from an XML string """
    return create_class_from_xml_string(X509Data, xml_string)


class XPath(DsBase):
    """The ds:XPath element"""

    c_tag = 'XPath'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def xpath_from_string(xml_string):
    """ Create XPath instance from an XML string """
    return create_class_from_xml_string(XPath, xml_string)


class Transform(DsBase):
    """The ds:Transform element"""

    c_tag = 'Transform'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Algorithm'] = 'algorithm'
    c_children['{%s}XPath' % NAMESPACE] = ('xpath', [XPath])

    def __init__(self, xpath=None, algorithm=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for Transform

        :param xpath: XPath elements
        :param algorithm: Algorithm attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.xpath = xpath or []
        self.algorithm = algorithm

def transform_from_string(xml_string):
    """ Create Transform instance from an XML string """
    return create_class_from_xml_string(Transform, xml_string)


class Transforms(DsBase):
    """The ds:Transforms element"""

    c_tag = 'Transforms'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}Transform' % NAMESPACE] = ('transform', [Transform])

    def __init__(self, transform=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for Transforms

        :param transform: Transform elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.transform = transform or []

def transforms_from_string(xml_string):
    """ Create Transforms instance from an XML string """
    return create_class_from_xml_string(Transforms, xml_string)


class RetrievalMethod(DsBase):
    """The ds:RetrievalMethod element"""

    c_tag = 'RetrievalMethod'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['URI'] = 'uri'
    c_attributes['Type'] = 'type'
    c_children['{%s}Transforms' % NAMESPACE] = ('transforms', [Transforms])

    def __init__(self, transforms=None, uri=None, type=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for RetrievalMethod

        :param transforms: Transforms elements
        :param uri: URI attribute
        :param typ: Type attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string 
            pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.uri = uri
        self.type = type
        self.transforms = transforms or []

def retrieval_method_from_string(xml_string):
    """ Create RetrievalMethod instance from an XML string """
    return create_class_from_xml_string(RetrievalMethod, xml_string)


class Modulus(DsBase):
    """The ds:Modulus element"""

    c_tag = 'Modulus'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def modulus_from_string(xml_string):
    """ Create Modulus instance from an XML string """
    return create_class_from_xml_string(Modulus, xml_string)


class Exponent(DsBase):
    """The ds:Exponent element"""

    c_tag = 'Exponent'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def exponent_from_string(xml_string):
    """ Create Exponent instance from an XML string """
    return create_class_from_xml_string(Exponent, xml_string)


class RSAKeyValue(DsBase):
    """The ds:RSAKeyValue element"""

    c_tag = 'RSAKeyValue'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}Modulus' % NAMESPACE] = ('modulus', Modulus)
    c_children['{%s}Exponent' % NAMESPACE] = ('exponent', Exponent)
    c_child_order = ['modulus', 'exponent']

    def __init__(self, modulus=None, exponent=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for RSAKeyValue

        :param modulus: Modulus element
        :param exponent: Exponent element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.modulus = modulus
        self.exponent = exponent

def rsa_key_value_from_string(xml_string):
    """ Create RSAKeyValue instance from an XML string """
    return create_class_from_xml_string(RSAKeyValue, xml_string)


class DsP(DsBase):
    """The ds:P element"""

    c_tag = 'P'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def p_from_string(xml_string):
    """ Create DsP instance from an XML string """
    return create_class_from_xml_string(DsP, xml_string)


class DsQ(DsBase):
    """The ds:Q element"""

    c_tag = 'Q'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def q_from_string(xml_string):
    """ Create DsQ instance from an XML string """
    return create_class_from_xml_string(DsQ, xml_string)


class DsG(DsBase):
    """The ds:G element"""

    c_tag = 'G'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def g_from_string(xml_string):
    """ Create DsG instance from an XML string """
    return create_class_from_xml_string(DsG, xml_string)


class DsY(DsBase):
    """The ds:Y element"""

    c_tag = 'Y'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def y_from_string(xml_string):
    """ Create DsY instance from an XML string """
    return create_class_from_xml_string(DsY, xml_string)


class DsJ(DsBase):
    """The ds:J element"""

    c_tag = 'J'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def j_from_string(xml_string):
    """ Create DsJ instance from an XML string """
    return create_class_from_xml_string(DsJ, xml_string)


class Seed(DsBase):
    """The ds:Seed element"""

    c_tag = 'Seed'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def seed_from_string(xml_string):
    """ Create Seed instance from an XML string """
    return create_class_from_xml_string(Seed, xml_string)


class PgenCounter(DsBase):
    """The ds:PgenCounter element"""

    c_tag = 'PgenCounter'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def pgen_counter_from_string(xml_string):
    """ Create PgenCounter instance from an XML string """
    return create_class_from_xml_string(PgenCounter, xml_string)


class DSAKeyValue(DsBase):
    """The ds:DSAKeyValue element"""

    c_tag = 'DSAKeyValue'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}P' % NAMESPACE] = ('p', DsP)
    c_children['{%s}Q' % NAMESPACE] = ('q', DsQ)
    c_children['{%s}G' % NAMESPACE] = ('g', DsG)
    c_children['{%s}Y' % NAMESPACE] = ('y', DsY)
    c_children['{%s}J' % NAMESPACE] = ('j', DsJ)
    c_children['{%s}Seed' % NAMESPACE] = ('seed', Seed)
    c_children['{%s}PgenCounter' % NAMESPACE] = ('pgen_counter', PgenCounter)

    c_child_order = ['p', 'q', 'g', 'y', 'j', 'seed', 'pgen_counter']

    def __init__(self, p=None, q=None, g=None, y=None, j=None, seed=None,
                pgen_counter=None, text=None, extension_elements=None, 
                extension_attributes=None):
        """Constructor for DSAKeyValue

        :param p: P element
        :param q: Q element
        :param g: G element
        :param y: Y element
        :param j: J element
        :param seed: Seed element
        :param pgen_counter: PgenCounter element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.p = p
        self.q = q
        self.g = g
        self.y = y
        self.j = j
        self.seed = Seed
        self.pgen_counter = pgen_counter

def dsa_key_value_from_string(xml_string):
    """ Create DSAKeyValue instance from an XML string """
    return create_class_from_xml_string(DSAKeyValue, xml_string)


class KeyValue(DsBase):
    """The ds:KeyValue element"""

    c_tag = 'KeyValue'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_children['{%s}RSAKeyValue' % NAMESPACE] = ('rsa_key_value', 
                                                    RSAKeyValue)
    c_children['{%s}DSAKeyValue' % NAMESPACE] = ('dsa_key_value', 
                                                    DSAKeyValue)

    c_child_order = ['rsa_key_value', 'dsa_key_value']

    def __init__(self, rsa_key_value=None, dsa_key_value=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for DSAKeyValue

        :param rsa_key_value: RSAKeyValue element
        :param dsa_key_value: DSAKeyValue element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.rsa_key_value = rsa_key_value
        self.dsa_key_value = dsa_key_value

def key_value_from_string(xml_string):
    """ Create KeyValue instance from an XML string """
    return create_class_from_xml_string(KeyValue, xml_string)


class KeyName(DsBase):
    """The ds:KeyName element"""

    c_tag = 'KeyName'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def key_name_from_string(xml_string):
    """ Create KeyName instance from an XML string """
    return create_class_from_xml_string(KeyName, xml_string)


class KeyInfo(DsBase):
    """The ds:KeyInfo element"""

    c_tag = 'KeyInfo'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Id'] = "identifier"
    c_children['{%s}KeyName' % NAMESPACE] = ('key_name', [KeyName])
    c_children['{%s}KeyValue' % NAMESPACE] = ('key_value', [KeyValue])
    c_children['{%s}RetrievalMethod' % NAMESPACE] = (
        'retrieval_method', [RetrievalMethod])
    c_children['{%s}X509Data' % NAMESPACE] = ('x509_data', [X509Data])
    c_children['{%s}PGPData' % NAMESPACE] = ('pgp_data', [PGPData])
    c_children['{%s}SPKIData' % NAMESPACE] = ('spki_data', [SPKIData])
    c_children['{%s}MgmtData' % NAMESPACE] = ('mgmt_data', [MgmtData])
#    c_children['{%s}EncryptedKey' % xmlenc.NAMESPACE] = (
#                        'encrypted_key', [xmlenc.EncryptedKey])

    c_child_order = ['key_name', 'key_value', 'retrieval_method', 'x509_data',
                    'pgp_data', 'spki_data', 'mgmt_data',
                    'encrypted_key']

    def __init__(self, key_name=None, key_value=None, retrieval_method=None,
                x509_data=None, pgp_data=None, spki_data=None, mgmt_data=None,
                encrypted_key=None, identifier=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for DSAKeyValue

        :param key_name: KeyName elements
        :param key_value: KeyValue elements
        :param retrieval_method: RetrievalMethod elements
        :param x509_data: X509Data elements
        :param pgp_data: PGPData elements
        :param spki_data: SPKIData elements
        :param mgmt_data: MgmtData elements
        :param identifier: Id attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.key_name = key_name or []
        self.key_value = key_value or []
        self.retrieval_method = retrieval_method or []
        self.x509_data = x509_data or []
        self.pgp_data = pgp_data or []
        self.spki_data = spki_data or []
        self.mgmt_data = mgmt_data or []
        self.encrypted_key = encrypted_key or []
        self.identifier = identifier

def key_info_from_string(xml_string):
    """ Create KeyInfo instance from an XML string """
    return create_class_from_xml_string(KeyInfo, xml_string)


class DigestValue(DsBase):
    """The ds:DigestValue element"""

    c_tag = 'DigestValue'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def digest_value_from_string(xml_string):
    """ Create DigestValue instance from an XML string """
    return create_class_from_xml_string(DigestValue, xml_string)


class DigestMethod(DsBase):
    """The ds:DigestMethod element"""

    c_tag = 'DigestMethod'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Algorithm'] = "algorithm"

    def __init__(self, algorithm=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for DigestMethod

        :param algorithm: Algorithm attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.algorithm = algorithm

def digest_method_from_string(xml_string):
    """ Create DigestMethod instance from an XML string """
    return create_class_from_xml_string(DigestMethod, xml_string)


class Reference(DsBase):
    """The ds:Reference element"""

    c_tag = 'Reference'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Id'] = "identifier"
    c_attributes['URI'] = "uri"
    c_attributes['Type'] = "type"
    c_children['{%s}Transforms' % NAMESPACE] = ('transforms', [Transforms])
    c_children['{%s}DigestMethod' % NAMESPACE] = (
        'digest_method', [DigestMethod])
    c_children['{%s}DigestValue' % NAMESPACE] = ('digest_value', 
                                                    [DigestValue])
    c_child_order = ['transforms', 'digest_method', 'digest_value']

    def __init__(self, identifier=None, uri=None, typ=None, transforms=None,
                digest_method=None, digest_value=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for Reference

        Args:
        :param identifier: Id attribute
        :param uri: URI attribute
        :param type: Type attribute
        :param transforms: Transforms elements
        :param digest_method: DigestMethod elements
        :param digest_value: DigestValue elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier
        self.uri = uri
        self.type = typ
        self.transforms = transforms or []
        self.digest_method = digest_method or []
        self.digest_value = digest_value or []

def reference_from_string(xml_string):
    """ Create Reference instance from an XML string """
    return create_class_from_xml_string(Reference, xml_string)


class HMACOutputLength(DsBase):
    """The ds:HMACOutputLength element"""

    c_tag = 'HMACOutputLength'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()

def hmac_output_length_from_string(xml_string):
    """ Create HMACOutputLength instance from an XML string """
    return create_class_from_xml_string(HMACOutputLength, xml_string)


class SignatureMethod(DsBase):
    """The ds:SignatureMethod element"""

    c_tag = 'SignatureMethod'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Algorithm'] = "algorithm"
    c_children['{%s}HMACOutputLength' % NAMESPACE] = (
        'hmac_output_length', HMACOutputLength)

    def __init__(self, algorithm=None, hmac_output_length=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for SignatureMethod

        :param algorighm: Algorithm attribute
        :param hmac_output_length: HMACOutputLength element
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.algorithm = algorithm
        self.hmac_output_length = hmac_output_length

def signature_method_from_string(xml_string):
    """ Create SignatureMethod instance from an XML string """
    return create_class_from_xml_string(SignatureMethod, xml_string)


class CanonicalizationMethod(DsBase):
    """The ds:CanonicalizationMethod element"""

    c_tag = 'CanonicalizationMethod'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Algorithm'] = "algorithm"

    def __init__(self, algorithm=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for CanonicalizationMethod

        :param algorighm: Algorithm attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.algorithm = algorithm

def canonicalization_method_from_string(xml_string):
    """ Create CanonicalizationMethod instance from an XML string """
    return create_class_from_xml_string(CanonicalizationMethod, xml_string)


class SignedInfo(DsBase):
    """The ds:SignedInfo element"""

    c_tag = 'SignedInfo'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Id'] = "identifier"
    c_children['{%s}CanonicalizationMethod' % NAMESPACE] = (
        'canonicalization_method', CanonicalizationMethod)
    c_children['{%s}SignatureMethod' % NAMESPACE] = (
        'signature_method', SignatureMethod)
    c_children['{%s}Reference' % NAMESPACE] = ('reference', [Reference])
    c_child_order = ['canonicalization_method', 'signature_method',
                                    'reference']

    def __init__(self, identifier=None, canonicalization_method=None,
                signature_method=None, reference=None, text=None,
                extension_elements=None, extension_attributes=None):
        """Constructor for SignedInfo

        :param identifier: Id attribute
        :param canonicalization_method: CanonicalizationMethod element
        :param signature_method: SignatureMethod element
        :param reference: Reference elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier
        self.canonicalization_method = canonicalization_method
        self.signature_method = signature_method
        self.reference = reference or []

def signed_info_from_string(xml_string):
    """ Create SignedInfo instance from an XML string """
    return create_class_from_xml_string(SignedInfo, xml_string)


class SignatureValue(DsBase):
    """The ds:SignatureValue element"""

    c_tag = 'SignatureValue'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Id'] = "identifier"

    def __init__(self, identifier=None, text=None, extension_elements=None, 
                    extension_attributes=None):
        """Constructor for SignatureValue

        Args:
        :param identifier: Id attribute
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.identifier = identifier

def signature_value_from_string(xml_string):
    """ Create SignatureValue instance from an XML string """
    return create_class_from_xml_string(SignatureValue, xml_string)


class Signature(DsBase):
    """The ds:Signature element"""

    c_tag = 'Signature'
    c_namespace = NAMESPACE
    c_children = DsBase.c_children.copy()
    c_attributes = DsBase.c_attributes.copy()
    c_attributes['Id'] = "id"
    c_children['{%s}SignedInfo' % NAMESPACE] = ('signed_info', SignedInfo)
    c_children['{%s}SignatureValue' % NAMESPACE] = (
        'signature_value', SignatureValue)
    c_children['{%s}KeyInfo' % NAMESPACE] = ('key_info', KeyInfo)
    c_children['{%s}Object' % NAMESPACE] = ('object', [Object])
    c_child_order = ["signed_info", "signature_value", "key_info", "object"]

    def __init__(self, id=None, signed_info=None, signature_value=None,
                    key_info=None, objects=None, text=None,
                    extension_elements=None, extension_attributes=None):
        """Constructor for Signature

        :param identifier: Id attribute
        :param signed_info: SignedInfo element
        :param signature_value: SignatureValue element
        :param key_info: KeyInfo element
        :param object: Object elements
        :param text: The text data in the this element
        :param extension_elements: A list of ExtensionElement instances
        :param extension_attributes: A dictionary of attribute value string pairs
        """

        DsBase.__init__(self, text, extension_elements, extension_attributes)
        self.id = id
        self.signed_info = signed_info
        self.signature_value = signature_value
        self.key_info = key_info
        self.object = objects or []


def signature_from_string(xml_string):
    """ Create Signature instance from an XML string """
    return create_class_from_xml_string(Signature, xml_string)


def get_empty_signature(canonicalization_method_algorithm=C14N_WITH_C,
                        signature_method_algorithm=SIG_RSA_SHA1,
                        transform_algorithm=TRANSFORM_ENVELOPED,
                        digest_algorithm=DIGEST_SHA1):

    canonicalization_method = CanonicalizationMethod(
        algorithm=canonicalization_method_algorithm)
    signature_method = SignatureMethod(algorithm=signature_method_algorithm)
    transforms = Transforms(transform=Transform(algorithm=transform_algorithm))
    digest_method = DigestMethod(algorithm=digest_algorithm)
    reference = Reference(uri="", transforms=transforms,
                            digest_method=digest_method,
                            digest_value=DigestValue())
    signed_info = SignedInfo(
        canonicalization_method=canonicalization_method,
        signature_method=signature_method,
        reference=reference)
    signature = Signature(signed_info=signed_info,
                            signature_value=SignatureValue(),
                            key_info=KeyInfo(key_value=KeyValue()))
    return signature


ELEMENT_FROM_STRING = {
    Object.c_tag: object_from_string,
    MgmtData.c_tag: mgmt_data_from_string,
    SPKISexp.c_tag: spki_sexp_from_string,
    SPKIData.c_tag: spki_data_from_string,
    PGPKeyID.c_tag: pgp_key_id_from_string,
    PGPKeyPacket.c_tag: pgp_key_packet_from_string,
    PGPData.c_tag: pgp_data_from_string,
    X509IssuerName.c_tag: x509_issuer_name_from_string,
    X509IssuerNumber.c_tag: x509_issuer_number_from_string,
    X509IssuerSerial.c_tag: x509_issuer_serial_from_string,
    X509SKI.c_tag: x509_ski_from_string,
    X509SubjectName.c_tag: x509_subject_name_from_string,
    X509Certificate.c_tag: x509_certificate_from_string,
    X509CRL.c_tag: x509_crl_from_string,
    X509Data.c_tag: x509_data_from_string,
    XPath.c_tag: xpath_from_string,
    Transform.c_tag: transform_from_string,
    Transforms.c_tag: transforms_from_string,
    RetrievalMethod.c_tag: retrieval_method_from_string,
    Modulus.c_tag: modulus_from_string,
    Exponent.c_tag: exponent_from_string,
    RSAKeyValue.c_tag: rsa_key_value_from_string,
    DsP.c_tag: p_from_string,
    DsQ.c_tag: q_from_string,
    DsG.c_tag: g_from_string,
    DsY.c_tag: y_from_string,
    DsJ.c_tag: j_from_string,
    Seed.c_tag: seed_from_string,
    PgenCounter.c_tag: pgen_counter_from_string,
    DSAKeyValue.c_tag: dsa_key_value_from_string,
    KeyValue.c_tag: key_value_from_string,
    KeyName.c_tag: key_name_from_string,
    KeyInfo.c_tag: key_info_from_string,
    DigestValue.c_tag: digest_value_from_string,
    DigestMethod.c_tag: digest_method_from_string,
    Reference.c_tag: reference_from_string,
    HMACOutputLength.c_tag: hmac_output_length_from_string,
    SignatureMethod.c_tag: signature_method_from_string,
    CanonicalizationMethod.c_tag: canonicalization_method_from_string,
    SignedInfo.c_tag: signed_info_from_string,
    SignatureValue.c_tag: signature_value_from_string,
    Signature.c_tag: signature_from_string,
}
