#!/usr/bin/env python

#
# Generated Tue Aug  3 20:39:24 2010 by parse_xsd.py version 0.3.
#

import saml2
from saml2 import SamlBase


NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'


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


class CryptoBinary(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:CryptoBinary element """

    c_tag = 'CryptoBinary'
    c_namespace = NAMESPACE
    c_value_type = {'base': 'base64Binary'}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def crypto_binary_from_string(xml_string):
    return saml2.create_class_from_xml_string(CryptoBinary, xml_string)

class SignatureValueType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SignatureValueType element """

    c_tag = 'SignatureValueType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes['Id'] = ('id', 'ID', False)

    def __init__(self,
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
        self.id=id

def signature_value_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignatureValueType, xml_string)

class CanonicalizationMethodType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:CanonicalizationMethodType element """

    c_tag = 'CanonicalizationMethodType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes['Algorithm'] = ('algorithm', 'anyURI', True)

    def __init__(self,
            algorithm=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.algorithm=algorithm

def canonicalization_method_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(CanonicalizationMethodType, xml_string)

class XPath(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:XPath element """

    c_tag = 'XPath'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def x_path_from_string(xml_string):
    return saml2.create_class_from_xml_string(XPath, xml_string)

class TransformType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:TransformType element """

    c_tag = 'TransformType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}XPath'] = ('x_path', [XPath])
    c_cardinality['x_path'] = {"min":0}
    c_attributes['Algorithm'] = ('algorithm', 'anyURI', True)
    c_child_order.extend(['x_path'])

    def __init__(self,
            x_path=None,
            algorithm=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.x_path=x_path or []
        self.algorithm=algorithm

def transform_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(TransformType, xml_string)

class DigestMethodType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:DigestMethodType element """

    c_tag = 'DigestMethodType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes['Algorithm'] = ('algorithm', 'anyURI', True)

    def __init__(self,
            algorithm=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.algorithm=algorithm

def digest_method_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(DigestMethodType, xml_string)

class DigestValueType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:DigestValueType element """

    c_tag = 'DigestValueType'
    c_namespace = NAMESPACE
    c_value_type = {'base': 'base64Binary'}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def digest_value_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(DigestValueType, xml_string)

class KeyName(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:KeyName element """

    c_tag = 'KeyName'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def key_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyName, xml_string)

class MgmtData(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:MgmtData element """

    c_tag = 'MgmtData'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def mgmt_data_from_string(xml_string):
    return saml2.create_class_from_xml_string(MgmtData, xml_string)

class X509IssuerName(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509IssuerName element """

    c_tag = 'X509IssuerName'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def x509_issuer_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509IssuerName, xml_string)

class X509SerialNumber(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509SerialNumber element """

    c_tag = 'X509SerialNumber'
    c_namespace = NAMESPACE
    c_value_type = 'integer'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def x509_serial_number_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509SerialNumber, xml_string)

class X509IssuerSerialType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509IssuerSerialType element """

    c_tag = 'X509IssuerSerialType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509IssuerName'] = ('x509_issuer_name', X509IssuerName)
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber'] = ('x509_serial_number', X509SerialNumber)
    c_child_order.extend(['x509_issuer_name', 'x509_serial_number'])

    def __init__(self,
            x509_issuer_name=None,
            x509_serial_number=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.x509_issuer_name=x509_issuer_name
        self.x509_serial_number=x509_serial_number

def x509_issuer_serial_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509IssuerSerialType, xml_string)

class PGPKeyID(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:PGPKeyID element """

    c_tag = 'PGPKeyID'
    c_namespace = NAMESPACE
    c_value_type = 'base64Binary'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def pgp_key_id_from_string(xml_string):
    return saml2.create_class_from_xml_string(PGPKeyID, xml_string)

class PGPKeyPacket(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:PGPKeyPacket element """

    c_tag = 'PGPKeyPacket'
    c_namespace = NAMESPACE
    c_value_type = 'base64Binary'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def pgp_key_packet_from_string(xml_string):
    return saml2.create_class_from_xml_string(PGPKeyPacket, xml_string)

class PGPDataType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:PGPDataType element """

    c_tag = 'PGPDataType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}PGPKeyID'] = ('pgp_key_id', PGPKeyID)
    c_children['{http://www.w3.org/2000/09/xmldsig#}PGPKeyPacket'] = ('pgp_key_packet', PGPKeyPacket)
    c_cardinality['pgp_key_packet'] = {"min":0, "max":1}
    c_child_order.extend(['pgp_key_id', 'pgp_key_packet'])

    def __init__(self,
            pgp_key_id=None,
            pgp_key_packet=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.pgp_key_id=pgp_key_id
        self.pgp_key_packet=pgp_key_packet

def pgp_data_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(PGPDataType, xml_string)

class SPKISexp(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SPKISexp element """

    c_tag = 'SPKISexp'
    c_namespace = NAMESPACE
    c_value_type = 'base64Binary'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def spki_sexp_from_string(xml_string):
    return saml2.create_class_from_xml_string(SPKISexp, xml_string)

class SPKIDataType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SPKIDataType element """

    c_tag = 'SPKIDataType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}SPKISexp'] = ('spki_sexp', [SPKISexp])
    c_cardinality['spki_sexp'] = {"min":1}
    c_child_order.extend(['spki_sexp'])

    def __init__(self,
            spki_sexp=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.spki_sexp=spki_sexp or []

def spki_data_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SPKIDataType, xml_string)

class ObjectType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:ObjectType element """

    c_tag = 'ObjectType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes['Id'] = ('id', 'ID', False)
    c_attributes['MimeType'] = ('mime_type', 'string', False)
    c_attributes['Encoding'] = ('encoding', 'anyURI', False)

    def __init__(self,
            id=None,
            mime_type=None,
            encoding=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.id=id
        self.mime_type=mime_type
        self.encoding=encoding

def object_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ObjectType, xml_string)

class SignaturePropertyType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SignaturePropertyType element """

    c_tag = 'SignaturePropertyType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes['Target'] = ('target', 'anyURI', True)
    c_attributes['Id'] = ('id', 'ID', False)

    def __init__(self,
            target=None,
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
        self.target=target
        self.id=id

def signature_property_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignaturePropertyType, xml_string)

class HMACOutputLengthType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:HMACOutputLengthType element """

    c_tag = 'HMACOutputLengthType'
    c_namespace = NAMESPACE
    c_value_type = {'base': 'integer'}
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def hmac_output_length_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(HMACOutputLengthType, xml_string)

class P(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:P element """

    c_tag = 'P'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def p_from_string(xml_string):
    return saml2.create_class_from_xml_string(P, xml_string)

class Q(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:Q element """

    c_tag = 'Q'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def q_from_string(xml_string):
    return saml2.create_class_from_xml_string(Q, xml_string)

class G(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:G element """

    c_tag = 'G'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def g_from_string(xml_string):
    return saml2.create_class_from_xml_string(G, xml_string)

class Y(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:Y element """

    c_tag = 'Y'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def y_from_string(xml_string):
    return saml2.create_class_from_xml_string(Y, xml_string)

class J(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:J element """

    c_tag = 'J'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def j_from_string(xml_string):
    return saml2.create_class_from_xml_string(J, xml_string)

class Seed(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:Seed element """

    c_tag = 'Seed'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def seed_from_string(xml_string):
    return saml2.create_class_from_xml_string(Seed, xml_string)

class PgenCounter(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:PgenCounter element """

    c_tag = 'PgenCounter'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def pgen_counter_from_string(xml_string):
    return saml2.create_class_from_xml_string(PgenCounter, xml_string)

class DSAKeyValueType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:DSAKeyValueType element """

    c_tag = 'DSAKeyValueType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}P'] = ('p', P)
    c_cardinality['p'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}Q'] = ('q', Q)
    c_cardinality['q'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}G'] = ('g', G)
    c_cardinality['g'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}Y'] = ('y', Y)
    c_children['{http://www.w3.org/2000/09/xmldsig#}J'] = ('j', J)
    c_cardinality['j'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}Seed'] = ('seed', Seed)
    c_cardinality['seed'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}PgenCounter'] = ('pgen_counter', PgenCounter)
    c_cardinality['pgen_counter'] = {"min":0, "max":1}
    c_child_order.extend(['p', 'q', 'g', 'y', 'j', 'seed', 'pgen_counter'])

    def __init__(self,
            p=None,
            q=None,
            g=None,
            y=None,
            j=None,
            seed=None,
            pgen_counter=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.p=p
        self.q=q
        self.g=g
        self.y=y
        self.j=j
        self.seed=seed
        self.pgen_counter=pgen_counter

def dsa_key_value_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(DSAKeyValueType, xml_string)

class Modulus(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:Modulus element """

    c_tag = 'Modulus'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def modulus_from_string(xml_string):
    return saml2.create_class_from_xml_string(Modulus, xml_string)

class Exponent(CryptoBinary):
    """The http://www.w3.org/2000/09/xmldsig#:Exponent element """

    c_tag = 'Exponent'
    c_namespace = NAMESPACE
    c_children = CryptoBinary.c_children.copy()
    c_attributes = CryptoBinary.c_attributes.copy()
    c_child_order = CryptoBinary.c_child_order[:]
    c_cardinality = CryptoBinary.c_cardinality.copy()

def exponent_from_string(xml_string):
    return saml2.create_class_from_xml_string(Exponent, xml_string)

class RSAKeyValueType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:RSAKeyValueType element """

    c_tag = 'RSAKeyValueType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}Modulus'] = ('modulus', Modulus)
    c_children['{http://www.w3.org/2000/09/xmldsig#}Exponent'] = ('exponent', Exponent)
    c_child_order.extend(['modulus', 'exponent'])

    def __init__(self,
            modulus=None,
            exponent=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.modulus=modulus
        self.exponent=exponent

def rsa_key_value_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(RSAKeyValueType, xml_string)

class SignatureValue(SignatureValueType):
    """The http://www.w3.org/2000/09/xmldsig#:SignatureValue element """

    c_tag = 'SignatureValue'
    c_namespace = NAMESPACE
    c_children = SignatureValueType.c_children.copy()
    c_attributes = SignatureValueType.c_attributes.copy()
    c_child_order = SignatureValueType.c_child_order[:]
    c_cardinality = SignatureValueType.c_cardinality.copy()

def signature_value_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignatureValue, xml_string)

class CanonicalizationMethod(CanonicalizationMethodType):
    """The http://www.w3.org/2000/09/xmldsig#:CanonicalizationMethod element """

    c_tag = 'CanonicalizationMethod'
    c_namespace = NAMESPACE
    c_children = CanonicalizationMethodType.c_children.copy()
    c_attributes = CanonicalizationMethodType.c_attributes.copy()
    c_child_order = CanonicalizationMethodType.c_child_order[:]
    c_cardinality = CanonicalizationMethodType.c_cardinality.copy()

def canonicalization_method_from_string(xml_string):
    return saml2.create_class_from_xml_string(CanonicalizationMethod, xml_string)

class HMACOutputLength(HMACOutputLengthType):
    """The http://www.w3.org/2000/09/xmldsig#:HMACOutputLength element """

    c_tag = 'HMACOutputLength'
    c_namespace = NAMESPACE
    c_children = HMACOutputLengthType.c_children.copy()
    c_attributes = HMACOutputLengthType.c_attributes.copy()
    c_child_order = HMACOutputLengthType.c_child_order[:]
    c_cardinality = HMACOutputLengthType.c_cardinality.copy()

def hmac_output_length_from_string(xml_string):
    return saml2.create_class_from_xml_string(HMACOutputLength, xml_string)

class SignatureMethodType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SignatureMethodType element """

    c_tag = 'SignatureMethodType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}HMACOutputLength'] = ('hmac_output_length', HMACOutputLength)
    c_cardinality['hmac_output_length'] = {"min":0, "max":1}
    c_attributes['Algorithm'] = ('algorithm', 'anyURI', True)
    c_child_order.extend(['hmac_output_length'])

    def __init__(self,
            hmac_output_length=None,
            algorithm=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.hmac_output_length=hmac_output_length
        self.algorithm=algorithm

def signature_method_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignatureMethodType, xml_string)

class Transform(TransformType):
    """The http://www.w3.org/2000/09/xmldsig#:Transform element """

    c_tag = 'Transform'
    c_namespace = NAMESPACE
    c_children = TransformType.c_children.copy()
    c_attributes = TransformType.c_attributes.copy()
    c_child_order = TransformType.c_child_order[:]
    c_cardinality = TransformType.c_cardinality.copy()

def transform_from_string(xml_string):
    return saml2.create_class_from_xml_string(Transform, xml_string)

class DigestMethod(DigestMethodType):
    """The http://www.w3.org/2000/09/xmldsig#:DigestMethod element """

    c_tag = 'DigestMethod'
    c_namespace = NAMESPACE
    c_children = DigestMethodType.c_children.copy()
    c_attributes = DigestMethodType.c_attributes.copy()
    c_child_order = DigestMethodType.c_child_order[:]
    c_cardinality = DigestMethodType.c_cardinality.copy()

def digest_method_from_string(xml_string):
    return saml2.create_class_from_xml_string(DigestMethod, xml_string)

class DigestValue(DigestValueType):
    """The http://www.w3.org/2000/09/xmldsig#:DigestValue element """

    c_tag = 'DigestValue'
    c_namespace = NAMESPACE
    c_children = DigestValueType.c_children.copy()
    c_attributes = DigestValueType.c_attributes.copy()
    c_child_order = DigestValueType.c_child_order[:]
    c_cardinality = DigestValueType.c_cardinality.copy()

def digest_value_from_string(xml_string):
    return saml2.create_class_from_xml_string(DigestValue, xml_string)

class X509IssuerSerial(X509IssuerSerialType):
    """The http://www.w3.org/2000/09/xmldsig#:X509IssuerSerial element """

    c_tag = 'X509IssuerSerial'
    c_namespace = NAMESPACE
    c_children = X509IssuerSerialType.c_children.copy()
    c_attributes = X509IssuerSerialType.c_attributes.copy()
    c_child_order = X509IssuerSerialType.c_child_order[:]
    c_cardinality = X509IssuerSerialType.c_cardinality.copy()

def x509_issuer_serial_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509IssuerSerial, xml_string)

class X509SKI(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509SKI element """

    c_tag = 'X509SKI'
    c_namespace = NAMESPACE
    c_value_type = 'base64Binary'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def x509_ski_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509SKI, xml_string)

class X509SubjectName(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509SubjectName element """

    c_tag = 'X509SubjectName'
    c_namespace = NAMESPACE
    c_value_type = 'string'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def x509_subject_name_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509SubjectName, xml_string)

class X509Certificate(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509Certificate element """

    c_tag = 'X509Certificate'
    c_namespace = NAMESPACE
    c_value_type = 'base64Binary'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def x509_certificate_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509Certificate, xml_string)

class X509CRL(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509CRL element """

    c_tag = 'X509CRL'
    c_namespace = NAMESPACE
    c_value_type = 'base64Binary'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()

def x509_crl_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509CRL, xml_string)

class X509DataType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:X509DataType element """

    c_tag = 'X509DataType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509IssuerSerial'] = ('x509_issuer_serial', X509IssuerSerial)
    c_cardinality['x509_issuer_serial'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509SKI'] = ('x509_ski', X509SKI)
    c_cardinality['x509_ski'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509SubjectName'] = ('x509_subject_name', X509SubjectName)
    c_cardinality['x509_subject_name'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509Certificate'] = ('x509_certificate', X509Certificate)
    c_cardinality['x509_certificate'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509CRL'] = ('x509_crl', X509CRL)
    c_cardinality['x509_crl'] = {"min":0, "max":1}
    c_child_order.extend(['x509_issuer_serial', 'x509_ski', 'x509_subject_name', 'x509_certificate', 'x509_crl'])

    def __init__(self,
            x509_issuer_serial=None,
            x509_ski=None,
            x509_subject_name=None,
            x509_certificate=None,
            x509_crl=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.x509_issuer_serial=x509_issuer_serial
        self.x509_ski=x509_ski
        self.x509_subject_name=x509_subject_name
        self.x509_certificate=x509_certificate
        self.x509_crl=x509_crl

def x509_data_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509DataType, xml_string)

class PGPData(PGPDataType):
    """The http://www.w3.org/2000/09/xmldsig#:PGPData element """

    c_tag = 'PGPData'
    c_namespace = NAMESPACE
    c_children = PGPDataType.c_children.copy()
    c_attributes = PGPDataType.c_attributes.copy()
    c_child_order = PGPDataType.c_child_order[:]
    c_cardinality = PGPDataType.c_cardinality.copy()

def pgp_data_from_string(xml_string):
    return saml2.create_class_from_xml_string(PGPData, xml_string)

class SPKIData(SPKIDataType):
    """The http://www.w3.org/2000/09/xmldsig#:SPKIData element """

    c_tag = 'SPKIData'
    c_namespace = NAMESPACE
    c_children = SPKIDataType.c_children.copy()
    c_attributes = SPKIDataType.c_attributes.copy()
    c_child_order = SPKIDataType.c_child_order[:]
    c_cardinality = SPKIDataType.c_cardinality.copy()

def spki_data_from_string(xml_string):
    return saml2.create_class_from_xml_string(SPKIData, xml_string)

class Object(ObjectType):
    """The http://www.w3.org/2000/09/xmldsig#:Object element """

    c_tag = 'Object'
    c_namespace = NAMESPACE
    c_children = ObjectType.c_children.copy()
    c_attributes = ObjectType.c_attributes.copy()
    c_child_order = ObjectType.c_child_order[:]
    c_cardinality = ObjectType.c_cardinality.copy()

def object_from_string(xml_string):
    return saml2.create_class_from_xml_string(Object, xml_string)

class SignatureProperty(SignaturePropertyType):
    """The http://www.w3.org/2000/09/xmldsig#:SignatureProperty element """

    c_tag = 'SignatureProperty'
    c_namespace = NAMESPACE
    c_children = SignaturePropertyType.c_children.copy()
    c_attributes = SignaturePropertyType.c_attributes.copy()
    c_child_order = SignaturePropertyType.c_child_order[:]
    c_cardinality = SignaturePropertyType.c_cardinality.copy()

def signature_property_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignatureProperty, xml_string)

class DSAKeyValue(DSAKeyValueType):
    """The http://www.w3.org/2000/09/xmldsig#:DSAKeyValue element """

    c_tag = 'DSAKeyValue'
    c_namespace = NAMESPACE
    c_children = DSAKeyValueType.c_children.copy()
    c_attributes = DSAKeyValueType.c_attributes.copy()
    c_child_order = DSAKeyValueType.c_child_order[:]
    c_cardinality = DSAKeyValueType.c_cardinality.copy()

def dsa_key_value_from_string(xml_string):
    return saml2.create_class_from_xml_string(DSAKeyValue, xml_string)

class RSAKeyValue(RSAKeyValueType):
    """The http://www.w3.org/2000/09/xmldsig#:RSAKeyValue element """

    c_tag = 'RSAKeyValue'
    c_namespace = NAMESPACE
    c_children = RSAKeyValueType.c_children.copy()
    c_attributes = RSAKeyValueType.c_attributes.copy()
    c_child_order = RSAKeyValueType.c_child_order[:]
    c_cardinality = RSAKeyValueType.c_cardinality.copy()

def rsa_key_value_from_string(xml_string):
    return saml2.create_class_from_xml_string(RSAKeyValue, xml_string)

class SignatureMethod(SignatureMethodType):
    """The http://www.w3.org/2000/09/xmldsig#:SignatureMethod element """

    c_tag = 'SignatureMethod'
    c_namespace = NAMESPACE
    c_children = SignatureMethodType.c_children.copy()
    c_attributes = SignatureMethodType.c_attributes.copy()
    c_child_order = SignatureMethodType.c_child_order[:]
    c_cardinality = SignatureMethodType.c_cardinality.copy()

def signature_method_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignatureMethod, xml_string)

class TransformsType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:TransformsType element """

    c_tag = 'TransformsType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}Transform'] = ('transform', [Transform])
    c_cardinality['transform'] = {"min":1}
    c_child_order.extend(['transform'])

    def __init__(self,
            transform=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.transform=transform or []

def transforms_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(TransformsType, xml_string)

class KeyValueType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:KeyValueType element """

    c_tag = 'KeyValueType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}DSAKeyValue'] = ('dsa_key_value', DSAKeyValue)
    c_cardinality['dsa_key_value'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}RSAKeyValue'] = ('rsa_key_value', RSAKeyValue)
    c_cardinality['rsa_key_value'] = {"min":0, "max":1}
    c_child_order.extend(['dsa_key_value', 'rsa_key_value'])

    def __init__(self,
            dsa_key_value=None,
            rsa_key_value=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.dsa_key_value=dsa_key_value
        self.rsa_key_value=rsa_key_value

def key_value_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyValueType, xml_string)

class X509Data(X509DataType):
    """The http://www.w3.org/2000/09/xmldsig#:X509Data element """

    c_tag = 'X509Data'
    c_namespace = NAMESPACE
    c_children = X509DataType.c_children.copy()
    c_attributes = X509DataType.c_attributes.copy()
    c_child_order = X509DataType.c_child_order[:]
    c_cardinality = X509DataType.c_cardinality.copy()

def x509_data_from_string(xml_string):
    return saml2.create_class_from_xml_string(X509Data, xml_string)

class SignaturePropertiesType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SignaturePropertiesType element """

    c_tag = 'SignaturePropertiesType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}SignatureProperty'] = ('signature_property', [SignatureProperty])
    c_cardinality['signature_property'] = {"min":1}
    c_attributes['Id'] = ('id', 'ID', False)
    c_child_order.extend(['signature_property'])

    def __init__(self,
            signature_property=None,
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
        self.signature_property=signature_property or []
        self.id=id

def signature_properties_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignaturePropertiesType, xml_string)

class Transforms(TransformsType):
    """The http://www.w3.org/2000/09/xmldsig#:Transforms element """

    c_tag = 'Transforms'
    c_namespace = NAMESPACE
    c_children = TransformsType.c_children.copy()
    c_attributes = TransformsType.c_attributes.copy()
    c_child_order = TransformsType.c_child_order[:]
    c_cardinality = TransformsType.c_cardinality.copy()

def transforms_from_string(xml_string):
    return saml2.create_class_from_xml_string(Transforms, xml_string)

class KeyValue(KeyValueType):
    """The http://www.w3.org/2000/09/xmldsig#:KeyValue element """

    c_tag = 'KeyValue'
    c_namespace = NAMESPACE
    c_children = KeyValueType.c_children.copy()
    c_attributes = KeyValueType.c_attributes.copy()
    c_child_order = KeyValueType.c_child_order[:]
    c_cardinality = KeyValueType.c_cardinality.copy()

def key_value_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyValue, xml_string)

class RetrievalMethodType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:RetrievalMethodType element """

    c_tag = 'RetrievalMethodType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}Transforms'] = ('transforms', Transforms)
    c_cardinality['transforms'] = {"min":0, "max":1}
    c_attributes['URI'] = ('uri', 'anyURI', False)
    c_attributes['Type'] = ('type', 'anyURI', False)
    c_child_order.extend(['transforms'])

    def __init__(self,
            transforms=None,
            uri=None,
            type=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.transforms=transforms
        self.uri=uri
        self.type=type

def retrieval_method_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(RetrievalMethodType, xml_string)

class SignatureProperties(SignaturePropertiesType):
    """The http://www.w3.org/2000/09/xmldsig#:SignatureProperties element """

    c_tag = 'SignatureProperties'
    c_namespace = NAMESPACE
    c_children = SignaturePropertiesType.c_children.copy()
    c_attributes = SignaturePropertiesType.c_attributes.copy()
    c_child_order = SignaturePropertiesType.c_child_order[:]
    c_cardinality = SignaturePropertiesType.c_cardinality.copy()

def signature_properties_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignatureProperties, xml_string)

class ReferenceType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:ReferenceType element """

    c_tag = 'ReferenceType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}Transforms'] = ('transforms', Transforms)
    c_cardinality['transforms'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}DigestMethod'] = ('digest_method', DigestMethod)
    c_children['{http://www.w3.org/2000/09/xmldsig#}DigestValue'] = ('digest_value', DigestValue)
    c_attributes['Id'] = ('id', 'ID', False)
    c_attributes['URI'] = ('uri', 'anyURI', False)
    c_attributes['Type'] = ('type', 'anyURI', False)
    c_child_order.extend(['transforms', 'digest_method', 'digest_value'])

    def __init__(self,
            transforms=None,
            digest_method=None,
            digest_value=None,
            id=None,
            uri=None,
            type=None,
            text=None,
            extension_elements=None,
            extension_attributes=None,
        ):
        SamlBase.__init__(self, 
                text=text,
                extension_elements=extension_elements,
                extension_attributes=extension_attributes,
                )
        self.transforms=transforms
        self.digest_method=digest_method
        self.digest_value=digest_value
        self.id=id
        self.uri=uri
        self.type=type

def reference_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ReferenceType, xml_string)

class RetrievalMethod(RetrievalMethodType):
    """The http://www.w3.org/2000/09/xmldsig#:RetrievalMethod element """

    c_tag = 'RetrievalMethod'
    c_namespace = NAMESPACE
    c_children = RetrievalMethodType.c_children.copy()
    c_attributes = RetrievalMethodType.c_attributes.copy()
    c_child_order = RetrievalMethodType.c_child_order[:]
    c_cardinality = RetrievalMethodType.c_cardinality.copy()

def retrieval_method_from_string(xml_string):
    return saml2.create_class_from_xml_string(RetrievalMethod, xml_string)

class Reference(ReferenceType):
    """The http://www.w3.org/2000/09/xmldsig#:Reference element """

    c_tag = 'Reference'
    c_namespace = NAMESPACE
    c_children = ReferenceType.c_children.copy()
    c_attributes = ReferenceType.c_attributes.copy()
    c_child_order = ReferenceType.c_child_order[:]
    c_cardinality = ReferenceType.c_cardinality.copy()

def reference_from_string(xml_string):
    return saml2.create_class_from_xml_string(Reference, xml_string)

class KeyInfoType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:KeyInfoType element """

    c_tag = 'KeyInfoType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}KeyName'] = ('key_name', [KeyName])
    c_cardinality['key_name'] = {"min":0}
    c_children['{http://www.w3.org/2000/09/xmldsig#}KeyValue'] = ('key_value', [KeyValue])
    c_cardinality['key_value'] = {"min":0}
    c_children['{http://www.w3.org/2000/09/xmldsig#}RetrievalMethod'] = ('retrieval_method', [RetrievalMethod])
    c_cardinality['retrieval_method'] = {"min":0}
    c_children['{http://www.w3.org/2000/09/xmldsig#}X509Data'] = ('x509_data', [X509Data])
    c_cardinality['x509_data'] = {"min":0}
    c_children['{http://www.w3.org/2000/09/xmldsig#}PGPData'] = ('pgp_data', [PGPData])
    c_cardinality['pgp_data'] = {"min":0}
    c_children['{http://www.w3.org/2000/09/xmldsig#}SPKIData'] = ('spki_data', [SPKIData])
    c_cardinality['spki_data'] = {"min":0}
    c_children['{http://www.w3.org/2000/09/xmldsig#}MgmtData'] = ('mgmt_data', [MgmtData])
    c_cardinality['mgmt_data'] = {"min":0}
    c_attributes['Id'] = ('id', 'ID', False)
    c_child_order.extend(['key_name', 'key_value', 'retrieval_method', 'x509_data', 'pgp_data', 'spki_data', 'mgmt_data'])

    def __init__(self,
            key_name=None,
            key_value=None,
            retrieval_method=None,
            x509_data=None,
            pgp_data=None,
            spki_data=None,
            mgmt_data=None,
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
        self.key_name=key_name or []
        self.key_value=key_value or []
        self.retrieval_method=retrieval_method or []
        self.x509_data=x509_data or []
        self.pgp_data=pgp_data or []
        self.spki_data=spki_data or []
        self.mgmt_data=mgmt_data or []
        self.id=id

def key_info_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyInfoType, xml_string)

class ManifestType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:ManifestType element """

    c_tag = 'ManifestType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}Reference'] = ('reference', [Reference])
    c_cardinality['reference'] = {"min":1}
    c_attributes['Id'] = ('id', 'ID', False)
    c_child_order.extend(['reference'])

    def __init__(self,
            reference=None,
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
        self.reference=reference or []
        self.id=id

def manifest_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(ManifestType, xml_string)

class SignedInfoType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SignedInfoType element """

    c_tag = 'SignedInfoType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod'] = ('canonicalization_method', CanonicalizationMethod)
    c_children['{http://www.w3.org/2000/09/xmldsig#}SignatureMethod'] = ('signature_method', SignatureMethod)
    c_children['{http://www.w3.org/2000/09/xmldsig#}Reference'] = ('reference', [Reference])
    c_cardinality['reference'] = {"min":1}
    c_attributes['Id'] = ('id', 'ID', False)
    c_child_order.extend(['canonicalization_method', 'signature_method', 'reference'])

    def __init__(self,
            canonicalization_method=None,
            signature_method=None,
            reference=None,
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
        self.canonicalization_method=canonicalization_method
        self.signature_method=signature_method
        self.reference=reference or []
        self.id=id

def signed_info_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignedInfoType, xml_string)

class KeyInfo(KeyInfoType):
    """The http://www.w3.org/2000/09/xmldsig#:KeyInfo element """

    c_tag = 'KeyInfo'
    c_namespace = NAMESPACE
    c_children = KeyInfoType.c_children.copy()
    c_attributes = KeyInfoType.c_attributes.copy()
    c_child_order = KeyInfoType.c_child_order[:]
    c_cardinality = KeyInfoType.c_cardinality.copy()

def key_info_from_string(xml_string):
    return saml2.create_class_from_xml_string(KeyInfo, xml_string)

class Manifest(ManifestType):
    """The http://www.w3.org/2000/09/xmldsig#:Manifest element """

    c_tag = 'Manifest'
    c_namespace = NAMESPACE
    c_children = ManifestType.c_children.copy()
    c_attributes = ManifestType.c_attributes.copy()
    c_child_order = ManifestType.c_child_order[:]
    c_cardinality = ManifestType.c_cardinality.copy()

def manifest_from_string(xml_string):
    return saml2.create_class_from_xml_string(Manifest, xml_string)

class SignedInfo(SignedInfoType):
    """The http://www.w3.org/2000/09/xmldsig#:SignedInfo element """

    c_tag = 'SignedInfo'
    c_namespace = NAMESPACE
    c_children = SignedInfoType.c_children.copy()
    c_attributes = SignedInfoType.c_attributes.copy()
    c_child_order = SignedInfoType.c_child_order[:]
    c_cardinality = SignedInfoType.c_cardinality.copy()

def signed_info_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignedInfo, xml_string)

class SignatureType(SamlBase):
    """The http://www.w3.org/2000/09/xmldsig#:SignatureType element """

    c_tag = 'SignatureType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_children['{http://www.w3.org/2000/09/xmldsig#}SignedInfo'] = ('signed_info', SignedInfo)
    c_children['{http://www.w3.org/2000/09/xmldsig#}SignatureValue'] = ('signature_value', SignatureValue)
    c_children['{http://www.w3.org/2000/09/xmldsig#}KeyInfo'] = ('key_info', KeyInfo)
    c_cardinality['key_info'] = {"min":0, "max":1}
    c_children['{http://www.w3.org/2000/09/xmldsig#}Object'] = ('object', [Object])
    c_cardinality['object'] = {"min":0}
    c_attributes['Id'] = ('id', 'ID', False)
    c_child_order.extend(['signed_info', 'signature_value', 'key_info', 'object'])

    def __init__(self,
            signed_info=None,
            signature_value=None,
            key_info=None,
            object=None,
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
        self.signed_info=signed_info
        self.signature_value=signature_value
        self.key_info=key_info
        self.object=object or []
        self.id=id

def signature_type_from_string(xml_string):
    return saml2.create_class_from_xml_string(SignatureType, xml_string)

class Signature(SignatureType):
    """The http://www.w3.org/2000/09/xmldsig#:Signature element """

    c_tag = 'Signature'
    c_namespace = NAMESPACE
    c_children = SignatureType.c_children.copy()
    c_attributes = SignatureType.c_attributes.copy()
    c_child_order = SignatureType.c_child_order[:]
    c_cardinality = SignatureType.c_cardinality.copy()

def signature_from_string(xml_string):
    return saml2.create_class_from_xml_string(Signature, xml_string)

ELEMENT_FROM_STRING = {
    CryptoBinary.c_tag: crypto_binary_from_string,
    Signature.c_tag: signature_from_string,
    SignatureType.c_tag: signature_type_from_string,
    SignatureValue.c_tag: signature_value_from_string,
    SignatureValueType.c_tag: signature_value_type_from_string,
    SignedInfo.c_tag: signed_info_from_string,
    SignedInfoType.c_tag: signed_info_type_from_string,
    CanonicalizationMethod.c_tag: canonicalization_method_from_string,
    CanonicalizationMethodType.c_tag: canonicalization_method_type_from_string,
    SignatureMethod.c_tag: signature_method_from_string,
    SignatureMethodType.c_tag: signature_method_type_from_string,
    Reference.c_tag: reference_from_string,
    ReferenceType.c_tag: reference_type_from_string,
    Transforms.c_tag: transforms_from_string,
    TransformsType.c_tag: transforms_type_from_string,
    Transform.c_tag: transform_from_string,
    TransformType.c_tag: transform_type_from_string,
    DigestMethod.c_tag: digest_method_from_string,
    DigestMethodType.c_tag: digest_method_type_from_string,
    DigestValue.c_tag: digest_value_from_string,
    DigestValueType.c_tag: digest_value_type_from_string,
    KeyInfo.c_tag: key_info_from_string,
    KeyInfoType.c_tag: key_info_type_from_string,
    KeyName.c_tag: key_name_from_string,
    MgmtData.c_tag: mgmt_data_from_string,
    KeyValue.c_tag: key_value_from_string,
    KeyValueType.c_tag: key_value_type_from_string,
    RetrievalMethod.c_tag: retrieval_method_from_string,
    RetrievalMethodType.c_tag: retrieval_method_type_from_string,
    X509Data.c_tag: x509_data_from_string,
    X509DataType.c_tag: x509_data_type_from_string,
    X509IssuerSerialType.c_tag: x509_issuer_serial_type_from_string,
    PGPData.c_tag: pgp_data_from_string,
    PGPDataType.c_tag: pgp_data_type_from_string,
    SPKIData.c_tag: spki_data_from_string,
    SPKIDataType.c_tag: spki_data_type_from_string,
    Object.c_tag: object_from_string,
    ObjectType.c_tag: object_type_from_string,
    Manifest.c_tag: manifest_from_string,
    ManifestType.c_tag: manifest_type_from_string,
    SignatureProperties.c_tag: signature_properties_from_string,
    SignaturePropertiesType.c_tag: signature_properties_type_from_string,
    SignatureProperty.c_tag: signature_property_from_string,
    SignaturePropertyType.c_tag: signature_property_type_from_string,
    HMACOutputLengthType.c_tag: hmac_output_length_type_from_string,
    DSAKeyValue.c_tag: dsa_key_value_from_string,
    DSAKeyValueType.c_tag: dsa_key_value_type_from_string,
    RSAKeyValue.c_tag: rsa_key_value_from_string,
    RSAKeyValueType.c_tag: rsa_key_value_type_from_string,
    XPath.c_tag: x_path_from_string,
    X509IssuerName.c_tag: x509_issuer_name_from_string,
    X509SerialNumber.c_tag: x509_serial_number_from_string,
    PGPKeyID.c_tag: pgp_key_id_from_string,
    PGPKeyPacket.c_tag: pgp_key_packet_from_string,
    SPKISexp.c_tag: spki_sexp_from_string,
    P.c_tag: p_from_string,
    Q.c_tag: q_from_string,
    G.c_tag: g_from_string,
    Y.c_tag: y_from_string,
    J.c_tag: j_from_string,
    Seed.c_tag: seed_from_string,
    PgenCounter.c_tag: pgen_counter_from_string,
    Modulus.c_tag: modulus_from_string,
    Exponent.c_tag: exponent_from_string,
    HMACOutputLength.c_tag: hmac_output_length_from_string,
    X509IssuerSerial.c_tag: x509_issuer_serial_from_string,
    X509SKI.c_tag: x509_ski_from_string,
    X509SubjectName.c_tag: x509_subject_name_from_string,
    X509Certificate.c_tag: x509_certificate_from_string,
    X509CRL.c_tag: x509_crl_from_string,
}

ELEMENT_BY_TAG = {
    'CryptoBinary': CryptoBinary,
    'Signature': Signature,
    'SignatureType': SignatureType,
    'SignatureValue': SignatureValue,
    'SignatureValueType': SignatureValueType,
    'SignedInfo': SignedInfo,
    'SignedInfoType': SignedInfoType,
    'CanonicalizationMethod': CanonicalizationMethod,
    'CanonicalizationMethodType': CanonicalizationMethodType,
    'SignatureMethod': SignatureMethod,
    'SignatureMethodType': SignatureMethodType,
    'Reference': Reference,
    'ReferenceType': ReferenceType,
    'Transforms': Transforms,
    'TransformsType': TransformsType,
    'Transform': Transform,
    'TransformType': TransformType,
    'DigestMethod': DigestMethod,
    'DigestMethodType': DigestMethodType,
    'DigestValue': DigestValue,
    'DigestValueType': DigestValueType,
    'KeyInfo': KeyInfo,
    'KeyInfoType': KeyInfoType,
    'KeyName': KeyName,
    'MgmtData': MgmtData,
    'KeyValue': KeyValue,
    'KeyValueType': KeyValueType,
    'RetrievalMethod': RetrievalMethod,
    'RetrievalMethodType': RetrievalMethodType,
    'X509Data': X509Data,
    'X509DataType': X509DataType,
    'X509IssuerSerialType': X509IssuerSerialType,
    'PGPData': PGPData,
    'PGPDataType': PGPDataType,
    'SPKIData': SPKIData,
    'SPKIDataType': SPKIDataType,
    'Object': Object,
    'ObjectType': ObjectType,
    'Manifest': Manifest,
    'ManifestType': ManifestType,
    'SignatureProperties': SignatureProperties,
    'SignaturePropertiesType': SignaturePropertiesType,
    'SignatureProperty': SignatureProperty,
    'SignaturePropertyType': SignaturePropertyType,
    'HMACOutputLengthType': HMACOutputLengthType,
    'DSAKeyValue': DSAKeyValue,
    'DSAKeyValueType': DSAKeyValueType,
    'RSAKeyValue': RSAKeyValue,
    'RSAKeyValueType': RSAKeyValueType,
    'XPath': XPath,
    'X509IssuerName': X509IssuerName,
    'X509SerialNumber': X509SerialNumber,
    'PGPKeyID': PGPKeyID,
    'PGPKeyPacket': PGPKeyPacket,
    'SPKISexp': SPKISexp,
    'P': P,
    'Q': Q,
    'G': G,
    'Y': Y,
    'J': J,
    'Seed': Seed,
    'PgenCounter': PgenCounter,
    'Modulus': Modulus,
    'Exponent': Exponent,
    'HMACOutputLength': HMACOutputLength,
    'X509IssuerSerial': X509IssuerSerial,
    'X509SKI': X509SKI,
    'X509SubjectName': X509SubjectName,
    'X509Certificate': X509Certificate,
    'X509CRL': X509CRL,
}

def factory(tag, **kwargs):
    return ELEMENT_BY_TAG[tag](**kwargs)

