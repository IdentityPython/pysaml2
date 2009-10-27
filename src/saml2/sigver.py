""" functions connected to signing and verifying """

from saml2 import samlp
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
import base64
import random

XMLSEC_BINARY = "/opt/local/bin/xmlsec1"
ID_ATTR = "ID"
NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
ENC_NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:EncryptedAssertion"

_TEST_ = True

def decrypt( input, key_file, xmlsec_binary):
    fil_p, fil = make_temp("%s" % input, decode=False)
    ntf = NamedTemporaryFile()
    
    com_list = [xmlsec_binary, "--decrypt", 
                 "--privkey-pem", key_file, 
                 "--output", ntf.name,
                 "--id-attr:%s" % ID_ATTR, 
                 ENC_NODE_NAME, fil]

    result = Popen(com_list, stderr=PIPE).communicate()
    ntf.seek(0)
    return ntf.read()

def create_id():
    ret = ""
    for _ in range(40):
        ret = ret + chr(random.randint(0, 15) + ord('a'))
    return ret
    
def make_temp(string, suffix="", decode=True):
    """ xmlsec needs files in some cases and I have string hence the
    need for this function, that creates as temporary file with the
    string as only content.
    
    :param string: The information to be placed in the file
    :param suffix: The temporary file might have to have a specific 
        suffix in certain circumstances.
    :param decode: The input string might be base64 coded. If so it 
        must be decoded before placed in the file.
    :return: 2-tuple with file pointer ( so the calling function can
        close the file) and filename (which is then needed by the 
        xmlsec function).
    """
    ntf = NamedTemporaryFile(suffix=suffix)
    if decode:
        ntf.write(base64.b64decode(string))
    else:
        ntf.write(string)
    ntf.seek(0)
    return ntf, ntf.name

def cert_from_encrypted_assertion(enc_assertion):
#  <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
#    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" 
#      Id="_e569196d0d66132d3091a75b54d97ccd" 
#      Type="http://www.w3.org/2001/04/xmlenc#Element">
#      <xenc:EncryptionMethod 
#        Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc" 
#        xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>
#        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
#          <xenc:EncryptedKey Id="_e413a3473a60aaa6148664f3b535681f" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
#            <xenc:EncryptionMethod 
#              Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" 
#              xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
#              <ds:DigestMethod 
#                Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" 
#                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
#            </xenc:EncryptionMethod>
#            <ds:KeyInfo>
#              <ds:X509Data>
#                <ds:X509Certificate>
    data = enc_assertion.encrypted_data
    
def cert_from_assertion(assertion):
    """ Find certificates that are part of an assertion

    :param assertion: A saml.Assertion instance
    :return: possible empty list of certificates
    """
    if assertion.signature:
        if assertion.signature.key_info:
            return cert_from_key_info(assertion.signature.key_info)
    return []

def cert_from_key_info(key_info):
    """ Get all X509 certs from a KeyInfo instance. Care is taken to make sure
    that the certs are continues sequences of bytes.

    :param key_info: The KeyInfo instance
    :return: A possibly empty list of certs
    """
    keys = []
    for x509_data in key_info.x509_data:
        #print "X509Data",x509_data
        for x509_certificate in x509_data.x509_certificate:
            cert = x509_certificate.text.strip()
            cert = "".join([s.strip() for s in cert.split("\n")])
            keys.append(cert)
    return keys

def encrypted_cert_from_key_info(key_info):
    """ Get all encrypted X509 certs from a KeyInfo instance. 
    Care is taken to make sure
    that the certs are continues sequences of bytes.

    :param key_info: The KeyInfo instance
    :return: A possibly empty list of certs
    """
    keys = []
    for x509_data in key_info.x509_data:
        #print "X509Data",x509_data
        for x509_certificate in x509_data.x509_certificate:
            cert = x509_certificate.text.strip()
            cert = "".join([s.strip() for s in cert.split("\n")])
            keys.append(cert)
    return keys

def _parse_popen_output(output):
    for line in output.split("\n"):
        if line == "OK":
            return True
        elif line == "FALSE":
            return False
    return False
        
def _verify_signature(xmlsec_binary, input, der_file):
        
    fil_p, fil = make_temp("%s" % input, decode=False)
    
    com_list = [xmlsec_binary, "--verify",
                "--pubkey-cert-der", der_file, 
                "--id-attr:%s" % ID_ATTR, 
                NODE_NAME, fil]

    if _TEST_: 
        print " ".join(com_list)
    verified = _parse_popen_output(Popen(com_list, 
                                    stderr=PIPE).communicate()[1])
    if _TEST_:
        print "Verify result: '%s'" % (verified,)

    return verified
    
def correctly_signed_response(decoded_xml, xmlsec_binary=XMLSEC_BINARY,
        metadata=None, log=None):
    """ Check if a response is correctly signed, if we have metadata for
    the IdP that sent the info use that, if not use the key that are in 
    the message if any.
    
    :param decode_xml: The SAML message as a XML string
    :param xmlsec_binary: Where the xmlsec1 binary can be found on this
        system.
    :param metadata: Metadata information
    :return: None if the signature can not be verified otherwise 
        response as a samlp.Response instance
    """
    if not xmlsec_binary:
        xmlsec_binary = XMLSEC_BINARY
    #log and log.info("Decoded response: %s" % decoded_xml)
    response = samlp.response_from_string(decoded_xml)

    # Try to find the signing cert in the assertion
    for assertion in response.assertion:
        if not assertion.signature:
            if _TEST_:
                print "unsigned"
            continue
        else:
            if _TEST_:
                print "signed"
        
        issuer = assertion.issuer.text.strip()
        if _TEST_:
            print "issuer: %s" % issuer
        if metadata:
            certs = metadata.certs(issuer)
        else:
            certs = []
        if not certs:
            certs = [make_temp("%s" % cert, ".der") \
                        for cert in cert_from_assertion(assertion)]
        if not certs:
            continue

        verified = False
        for _, der_file in certs:
            if _verify_signature(xmlsec_binary, decoded_xml, der_file):
                verified = True
                break
                    
        if not verified:
            return None

    return response
        
def sign_using_xmlsec(statement, sign_key, xmlsec_binary):
    """xmlsec1 --sign --privkey-pem test.key --id-attr:ID 
        urn:oasis:names:tc:SAML:2.0:assertion:Assertion saml_response.xml"""
        
    _, fil = make_temp("%s" % statement, decode=False)
    _, pem_file = make_temp("%s" % sign_key, ".pem")
    
    com_list = [xmlsec_binary, "--sign", 
                "--privkey-cert-pem", pem_file, "--id-attr:%s" % ID_ATTR, 
                "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
                fil]

    #print " ".join(com_list)

    return _parse_popen_output(Popen(com_list, stdout=PIPE).communicate()[0])
        