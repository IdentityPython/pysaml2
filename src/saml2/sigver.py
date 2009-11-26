#!/usr/bin/python
# -*- coding: utf-8 -*-
#
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

""" Functions connected to signing and verifying.
Based on the use of xmlsec1 binaries and not the python xmlsec module.
"""

from saml2 import samlp
import xmldsig as ds
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
import base64
import random
import os

XMLSEC_BINARY = "/opt/local/bin/xmlsec1"
ID_ATTR = "ID"
NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
ENC_NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:EncryptedAssertion"

_TEST_ = False

class SignatureError(Exception):
    pass
    
def decrypt( input, key_file, xmlsec_binary, log=None):
    """ Decrypting an encrypted text by the use of a private key.
    
    :param input: The encrypted text as a string
    :param key_file: The name of the key file
    :param xmlsec_binary: Where on the computer the xmlsec binary is.
    :param log: A reference to a logging instance.
    :return: The decrypted text
    """
    log and log.info("input len: %d" % len(input))
    fil_p, fil = make_temp("%s" % input, decode=False)
    ntf = NamedTemporaryFile()

    log and log.info("xmlsec binary: %s" % xmlsec_binary)
    com_list = [xmlsec_binary, "--decrypt", 
                 "--privkey-pem", key_file, 
                 "--output", ntf.name,
                 "--id-attr:%s" % ID_ATTR, 
                 ENC_NODE_NAME, fil]

    log and log.info("Decrypt command: %s" % " ".join(com_list))
    result = Popen(com_list, stderr=PIPE).communicate()
    log and log.info("Decrypt result: %s" % (result,))

    ntf.seek(0)
    return ntf.read()

def create_id():
    """ Create a string of 40 random characters from the set [a-p], 
    can be used as a unique identifier of objects.
    
    :return: The string of random characters
    """
    ret = ""
    for _ in range(40):
        ret = ret + chr(random.randint(0, 15) + ord('a'))
    return ret
    
def make_temp(string, suffix="", decode=True):
    """ xmlsec needs files in some cases where only strings exist, hence the
    need for this function. It creates a temporary file with the
    string as only content.
    
    :param string: The information to be placed in the file
    :param suffix: The temporary file might have to have a specific 
        suffix in certain circumstances.
    :param decode: The input string might be base64 coded. If so it 
        must, in some cases, be decoded before placed in the file.
    :return: 2-tuple with file pointer ( so the calling function can
        close the file) and filename (which is for instance needed by the 
        xmlsec function).
    """
    ntf = NamedTemporaryFile(suffix=suffix)
    if decode:
        ntf.write(base64.b64decode(string))
    else:
        ntf.write(string)
    ntf.seek(0)
    return ntf, ntf.name
    
def cert_from_key_info(key_info):
    """ Get all X509 certs from a KeyInfo instance. Care is taken to make sure
    that the certs are continues sequences of bytes.

    :param key_info: The KeyInfo instance
    :return: A possibly empty list of certs
    """
    res = []
    for x509_data in key_info.x509_data:
        #print "X509Data",x509_data
        for x509_certificate in x509_data.x509_certificate:
            cert = x509_certificate.text.strip()
            cert = "".join([s.strip() for s in cert.split("\n")])
            res.append(cert)
    return res

def cert_from_instance(instance):
    """ Find certificates that are part of an instance

    :param assertion: An instance
    :return: possible empty list of certificates
    """
    if instance.signature:
        if instance.signature.key_info:
            return cert_from_key_info(instance.signature.key_info)
    return []

def _parse_xmlsec_output(output):
    """ Parse the output from xmlsec to try to find out if the 
    command was successfull or not.
    
    :param output: The output from POpen
    :return: A boolean; True if the command was a success otherwise False
    """ 
    for line in output.split("\n"):
        if line == "OK":
            return True
        elif line == "FALSE":
            return False
    return False
        
def verify_signature_assertion(xmlsec_binary, input, cert_file):
    return verify_signature(xmlsec_binary, input, cert_file,
                            "der",
                            "urn:oasis:names:tc:SAML:2.0:assertion:Assertion")
    
def verify_signature(xmlsec_binary, input, cert_file, 
                        cert_type="der", node_name=NODE_NAME):
    """ Verifies the signature of a XML document.
    
    :param xmlsec_binary: The xmlsec1 binaries to be used
    :param input: The XML document as a string
    :param der_file: The public key that was used to sign the document
    :return: Boolean True if the signature was correct otherwise False.
    """
    fil_p, fil = make_temp("%s" % input, decode=False)
    
    com_list = [xmlsec_binary, "--verify",
                "--pubkey-cert-%s" % cert_type, cert_file, 
                "--id-attr:%s" % ID_ATTR, 
                node_name, fil]

    if _TEST_: 
        print " ".join(com_list)

    output = Popen(com_list, stderr=PIPE).communicate()[1]
    verified = _parse_xmlsec_output(output)

    if _TEST_:
        print output
        print os.stat(cert_file)
        print "Verify result: '%s'" % (verified,)
        fil_p.seek(0)
        print fil_p.read()

    return verified

def correctly_signed_authn_request(decoded_xml, xmlsec_binary=XMLSEC_BINARY,
        metadata=None, log=None, must=False):
    """ Check if a request is correctly signed, if we have metadata for
    the SP that sent the info use that, if not use the key that are in 
    the message if any.
    
    :param decode_xml: The SAML message as a XML string
    :param xmlsec_binary: Where the xmlsec1 binary can be found on this
        system.
    :param metadata: Metadata information
    :return: None if the signature can not be verified otherwise 
        request as a samlp.Request instance
    """
    request = samlp.authn_request_from_string(decoded_xml)

    if not request.signature:
        if must:
            raise SignatureError("Missing must signature")
        else:
            return request
        
    issuer = request.issuer.text.strip()

    if metadata:
        certs = metadata.certs(issuer)
    else:
        certs = []
    if not certs:
        certs = [make_temp("%s" % cert, ".der") \
                    for cert in cert_from_instance(request)]
    if not certs:
        raise SignatureError("Missing signing certificate")

    verified = False
    for _, der_file in certs:
        if verify_signature(xmlsec_binary, decoded_xml, der_file):
            verified = True
            break
                
    if not verified:
        raise SignatureError("Failed to verify signature")

    return request

def correctly_signed_response(decoded_xml, 
        xmlsec_binary=XMLSEC_BINARY, metadata=None, log=None, must=False):
    """ Check if a instance is correctly signed, if we have metadata for
    the IdP that sent the info use that, if not use the key that are in 
    the message if any.
    
    :param decode_xml: The SAML message as a XML string
    :param xmlsec_binary: Where the xmlsec1 binary can be found on this
        system.
    :param metadata: Metadata information
    :return: None if the signature can not be verified otherwise an instance
    """
    
    response = samlp.response_from_string(decoded_xml)

    if not xmlsec_binary:
        xmlsec_binary = XMLSEC_BINARY

    # Try to find the signing cert in the assertion
    for assertion in response.assertion:
        if not assertion.signature:
            if _TEST_:
                log and log.info("unsigned")
            if must:
                raise SignatureError("Signature missing")
            continue
        else:
            if _TEST_:
                log and log.info("signed")
        
        issuer = assertion.issuer.text.strip()
        if _TEST_:
            print "issuer: %s" % issuer
        if metadata:
            certs = metadata.certs(issuer)
        else:
            certs = []

        if _TEST_:
            print "metadata certs: %s" % certs

        if not certs:
            certs = [make_temp("%s" % cert, ".der") \
                        for cert in cert_from_instance(assertion)]
        if not certs:
            raise SignatureError("Missing certificate")

        verified = False
        for _, der_file in certs:
            if verify_signature(xmlsec_binary, decoded_xml, der_file):
                verified = True
                break
                    
        if not verified:
            raise SignatureError("Could not verify")

    return response

#----------------------------------------------------------------------------
# SIGNATURE PART
#----------------------------------------------------------------------------
        
def sign_assertion_using_xmlsec(statement, xmlsec_binary, key=None, 
                                    key_file=None):
    """Sign a SAML statement using xmlsec.
    
    :param statement: The statement to be signed
    :param key: The key to be used for the signing, either this or
    :param key_File: The file where the key can be found
    :param xmlsec_binary: The xmlsec1 binaries used to do the signing.
    :return: The signed statement
    """
        
    _, fil = make_temp("%s" % statement, decode=False)

    if key:
        _, key_file = make_temp("%s" % key, ".pem")
    ntf = NamedTemporaryFile()
    
    com_list = [xmlsec_binary, "--sign", 
                "--output", ntf.name,
                "--privkey-pem", key_file, 
                "--id-attr:%s" % ID_ATTR, 
                "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
                fil]

    #print " ".join(com_list)

    if Popen(com_list, stdout=PIPE).communicate()[0] == "":
        ntf.seek(0)
        return ntf.read()
    else:
        raise Exception("Signing failed")

PRE_SIGNATURE = {
    "signed_info": {
        "signature_method": {
            "algorithm": ds.SIG_RSA_SHA1
        },
        "canonicalization_method": { 
            "algorithm": ds.ALG_EXC_C14N
        },
        "reference": {
            # must be replace by a uriref based on the assertion ID
            "uri": "#%s", 
            "transforms": {
                "transform": [{
                    "algorithm": ds.TRANSFORM_ENVELOPED,
                },
                {  
                    "algorithm": ds.ALG_EXC_C14N,
                    "inclusive_namespaces": {
                        "prefix_list": "ds saml2 saml2p xenc",
                    }   
                }
                ]
            },
            "digest_method":{
                "algorithm": ds.DIGEST_SHA1,
            },
            "digest_value": "",
        }
    },
    "signature_value": None,
}

def pre_signature_part(id):
    """
    If an assertion is to be signed the signature part has to be preset
    with which algorithms to be used, this function returns such a
    preset part.
    
    :param id: The identifier of the assertion, so you know which assertion
        was signed
    :return: A preset signature part
    """
    
    presig = PRE_SIGNATURE
    presig["signed_info"]["reference"]["uri"] = "#%s" % id
    return presig
