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

from saml2 import samlp, class_name, saml
import xmldsig as ds
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
import base64
import random
import os

def get_xmlsec_binary():
    for path in os.environ["PATH"].split(":"):
        fil = os.path.join(path, "xmlsec1")
        if os.access(fil,os.X_OK):
            return fil

    raise Exception("Can't find xmlsec1")
    
XMLSEC_BINARY = get_xmlsec_binary()
ID_ATTR = "ID"
NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
ENC_NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:EncryptedAssertion"

_TEST_ = True

class SignatureError(Exception):
    pass

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

def verify_signature(enctext, xmlsec_binary, cert_file=None, cert_type="", 
                        node_name=NODE_NAME, debug=False):
    """ Verifies the signature of a XML document.
    
    :param xmlsec_binary: The xmlsec1 binaries to be used
    :param input: The XML document as a string
    :param der_file: The public key that was used to sign the document
    :return: Boolean True if the signature was correct otherwise False.
    """
        
    _, fil = make_temp("%s" % enctext, decode=False)
    
    com_list = [xmlsec_binary, "--verify",
                "--pubkey-cert-%s" % cert_type, cert_file, 
                "--id-attr:%s" % ID_ATTR, 
                node_name, fil]

    if debug: 
        try:
            print " ".join(com_list)
        except TypeError:
            print "cert_type", cert_type
            print "cert_file", cert_file
            print "node_name", node_name
            print "fil", fil
            raise
        print "%s: %s" % (cert_file, os.access(cert_file, os.F_OK))
        print "%s: %s" % (fil, os.access(fil, os.F_OK))

    output = Popen(com_list, stderr=PIPE).communicate()[1]
    verified = _parse_xmlsec_output(output)

    if debug:
        print output
        print os.stat(cert_file)
        print "Verify result: '%s'" % (verified,)
        #fil_p.seek(0)
        #print fil_p.read()

    return verified

# ---------------------------------------------------------------------------

def security_context(conf, log=None):
    if not conf:
        return None
        
    try:
        debug = conf["debug"]
    except KeyError:
        debug = 0
        
    return SecurityContext(conf.xmlsec(), conf["key_file"], "pem",
                            conf["cert_file"], "pem", conf["metadata"],
                            log=log, debug=debug)

class SecurityContext(object):
    def __init__(self, xmlsec_binary, key_file="", key_type= "pem", 
                    cert_file="", cert_type="pem", metadata=None, log=None, 
                    debug=False):
        self.xmlsec = xmlsec_binary
        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_type = cert_type
        self.metadata = metadata
        self.log = log
        self.debug = debug

        if self.debug and not self.log:
            self.debug = 0
            
    def correctly_signed(self, xml, must=False):
        self.log and self.log.info("verify correct signature")
        return self.correctly_signed_response(xml, must)

    def decrypt(self, enctext):
        """ Decrypting an encrypted text by the use of a private key.
        
        :param enctext: The encrypted text as a string
        :return: The decrypted text
        """
        self.log and self.log.info("input len: %d" % len(enctext))
        _, fil = make_temp("%s" % enctext, decode=False)
        ntf = NamedTemporaryFile()

        com_list = [self.xmlsec, "--decrypt", 
                     "--privkey-pem", key_file, 
                     "--output", ntf.name,
                     "--id-attr:%s" % ID_ATTR, 
                     ENC_NODE_NAME, fil]

        if self.debug:
            self.log.debug("Decrypt command: %s" % " ".join(com_list))
            
        result = Popen(com_list, stderr=PIPE).communicate()
        
        if self.debug:
            self.log.debug("Decrypt result: %s" % (result,))

        ntf.seek(0)
        return ntf.read()

    
        
    def verify_signature(self, enctext, cert_file=None, cert_type="pem", 
                            node_name=NODE_NAME):
        """ Verifies the signature of a XML document.
        
        :param enctext: The XML document as a string
        :param der_file: The public key that was used to sign the document
        :return: Boolean True if the signature was correct otherwise False.
        """
        if not cert_file:
            cert_file = self.cert_file
            cert_type = self.cert_type
            
        return verify_signature(enctext, self.xmlsec, cert_file, cert_type,
                                node_name, True)
        
    def correctly_signed_authn_request(self, decoded_xml, must=False):
        """ Check if a request is correctly signed, if we have metadata for
        the SP that sent the info use that, if not use the key that are in 
        the message if any.
        
        :param decode_xml: The SAML message as a XML string
        :param must: Whether there must be a signature
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

        if self.metadata:
            certs = self.metadata.certs(issuer)
        else:
            certs = []
            
        if not certs:
            certs = [make_temp("%s" % cert, ".der") \
                        for cert in cert_from_instance(request)]
        if not certs:
            raise SignatureError("Missing signing certificate")

        verified = False
        for _, der_file in certs:
            if verify_signature(self.xmlsec, decoded_xml, der_file):
                verified = True
                break
                    
        if not verified:
            raise SignatureError("Failed to verify signature")

        return request

    def correctly_signed_response(self, decoded_xml, must=False):
        """ Check if a instance is correctly signed, if we have metadata for
        the IdP that sent the info use that, if not use the key that are in 
        the message if any.
        
        :param decode_xml: The SAML message as a XML string
        :param must: Whether there must be a signature
        :return: None if the signature can not be verified otherwise an instance
        """
        
        response = samlp.response_from_string(decoded_xml)

        # Try to find the signing cert in the assertion
        for assertion in response.assertion:
            if not assertion.signature:
                if self.debug:
                    self.log.debug("unsigned")
                if must:
                    raise SignatureError("Signature missing")
                continue
            else:
                if self.debug:
                    self.log.debug("signed")
            
            issuer = assertion.issuer.text.strip()

            if self.debug:
                self.log.debug("issuer: %s" % issuer)

            if self.metadata:
                certs = self.metadata.certs(issuer)
            else:
                certs = []

            if self.debug:
                self.log.debug("metadata certs: %s" % certs)

            if not certs:
                certs = [make_temp("%s" % cert, ".der") \
                            for cert in cert_from_instance(assertion)]
            if not certs:
                raise SignatureError("Missing certificate")

            verified = False
            for _, der_file in certs:
                if self.verify_signature(decoded_xml, der_file, "der"):
                    verified = True
                    break
                        
            if not verified:
                raise SignatureError("Could not verify")

        return response

    #----------------------------------------------------------------------------
    # SIGNATURE PART
    #----------------------------------------------------------------------------
            
    def sign_statement_using_xmlsec(self, statement, class_name, key=None, 
                                    key_file=None):
        """Sign a SAML statement using xmlsec.
        
        :param statement: The statement to be signed
        :param key: The key to be used for the signing, either this or
        :param key_File: The file where the key can be found
        :return: The signed statement
        """
        
        if not key and not key_file:
            key_file = self.key_file
            
        _, fil = make_temp("%s" % statement, decode=False)

        if key:
            _, key_file = make_temp("%s" % key, ".pem")
            
        ntf = NamedTemporaryFile()
        
        com_list = [self.xmlsec, "--sign", 
                    "--output", ntf.name,
                    "--privkey-pem", key_file, 
                    "--id-attr:%s" % ID_ATTR, 
                    class_name,
                    fil]

        if Popen(com_list, stdout=PIPE).communicate()[0] == "":
            ntf.seek(0)
            return ntf.read()
        else:
            raise Exception("Signing failed")

    def sign_assertion_using_xmlsec(self, statement, key=None, key_file=None):
        """Sign a SAML assertion using xmlsec.
        
        :param statement: The statement to be signed
        :param key: The key to be used for the signing, either this or
        :param key_File: The file where the key can be found
        :return: The signed statement
        """

        return self.sign_statement_using_xmlsec( statement,
                        class_name(saml.Assertion()), key=None, key_file=None)

# ===========================================================================

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

def pre_signature_part(ident):
    """
    If an assertion is to be signed the signature part has to be preset
    with which algorithms to be used, this function returns such a
    preset part.
    
    :param ident: The identifier of the assertion, so you know which assertion
        was signed
    :return: A preset signature part
    """
    
    presig = PRE_SIGNATURE
    presig["signed_info"]["reference"]["uri"] = "#%s" % ident
    return presig
