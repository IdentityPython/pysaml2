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

from saml2 import samlp, class_name, saml, make_instance
from saml2 import create_class_from_xml_string
import xmldsig as ds
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
import base64
import random
import os
import copy

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

# --------------------------------------------------------------------------

#def make_signed_instance(klass, spec, seccont, base64encode=False):
#    """ Will only return signed instance if the signature 
#    preamble is present
#    
#    :param klass: The type of class the instance should be
#    :param spec: The specification of attributes and children of the class
#    :param seccont: The security context (instance of SecurityContext)
#    :param base64encode: Whether the attribute values should be base64 encoded
#    :return: A signed (or possibly unsigned) instance of the class
#    """
#    if "signature" in spec:
#        signed_xml = seccont.sign_statement_using_xmlsec("%s" % instance,
#                                    class_name(instance), instance.id)
#        return create_class_from_xml_string(instance.__class__, signed_xml)
#    else:
#        return make_instance(klass, spec, base64encode)

def _make_vals(val, klass, seccont, klass_inst=None, prop=None, part=False,
                base64encode=False, elements_to_sign=None):
    """
    Creates a class instance with a specified value, the specified
    class instance may be a value on a property in a defined class instance.
    
    :param val: The value
    :param klass: The value class
    :param klass_inst: The class instance which has a property on which 
        what this function returns is a value.
    :param prop: The property which the value should be assigned to.
    :param part: If the value is one of a possible list of values it should be
        handled slightly different compared to if it isn't.
    :return: Value class instance
    """
    cinst = None

    #print "make_vals(%s, %s)" % (val, klass)
    
    if isinstance(val, dict):
        cinst = _instance(klass, val, seccont,base64encode=base64encode,
                            elements_to_sign=elements_to_sign)
    else:
        try:
            cinst = klass().set_text(val)
        except ValueError, excp:
            if not part:
                cis = [_make_vals(sval, klass, seccont, klass_inst, prop, 
                        True, base64encode, elements_to_sign) for sval in val]
                setattr(klass_inst, prop, cis)
            else:
                raise
            
    if part:
        return cinst
    else:        
        if cinst:            
            cis = [cinst]
            setattr(klass_inst, prop, cis)
    
def _instance(klass, ava, seccont, base64encode=False, elements_to_sign=None):
    instance = klass()
    
    for prop in instance.c_attributes.values():
    #print "# %s" % (prop)
        if prop in ava:
            if isinstance(ava[prop], bool):
                setattr(instance, prop, "%s" % ava[prop])
            elif isinstance(ava[prop], int):
                setattr(instance, prop, "%d" % ava[prop])
            else:
                setattr(instance, prop, ava[prop])

    if "text" in ava:
        instance.set_text(ava["text"], base64encode)
        
    for prop, klassdef in instance.c_children.values():
        #print "## %s, %s" % (prop, klassdef)
        if prop in ava:
            #print "### %s" % ava[prop]
            if isinstance(klassdef, list): # means there can be a list of values
                _make_vals(ava[prop], klassdef[0], seccont, instance, prop,
                            base64encode=base64encode, 
                            elements_to_sign=elements_to_sign)
            else:
                cis = _make_vals(ava[prop], klassdef, seccont, instance, prop,
                                True, base64encode, elements_to_sign)
                setattr(instance, prop, cis)

    if "extension_elements" in ava:
        for item in ava["extension_elements"]:
            instance.extension_elements.append(
                                    ExtensionElement(item["tag"]).loadd(item))
        
    if "extension_attributes" in ava:
        for key, val in ava["extension_attributes"].items():
            instance.extension_attributes[key] = val
        
    
    if "signature" in ava:
        elements_to_sign.append((class_name(instance), instance.id)) 
    
    return instance

def signed_instance_factory(klass, ava, seccont, base64encode=False):
    elements_to_sign = []
    instance = _instance(klass, ava, seccont, base64encode=False, 
                        elements_to_sign=elements_to_sign)
    
    if elements_to_sign:
        signed_xml = "%s" % instance
        for (node_name, nodeid) in elements_to_sign:
            signed_xml = seccont.sign_statement_using_xmlsec(signed_xml,
                                    class_name=node_name, nodeid=nodeid) 

        #print "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        #print "%s" % signed_xml
        #print "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        return create_class_from_xml_string(instance.__class__, signed_xml)
    else:
        return instance

# --------------------------------------------------------------------------

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
        must, in some cases, be decoded before being placed in the file.
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

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]
        
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
            cert = "\n".join(split_len("".join([
                                        s.strip() for s in cert.split()]),64))
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

def pem_format(key):
    return "\n".join(["-----BEGIN CERTIFICATE-----",
        key,"-----END CERTIFICATE-----"])
        
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

__DEBUG = 1

def verify_signature(enctext, xmlsec_binary, cert_file=None, cert_type="pem",
                        node_name=NODE_NAME, debug=False, node_id=None):
    """ Verifies the signature of a XML document.
    
    :param xmlsec_binary: The xmlsec1 binaries to be used
    :param input: The XML document as a string
    :param der_file: The public key that was used to sign the document
    :return: Boolean True if the signature was correct otherwise False.
    """
        
    _, fil = make_temp(enctext, decode=False)
    
    com_list = [xmlsec_binary, "--verify",
                "--pubkey-cert-%s" % cert_type, cert_file, 
                "--id-attr:%s" % ID_ATTR, node_name]
                
    if debug:
        com_list.append("--store-signatures")
        
    if node_id:
        com_list.extend(["--node-id",node_id])
        
    com_list.append(fil)

    if __DEBUG: 
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

    if __DEBUG:
        print output
        print os.stat(cert_file)
        print "Verify result: '%s'" % (verified,)
        #fil_p.seek(0)
        #print fil_p.read()

    return verified

# ---------------------------------------------------------------------------

def read_cert_from_file(cert_file, cert_type):
    if not cert_file:
        return ""
    
    if cert_type == "pem":
        line = open(cert_file).read().split("\n")
        if line[0] == "-----BEGIN CERTIFICATE-----":
            line = line[1:]
        else:
            raise Exception("Strange beginning of PEM file")
        while line[-1] == "":
            line = line[:-1]
        if line[-1] == "-----END CERTIFICATE-----":
            line = line[:-1]
        else:
            raise Exception("Strange end of PEM file")
        return "".join(line)
    if cert_type in ["der", "cer", "crt"]:
        data = open(cert_file).read()
        return base64.b64encode(data)

def security_context(conf, log=None):
    if not conf:
        return None
        
    try:
        debug = conf["debug"]
    except KeyError:
        debug = 0
        
    try:
        metadata = conf["metadata"]
    except KeyError:
        metadata = None
        
    return SecurityContext(conf.xmlsec(), conf["key_file"], "pem",
                            conf["cert_file"], "pem", metadata,
                            log=log, debug=debug)

class SecurityContext(object):
    def __init__(self, xmlsec_binary, key_file="", key_type= "pem", 
                    cert_file="", cert_type="pem", metadata=None, log=None, 
                    debug=False):
        self.xmlsec = xmlsec_binary
        
        # Your private key
        self.key_file = key_file
        
        # Your certificate
        self.cert_file = cert_file
        self.cert_type = cert_type
        self.my_cert = read_cert_from_file(cert_file, cert_type)
        
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
                            node_name=NODE_NAME, node_id=None):
        """ Verifies the signature of a XML document.
        
        :param enctext: The XML document as a string
        :param cert_file: The public key that was used to sign the document
        :param cert_type: The file type of the certificate
        :param node_name: The name of the class that is signed
        :return: Boolean True if the signature was correct otherwise False.
        """
        # This is only for testing purposes, otherwise when would you receive
        # stuff that is signed with your key !?
        if not cert_file:
            cert_file = self.cert_file
            cert_type = self.cert_type
            
        return verify_signature(enctext, self.xmlsec, cert_file, cert_type,
                                node_name, self.debug, node_id)
        
    def _check_signature(self, decoded_xml, item, node_name=NODE_NAME):
        #print item
        try:
            issuer = item.issuer.text.strip()
        except AttributeError:
            issuer = None

        if self.metadata:
            certs = self.metadata.certs(issuer)
        else:
            certs = []
            
        if not certs:
            #print "==== Certs from instance ===="
            certs = [make_temp(pem_format(cert), ".pem", False) \
                        for cert in cert_from_instance(item)]
        #else:
            #print "==== Certs from metadata ==== %s: %s ====" % (issuer,certs)
            
        if not certs:
            raise SignatureError("Missing signing certificate")

        print certs
        
        verified = False
        for _, pem_file in certs:
            #print "========================================================="
            #print open(pem_file).read()
            #print "========================================================="
            if self.verify_signature(decoded_xml, pem_file, "pem", node_name,
                                    item.id):
                verified = True
                break
                    
        if not verified:
            raise SignatureError("Failed to verify signature")

        return item
    
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

        return self._check_signature( decoded_xml, request )

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

            self._check_signature( decoded_xml, assertion )

        return response

    #----------------------------------------------------------------------------
    # SIGNATURE PART
    #----------------------------------------------------------------------------
            
    def sign_statement_using_xmlsec(self, statement, class_name, key=None, 
                                    key_file=None, nodeid=None):
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
                    "--id-attr:%s" % ID_ATTR, class_name,
                    #"--store-signatures"
                    ]
        if nodeid:
            com_list.extend(["--node-id",nodeid])

        com_list.append(fil)

        
        out = Popen(com_list, stdout=PIPE).communicate()[0]
        # this doesn't work if --store-signatures are used
        if out == "":
            #print " ".join(com_list)
            #print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            #print out
            #print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            ntf.seek(0)
            return ntf.read()
        else:
            print out
            raise Exception("Signing failed")

    def sign_assertion_using_xmlsec(self, statement, key=None, key_file=None,
                                    nodeid=None):
        """Sign a SAML assertion using xmlsec.
        
        :param statement: The statement to be signed
        :param key: The key to be used for the signing, either this or
        :param key_File: The file where the key can be found
        :return: The signed statement
        """

        return self.sign_statement_using_xmlsec( statement,
                                                class_name(saml.Assertion()),
                                                key, key_file, nodeid)

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
            "uri": None, 
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

def pre_signature_part(ident, public_key=None, id=None):
    """
    If an assertion is to be signed the signature part has to be preset
    with which algorithms to be used, this function returns such a
    preset part.
    
    :param ident: The identifier of the assertion, so you know which assertion
        was signed
    :param public_key: The base64 part of a PEM file
    :return: A preset signature part
    """
    
    presig = copy.deepcopy(PRE_SIGNATURE)
    presig["signed_info"]["reference"]["uri"] = "#%s" % ident
    if id:
        presig["id"] = "Signature%d" % id
    if public_key:
        presig["key_info"] = {
            "x509_data": {
                "x509_certificate": public_key,
            }
        }    
        
    return presig
