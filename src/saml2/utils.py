#!/opt/local/bin/python
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

"""Contains utility methods used with SAML-2."""

import saml2
try:
    import libxml2 as libxml
except ImportError:
    import lxml as libxml
import xmlsec
import random
import time

TEST = True

# TODO: write tests for these methods

class VerifyError(Exception):
    pass
    
def create_id():
    ret = ""
    for _ in range(40):
        ret = ret + chr(random.randint(0, 15) + ord('a'))
    return ret

def get_date_and_time(base=None):
    if base is None:
        base = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base))

def lib_init():
    # Init libxml library
    libxml.initParser()
    libxml.substituteEntitiesDefault(1)

    # Init xmlsec library
    if xmlsec.init() < 0:
        raise(saml2.Error("Error: xmlsec initialization failed."))

    # Check loaded library version
    if xmlsec.checkVersion() != 1:
        raise(saml2.Error(
            "Error: loaded xmlsec library version is not compatible.\n"))

    # Init crypto library
    if xmlsec.cryptoAppInit(None) < 0:
        raise(saml2.Error("Error: crypto initialization failed."))

    # Init xmlsec-crypto library
    if xmlsec.cryptoInit() < 0:
        raise(saml2.Error("Error: xmlsec-crypto initialization failed."))    

def lib_shutdown():
    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    libxml.cleanupParser()

def verify(xml, key_file):
    lib_init()
    ret = verify_xml(xml, key_file)
    lib_shutdown()
    return ret == 0

# Verifies XML signature in xml string using public key from key_file.
# Returns 0 on success or a negative value if an error occurs.
def verify_xml(xml, key_file):

    doc = libxml.parseDoc(xml)
        
    if doc is None or doc.getRootElement() is None:
        cleanup(doc)
        raise saml2.Error("Error: unable to parse file \"%s\"" % xml)

    # Find start node
    node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature, 
                            xmlsec.DSigNs)

    # Create signature context, we don't need keys manager in this example
    dsig_ctx = xmlsec.DSigCtx()
    if dsig_ctx is None:
        cleanup(doc)
        raise saml2.Error("Error: failed to create signature context")

    # Load public key, assuming that there is no password
    if key_file.endswith(".der"):
        key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatDer,
                                        None, None, None)
    else:
        key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                        None, None, None)
    
    if key is None:
        cleanup(doc, dsig_ctx)
        raise saml2.Error(
                "Error: failed to load public key from \"%s\"" % key_file)

    dsig_ctx.signKey = key

    # Set key name to the file name, this is just an example!
    if key.setName(key_file) < 0:
        cleanup(doc, dsig_ctx)
        raise saml2.Error(
                "Error: failed to set key name for key from \"%s\"" % key_file)

    # Verify signature
    if dsig_ctx.verify(node) < 0:
        cleanup(doc, dsig_ctx)
        raise saml2.Error("Error: signature verify")

    # Print verification result to stdout
    if dsig_ctx.status == xmlsec.DSigStatusSucceeded:
        ret = 0
    else:
        ret = -1

    # Success
    cleanup(doc, dsig_ctx)
    return ret

def verify_xml_with_manager(mngr, xml):
    assert(mngr)
    assert(xml)

    doc = libxml.parseDoc(xml)
    if doc is None or doc.getRootElement() is None:
        cleanup(doc)
        raise saml2.Error("Error: unable to parse xml")


    # Find start node
    node = xmlsec.findNode(doc.getRootElement(),
                           xmlsec.NodeSignature, xmlsec.DSigNs)
    if node is None:
        raise saml2.Error("Error: start node not found in xml doc")
    elif TEST:
        print "Start node: %s" % (node,)
        
    # Create signature context
    dsig_ctx = xmlsec.DSigCtx(mngr)
    if dsig_ctx is None:
        cleanup(doc)
        raise saml2.Error("Error: failed to create signature context")

    # Verify signature
    if dsig_ctx.verify(node) < 0:
        cleanup(doc, dsig_ctx)
        raise saml2.Error( "Error: signature verify")

    # Print verification result to stdout
    if dsig_ctx.status != xmlsec.DSigStatusSucceeded:
        raise saml2.Error("Signature is INVALID")

    # Success
    return cleanup(doc, dsig_ctx, 1)

def sign(xml, key_file, cert_file=None):
    lib_init()
    ret = sign_xml(xml, key_file, cert_file)
    lib_shutdown()
    return ret

# Signs the xml_file using private key from key_file and dynamicaly
# created enveloped signature template.
# Returns 0 on success or a negative value if an error occurs.
def sign_xml(xml, key_file, cert_file=None):

    # Load template
    doc = libxml.parseDoc(xml)

    if doc is None or doc.getRootElement() is None:
        cleanup(doc)
        raise saml2.Error("Error: unable to parse string \"%s\"" % xml)

    node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature,
                                                 xmlsec.DSigNs)

    if node is None:
        cleanup(doc)
        raise saml2.Error("Error: start node not found.")

    # Create signature context, we don't need keys manager in this example
    dsig_ctx = xmlsec.DSigCtx()
    if dsig_ctx is None:
        cleanup(doc)
        raise saml2.Error("Error: failed to create signature context")

    # Load private key, assuming that there is not password
    key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                    None, None, None)
    if key is None:
        cleanup(doc, dsig_ctx)
        raise saml2.Error(
            "Error: failed to load private pem key from \"%s\"" % key_file)
    dsig_ctx.signKey = key

    if cert_file is not None:
        if xmlsec.cryptoAppKeyCertLoad(
            dsig_ctx.signKey, cert_file, xmlsec.KeyDataFormatPem) < 0:
            cleanup(doc, dsig_ctx)
            raise saml2.Error(
                "Error: failed to load cert pem from \"%s\"" % cert_file)
    else:
        pass
        
    # Set key name to the file name, this is just an example!
    if key.setName(key_file) < 0:
        cleanup(doc, dsig_ctx)
        raise saml2.Error(
            "Error: failed to set key name for key from \"%s\"" % key_file)

    # Sign the template
    if dsig_ctx.sign(node) < 0:
        cleanup(doc, dsig_ctx)
        raise saml2.Error("Error: signature failed")

    # signed document to string
    ret = doc.__str__()

    # Success
    cleanup(doc, dsig_ctx, 1)

    return ret

def cleanup(doc=None, dsig_ctx=None, res=0):
    if dsig_ctx is not None:
        dsig_ctx.destroy()
    if doc is not None:
        doc.freeDoc()
    return res
