import os
import sys

from subprocess import Popen
from subprocess import PIPE

from tempfile import NamedTemporaryFile

from saml2 import saml
from saml2 import class_name

from saml2.sigver import make_temp
from saml2.sigver import parse_xmlsec_output
from saml2.sigver import XmlsecError

__author__ = 'rohe0002'

import xmldsig as ds
import xmlenc as enc

#<EncryptedData
#  xmlns="http://www.w3.org/2001/04/xmlenc#"
#  Type="http://www.w3.org/2001/04/xmlenc#Element">
#  <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
#  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
#    <EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">
#      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
#      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
#        <KeyName/>
#      </KeyInfo>
#      <CipherData>
#        <CipherValue/>
#      </CipherData>
#    </EncryptedKey>
#  </KeyInfo>
#  <CipherData>
#    <CipherValue/>
#  </CipherData>
#</EncryptedData>

class DecryptionError(Exception):
    pass

ID_ATTR = "ID"
#NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
ENC_DATA = "urn:oasis:names:tc:SAML:2.0:assertion:EncryptedData"
ENC_KEY_CLASS = "EncryptedKey"

RSA_15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
AES128_CBC="http://www.w3.org/2001/04/xmlenc#aes128-cbc"

def pre_encrypted_id(ident, public_key=None):
    """
    If an assertion is to be signed the signature part has to be preset
    with which algorithms to be used, this function returns such a
    preset part.

    :param ident: The identifier of the assertion, so you know which assertion
        was signed
    :param public_key: The base64 part of a PEM file
    :return: A preset signature part
    """

    e_key_info = ds.KeyInfo(key_name=ds.KeyName())
    cipher_data = enc.CipherData(cipher_value=enc.CipherValue())
    encryption_method = enc.EncryptionMethod(algorithm=RSA_OAEP)
    encrypted_key = enc.EncryptedKey(key_info=e_key_info,
                                     cipher_data=cipher_data,
                                     encryption_method=encryption_method)
    key_info = ds.KeyInfo(encrypted_key=encrypted_key)
    encryption_method_ae = enc.EncryptionMethod(algorithm=AES128_CBC)
    encrypted_data = enc.EncryptedData(
                            type = "http://www.w3.org/2001/04/xmlenc#Element",
                            encryption_method=encryption_method_ae,
                            key_info=key_info)

    encrypted_id = saml.EncryptedID(encrypted_data=encrypted_data)
    encrypted_data.id = "ENC%s" % ident

    if public_key:
        x509_data = ds.X509Data(x509_certificate=[ds.X509DataType_X509Certificate(
            text=public_key)])
        e_key_info.x509_data=x509_data

    return encrypted_id

# xmlsec decrypt --privkey-pem userkey.pem doc-encrypted.xml

def decrypt_message(enctext, xmlsec_binary, node_name, cert_file=None,
                    cert_type="pem", debug=False, node_id=None,
                    log=None, id_attr=""):
    """ Verifies the signature of a XML document.

    :param enctext: XML document containing an encrypted part
    :param xmlsec_binary: The xmlsec1 binaries to be used
    :param node_name: The SAML class of the root node in the message
    :param cert_file: The key used to decrypt the message
    :param cert_type: The cert format
    :param debug: To debug or not
    :param node_id: The identifier of the root node if any
    :param id_attr: Should normally be one of "id", "Id" or "ID"
    :return: The decrypted document if all was OK otherwise will raise an
        exception.
    """

    if not id_attr:
        id_attr = ID_ATTR

    _, fil = make_temp(enctext, decode=False)

    com_list = [xmlsec_binary, "--decrypt",
                "--privkey-cert-%s" % cert_type, cert_file,
                "--id-attr:%s" % id_attr, node_name]

#    if debug:
#        com_list.append("--store-signatures")

    if node_id:
        com_list.extend(["--node-id", node_id])

    com_list.append(fil)

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

    pof = Popen(com_list, stderr=PIPE, stdout=PIPE)
    p_out = pof.stdout.read()
    try:
        p_err = pof.stderr.read()
        if debug:
            print p_err
        verified = parse_xmlsec_output(p_err)
    except XmlsecError, exc:
        if log:
            log.error(60*"=")
            log.error(p_out)
            log.error(60*"-")
            log.error("%s" % exc)
            log.error(60*"=")
        raise DecryptionError("%s" % (exc,))

    return verified

# Whole document
#xmlsec1 encrypt --pubkey-pem ServerKeys/pubkey.pem --session-key des-192
# --xml-data ClientRequest.xml
# --output ClientEncrypted.xml EncryptionTemplate.xml

# single value
#xmlsec encrypt --pubkey-pem pub-userkey.pem
# --session-key des-192
# --xml-data doc-plain.xml
# --output doc-encrypted-xpath.xml
# --node-xpath /PayInfo/CreditCard/Number/text()
# session-key-template.xml

def encrypt_using_xmlsec(xmlsec, doc, template, xpath=None, key=None,
                               key_file=None, session_key=None, log=None):
        """encrypting a value using xmlsec.

        :param xmlsec: Path to the xmlsec1 binary
        :param xpath: Which value to encrypt, if not the whole document
            should be encrypted.
        :param doc: Form which XML document the value should be picked.
        :param key: The key to be used for the encrypting, either this or
        :param key_file: The file where the key can be found
        :param session_key: Key algorithm
        :return: The signed statement
        """

        if not key_file and key:
            _, key_file = make_temp("%s" % key, ".pem")

        _, fil = make_temp("%s" % template, decode=False)

        ntf = NamedTemporaryFile()

        com_list = [xmlsec, "--encrypt",
                    "--output", ntf.name,
                    "--pubkey-pem", key_file,
                    "--xml-data", doc
                    #"--id-attr:%s" % id_attr, klass_namn
                    #"--store-signatures"
        ]
        if xpath:
            com_list.extend(["--node-xpath", xpath])

        if session_key:
            com_list.extend(["--session-key", session_key])

        com_list.append(fil)

        pof = Popen(com_list, stderr=PIPE, stdout=PIPE)
        p_out = pof.stdout.read()
        p_err = pof.stderr.read()

        # this doesn't work if --store-signatures are used
        if p_out == "":
            ntf.seek(0)
            signed_statement = ntf.read()
            if not signed_statement:
                if log:
                    log.error(p_err)
                else:
                    print >> sys.stderr, p_err
                raise Exception("Signing failed")
            else:
                return signed_statement
        else:
            print >> sys.stderr, p_out
            print "E", p_err
            raise Exception("Signing failed")

def encrypt_id(response, xmlsec, key_file, identifier, log=None):
    if not response.assertion[0].subject.encrypted_id:
        response.assertion[0].subject.encrypted_id = pre_encrypted_id(
                                                        identifier, key_file)

    statement = encrypt_using_xmlsec(xmlsec, response,
                            xpath="/Response/Assertion/Subject/NameID/text()",
                            key_file=key_file,
                            #nodeid=identifier,
                            log=log)
    return statement
