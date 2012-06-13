import os
import sys

from subprocess import Popen
from subprocess import PIPE

from tempfile import NamedTemporaryFile

from saml2.sigver import make_temp
from saml2.sigver import parse_xmlsec_output
from saml2.sigver import XmlsecError
from saml2 import saml

__author__ = 'rohe0002'

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
AES128_CBC="http://www.w3.org/2001/04/xmlenc#aes128-cbc"
TRIPLE_DES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"

# registered xmlsec transforms
TRANSFORMS = ["base64","enveloped-signature","c14n","c14n-with-comments",
              "c14n11","c14n11-with-comments","exc-c14n",
              "exc-c14n-with-comments","xpath","xpath2","xpointer","xslt",
              "aes128-cbc","aes192-cbc","aes256-cbc","kw-aes128","kw-aes192",
              "kw-aes256","tripledes-cbc","kw-tripledes","dsa-sha1","hmac-md5",
              "hmac-ripemd160","hmac-sha1","hmac-sha224","hmac-sha256",
              "hmac-sha384","hmac-sha512","md5","ripemd160","rsa-md5",
              "rsa-ripemd160","rsa-sha1","rsa-sha224","rsa-sha256","rsa-sha384",
              "rsa-sha512","rsa-1_5","rsa-oaep-mgf1p","sha1","sha224","sha256",
              "sha384","sha512"]

ALGORITHM = {
    "tripledes-cbc": TRIPLE_DES,
    "aes128-cbc": AES128_CBC,
    "rsa-1_5": RSA_15,
    "rsa-oaep-mgf1p": RSA_OAEP
}

def template(ident=None, session_key="tripledes-cbc"):
    """
    If an assertion is to be signed the signature part has to be preset
    with which algorithms to be used, this function returns such a
    preset part.

    :param ident: The identifier of the assertion, so you know which assertion
        was signed
    :return: A preset signature part
    """

    cipher_data = enc.CipherData(cipher_value=enc.CipherValue())
    encryption_method = enc.EncryptionMethod(algorithm=ALGORITHM[session_key])
    #key_info = ds.KeyInfo(key_name=ds.KeyName())
    encrypted_data = enc.EncryptedData(
                            type = "http://www.w3.org/2001/04/xmlenc#Element",
                            encryption_method=encryption_method,
                            #key_info=key_info,
                            cipher_data=cipher_data)

    if ident:
        encrypted_data.id = "%s" % ident

    return encrypted_data

# xmlsec decrypt --privkey-pem userkey.pem doc-encrypted.xml

def decrypt_message(enctext, xmlsec_binary, key_file=None,
                    key_file_type="privkey-pem", cafile=None,
                    epath=None, id_attr="",
                    node_name="", node_id=None, log=None, debug=False):
    """ Decrypts an encrypted part of a XML document.

    :param enctext: XML document containing an encrypted part
    :param xmlsec_binary: The xmlsec1 binaries to be used
    :param key_file: The key used to decrypt the message
    :param key_file_type: The key file type
    :param node_name: The SAML class of the root node in the message
    :param node_id: The identifier of the root node if any
    :param id_attr: Should normally be one of "id", "Id" or "ID"
    :param log: A log function to use when logging
    :param debug: To debug or not
    :return: The decrypted document if all was OK otherwise will raise an
        exception.
    """

    if not id_attr:
        id_attr = ID_ATTR

    _, fil = make_temp(enctext, decode=False)

    com_list = [xmlsec_binary, "--decrypt",
                "--%s" % key_file_type, key_file]

    if key_file_type in ["privkey-pem", "privkey-der", "pkcs8-pem",
                         "pkcs8-der"]:
        if isinstance(cafile, basestring):
            com_list.append(cafile)
        else:
            com_list.extend(cafile)

    if id_attr:
        com_list.extend(["--id-attr:%s" % id_attr, node_name])

    elif epath:
        xpath = create_xpath(epath)
        com_list.extend(['--node-xpath', xpath])

    #    if debug:
#        com_list.append("--store-signatures")

    if node_id:
        com_list.extend(["--node-id", node_id])

    com_list.append(fil)

    if debug:
        try:
            print " ".join(com_list)
        except TypeError:
            print "key_file_type", key_file_type
            print "key_file", key_file
            print "node_name", node_name
            print "fil", fil
            raise
        print "%s: %s" % (key_file, os.access(key_file, os.F_OK))
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
#/opt/local/bin/xmlsec1 encrypt --pubkey-cert-pem pubkey.pem
# --session-key des-192 --xml-data pre_saml2_response.xml
# --node-xpath '/*[local-name()="Response"]/*[local-name()="Assertion"]/*[local-name()="Subject"]/*[local-name()="EncryptedID"]/text()'
# encryption_template.xml > enc.out

def create_xpath(path):
    """
    :param path: list of element names
    """

    return "/*".join(['[local-name()="%s"]' % e for e in path]) + "/text()"

def encrypt_using_xmlsec(xmlsec, data, template, epath=None, key=None,
                               key_file=None, key_file_type="pubkey-pem",
                               session_key=None, log=None):
        """encrypting a value using xmlsec.

        :param xmlsec: Path to the xmlsec1 binary
        :param data: A XML document from which the value should be picked.
        :param template: The encyption part template
        :param epath: Which value to encrypt, if not the whole document
            should be encrypted.
        :param key: The key to be used for the encrypting, either this or
        :param key_file: The file where the key can be found
        :param key_file_type: pubkey-pem, pubkey-der, pubkey-cert-pem,
            pubkey-cert-der, privkey-der, privkey-pem, ...
        :param session_key: Key algorithm
        :param log: log function
        :return: The signed statement
        """

        if not key_file and key:
            _, key_file = make_temp("%s" % key, ".pem")

        ntf = NamedTemporaryFile()
        xpath = create_xpath(epath)

        com_list = [xmlsec, "encrypt",
                    "--output", ntf.name,
                    "--xml-data", data,
                    '--node-xpath', xpath,
                    key_file_type, key_file
        ]

        if session_key:
            com_list.extend(["--session-key", session_key])

        _, fil = make_temp("%s" % template, decode=False)
        com_list.append(fil)

        pof = Popen(com_list, stderr=PIPE, stdout=PIPE)
        p_out = pof.stdout.read()
        p_err = pof.stderr.read()

        # this doesn't work if --store-signatures are used
        if p_out == "":
            ntf.seek(0)
            encrypted_statement = ntf.read()
            if not encrypted_statement:
                if log:
                    log.error(p_err)
                else:
                    print >> sys.stderr, p_err
                raise Exception("Encryption failed")
            else:
                return encrypted_statement
        else:
            print >> sys.stderr, p_out
            print "E", p_err
            raise Exception("Encryption failed")

def encrypt_id(response, xmlsec, key_file, key_file_type, identifier,
               session_key, node_id="", log=None):
    """
    :param response: The response as a Response class instance
    :param xmlsec: Where the xmlsec1 binaries reside
    :param key_file: Which key file to use
    :param key_file_type: The type of key file
    :param identifier: The subject identifier
    :param session_key: The type of key used to encrypt
    :return: statement with the subject identifier encrypted
    """
    if not response.assertion[0].subject.encrypted_id:
        response.assertion[0].subject.encrypted_id = saml.EncryptedID(
                                                                    identifier)

    statement = encrypt_using_xmlsec(xmlsec, "%s" % response,
                            template=template(ident=node_id,
                                              session_key=session_key),
                            epath=["Response","Assertion","Subject","NameID"],
                            key_file=key_file,
                            key_file_type=key_file_type,
                            session_key=session_key,
                            log=log)

    return statement
