""" functions connected to signing and verifying """

from saml2 import samlp
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
import base64

XMLSEC_BINARY = "/usr/local/bin/xmlsec1"
ID_ATTR = "ID"
NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"

_TEST_ = True

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

def _parse_popen_output(output):
    for line in output.split("\n"):
        if line == "OK":
            return True
        elif line == "FALSE":
            return False
    return False
        
def correctly_signed_response(decoded_xml):
    response = samlp.response_from_string(decoded_xml)
    verified = False

        # Try to find the signing cert in the assertion
    for assertion in response.assertion:
        cert = cert_from_assertion(assertion)
        if not cert:
            continue
        #print cert
        #print assertion
        der_file_pointer, der_file = make_temp("%s" % cert[0], ".der")
        #signed_file = open("signed.file","w")
        #signed_file.write(decoded_xml)
        #signed_file.seek(0)
        fil_p, fil = make_temp("%s" % decoded_xml, decode=False)
        com_list = [XMLSEC_BINARY, "--verify", 
                    "--pubkey-cert-der", der_file, "--id-attr:%s" % ID_ATTR, 
                    NODE_NAME, fil]

        if _TEST_: 
            print " ".join(com_list)
        verified = _parse_popen_output(Popen(com_list, stderr=PIPE).communicate()[1])
        if _TEST_:
            print "Verify result: '%s'" % (verified,)

        der_file_pointer.close()
        fil_p.close()
        if verified:
            break

    if verified:
        return response
    else:
        return None
        
def sign_using_xmlsec(statement, sign_key):
    """xmlsec1 --sign --privkey-pem test.key --id-attr:ID 
        urn:oasis:names:tc:SAML:2.0:assertion:Assertion saml_response.xml"""
        
    fil_p, fil = make_temp("%s" % statement, decode=False)
    pem_file_pointer, pem_file = make_temp("%s" % sign_key, ".pem")
    
    com_list = [XMLSEC_BINARY, "--sign", 
                "--privkey-cert-pem", pem_file, "--id-attr:%s" % ID_ATTR, 
                "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
                fil]

    #print " ".join(com_list)

    return _parse_popen_output(Popen(com_list, stdout=PIPE).communicate()[0])
        