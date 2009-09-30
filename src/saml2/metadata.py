#!/iusr/bin/env python

from tempfile import NamedTemporaryFile
from saml2 import md
from saml2 import samlp
import xmlsec
import base64

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

# def check_keys(x509_certificates):
#     for cert in x509_certificates:
#         fil, key_file = make_temp(cert,suffix=".der")
#         key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatDer,
#                                            None, None, None)
#         fil.close
    
def load_certs_to_manager(x509_certificates):
    """ Creates simple keys manager and loads keys from certificates into it.
    
    :param x509_certificates: list of DER formated certificates
    :return: Manager with the keys loaded.
    """
    mngr = xmlsec.KeysMngr()
    if mngr is None:
        print "Error: failed to create keys manager."
        return None
    if xmlsec.cryptoAppDefaultKeysMngrInit(mngr) < 0:
        print "Error: failed to initialize keys manager."
        mngr.destroy()
        return None
    for cert in x509_certificates:
        fil, file_name = make_temp(cert)
        # Load trusted cert
        if mngr.certLoad(file_name, xmlsec.KeyDataFormatDer,
                         xmlsec.KeyDataTypeTrusted) < 0:
            print "Error: failed to load pem certificate from \"%s\"", file_name
            mngr.destroy()
            return None
        fil.close()
    return mngr

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
    
def import_metadata(xml_str):
    """ Import information; organization distinguish name, location and
    certificates from a metadata file.
    
    :param xml_str: The metadata as a XML string.
    :return: Dictionary with location as keys and 2-tuples of organization
        distinguised names and certs as values.
    """
    
    idps = {}
    entities_descriptor = md.entities_descriptor_from_string(xml_str)
    for entity_descriptor in entities_descriptor.entity_descriptor:
        organization = entity_descriptor.organization
        if organization:
            odn = [dn.text.strip() \
                        for dn in organization.organization_display_name]
        else:
            odn = []
        for idp in entity_descriptor.idp_sso_descriptor:
            if idp.protocol_support_enumeration != samlp.SAMLP_NAMESPACE:
                # Not interested
                continue
            location = [sso.location for sso in idp.single_sign_on_service]
            signing_keys = []
            for key in idp.key_descriptor:
                # only interested in keys that can be used for signing
                if key.use and key.use != "signing": 
                    continue
                signing_keys.extend(cert_from_key_info(key.key_info))
            for loc in location:
                idps[loc] = (odn, signing_keys)
    return idps
    
def cert_from_assertion(assertion):
    """ Find certificates that are part of an assertion
    
    :param assertion: A saml.Assertion instance
    :return: possible empty list of certificates
    """
    if assertion.signature:
        if assertion.signature.key_info:
            return cert_from_key_info(assertion.signature.key_info)
    return []
    
    