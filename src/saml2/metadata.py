#!/iusr/bin/env python

from tempfile import NamedTemporaryFile
from saml2 import md
from saml2 import samlp, BINDING_HTTP_REDIRECT
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
    
class MetaData(dict):
    """ A class to manage metadata information """
    
    def __init_(self, arg=None):
        dict.__init__(self, arg)
        self._loc_key = {}
        self._loc_bind = {}
        
    def import_metadata(self, xml_str):
        """ Import information; organization distinguish name, location and
        certificates from a metadata file.
    
        :param xml_str: The metadata as a XML string.
        :return: Dictionary with location as keys and 2-tuples of organization
            distinguised names and certs as values.
        """

        self._loc_key = {}
        self._loc_bind = {}
    
        entities_descriptor = md.entities_descriptor_from_string(xml_str)
        for entity_descriptor in entities_descriptor.entity_descriptor:
            idps = []
            
            #print "--",len(entity_descriptor.idp_sso_descriptor)
            # If not SAML2.0, drop it !
            for idp in entity_descriptor.idp_sso_descriptor:
                if samlp.SAMLP_NAMESPACE not in \
                        idp.protocol_support_enumeration.split(" "):
                    #print "<<<", idp.protocol_support_enumeration
                    continue
                
                idps.append(idp)
                certs = []
                for key_desc in idp.key_descriptor:
                    certs.extend(cert_from_key_info(key_desc.key_info))
                
                certs = [make_temp(c, suffix=".der") for c in certs]
                for sso in idp.single_sign_on_service:
                    self._loc_key[sso.location] = certs
                    
            if idps == []:
                #print "IGNORE", entity_descriptor.entity_id
                continue
                
            entity_descriptor.idp_sso_descriptor = idps
                
            self[entity_descriptor.entity_id] = entity_descriptor
    
    def single_sign_on_services(self, entity_id, 
                                binding = BINDING_HTTP_REDIRECT):
        """ Get me all single-sign-on services that supports the specified
        binding version.
        
        :param entity_id: The EntityId
        :param binding: A binding identifier
        :return: list of single-sign-on service location run by the entity 
            with the specified EntityId.
        """
        try:
            desc = self[entity_id]
        except KeyError:
            return None
        loc = []
        for idp in desc.idp_sso_descriptor:
            for sso in idp.single_sign_on_service:
                if binding == sso.binding:
                    loc.append(sso.location)
        return loc
        
    def locations(self):
        """ Returns all the locations that are know using this metadata file.
        
        :return: A list of IdP locations
        """
        return self._loc_key.keys()
        
    def certs(self, loc):
        """ Get all certificates that are used by a IdP at the specified
        location. There can be more than one because of overlapping lifetimes
        of the certs.
        
        :param loc: The location of the IdP
        :return: a list of 2-tuples (file pointer,file name) that represents
            certificates used by the IdP at the location loc.
        """
        return self._loc_key[loc]
        
def cert_from_assertion(assertion):
    """ Find certificates that are part of an assertion
    
    :param assertion: A saml.Assertion instance
    :return: possible empty list of certificates
    """
    if assertion.signature:
        if assertion.signature.key_info:
            return cert_from_key_info(assertion.signature.key_info)
    return []
    
def make_entity_description():
    org = md.Organization(
            organization_name = [md.Organization(text="Example Inc.")],
            organization_url = [md.OrganizationURL(
                                    text="http://www.example.com/")])
            
    spsso = md.SPSSODescriptor(
            protocolSupportEnumeration = samlp.SAMLP_NAMESPACE,
            want_assertions_signed = False,
            authn_requests_signed = False
            )
            
    return md.EntityDescriptor(
        entity_id = "http://xenosmilus.umdc.umu.se:8087/",
        organization = org,
        sp_sso_descriptor = [spsso]
        )
    
