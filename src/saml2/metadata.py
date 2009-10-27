#!/iusr/bin/env python

from tempfile import NamedTemporaryFile
from saml2 import md
from saml2 import samlp, BINDING_HTTP_REDIRECT, BINDING_SOAP
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
    
class MetaData(object):
    """ A class to manage metadata information """
    
    def __init__(self):
        self._loc_key = {}
        self._loc_bind = {}
        self.idp = {}
        self.aad = {}
        
    def _idp_metadata(self, entity_descriptor):

        try:
            isd = entity_descriptor.idp_sso_descriptor
        except AttributeError:
            return
        
        idps = []
        for tidp in isd:
            if samlp.NAMESPACE not in \
                    tidp.protocol_support_enumeration.split(" "):
                #print "<<<", idp.protocol_support_enumeration
                continue
            
            idps.append(tidp)
            certs = []
            for key_desc in tidp.key_descriptor:
                certs.extend(cert_from_key_info(key_desc.key_info))
            
            certs = [make_temp(c, suffix=".der") for c in certs]
            for sso in tidp.single_sign_on_service:
                self._loc_key[sso.location] = certs
                
        if idps != []:            
            self.idp[entity_descriptor.entity_id] = idps
    
    def _aad_metadata(self,entity_descriptor):
        #print entity_descriptor.__dict__.keys()
        try:
            attr_auth_descr = entity_descriptor.attribute_authority_descriptor
        except AttributeError:
            #print "No Attribute AD: %s" % entity_descriptor.entity_id
            return
            
        aads = []
        for taad in attr_auth_descr:
            # Remove everyone that doesn't talk SAML 2.0
            #print "supported protocols", taad.protocol_support_enumeration
            if samlp.NAMESPACE not in \
                    taad.protocol_support_enumeration.split(" "):
                continue
            
            # remove the bindings I can't handle
            aserv = []
            for attr_serv in taad.attribute_service:
                #print "binding", attr_serv.binding
                if attr_serv.binding == BINDING_SOAP:
                    aserv.append(attr_serv)
                    
            if aserv == []:
                continue
                
            taad.attribute_service = aserv
            
            # gather all the certs and place them in temporary files
            certs = []
            for key_desc in taad.key_descriptor:
                certs.extend(cert_from_key_info(key_desc.key_info))
            
            certs = [make_temp(c, suffix=".der") for c in certs]
            for sso in taad.attribute_service:
                try:
                    self._loc_key[sso.location].append(certs)
                except KeyError:
                    self._loc_key[sso.location] = certs
        
            aads.append(taad)

        if aads != []:            
            self.aad[entity_descriptor.entity_id] = aads
            
    def import_metadata(self, xml_str):
        """ Import information; organization distinguish name, location and
        certificates from a metadata file.
    
        :param xml_str: The metadata as a XML string.
        :return: Dictionary with location as keys and 2-tuples of organization
            distinguised names and certs as values.
        """

        entities_descriptor = md.entities_descriptor_from_string(xml_str)
        for entity_descriptor in entities_descriptor.entity_descriptor:
            self._idp_metadata(entity_descriptor)
            self._aad_metadata(entity_descriptor)

                    
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
            idps = self.idp[entity_id]
        except KeyError:
            return []
        loc = []
        for idp in idps:
            for sso in idp.single_sign_on_service:
                if binding == sso.binding:
                    loc.append(sso.location)
        return loc
        
    def attribute_services(self, entity_id):
        try:
            return self.aad[entity_id]
        except KeyError:
            return []
            
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
    
def make_contact_person(spec):
    return make_xyz(md.ContactPerson, spec)

def _make_vals(xyz_inst, val, prop, klass, part=False):
    ci = None
    #print "_make_val: %s %s (%s)" % (prop,val,klass)
    if isinstance(val, bool):
        ci = klass(text="%s" % val)
    elif isinstance(val, int):
        ci = klass(text="%d" % val)
    elif isinstance(val, basestring):
        ci = klass(text=val)
    elif isinstance(val, dict):
        ci = make_xyz(klass, val)
    elif not part:
        cis = [_make_vals(xyz_inst, sval, prop, klass, True) for sval in val]
        setattr(xyz_inst, prop, cis)
    else:
        raise ValueError()
        
    if part:
        return ci
    else:        
        if ci:
            cis = [ci]
        setattr(xyz_inst, prop, cis)
    
def make_xyz(xyz, spec):
    #print "Make", xyz
    #print "Spec", spec
    xyz_inst = xyz()
    for prop in xyz.c_attributes.values():
        if prop in spec:
            if isinstance(spec[prop],bool):
                setattr(xyz_inst,prop,"%s" % spec[prop])
            elif isinstance(spec[prop], int):
                setattr(xyz_inst,prop,"%d" % spec[prop])
            else:
                setattr(xyz_inst,prop,spec[prop])
    if "text" in spec:
        setattr(xyz_inst,"text",spec["text"])
        
    for prop, klass in xyz.c_children.values():
        #print "Prop",prop
        #print "Class",klass
        if prop in spec:
            if isinstance(klass, list): # means there can be a list of values
                #print "Possible list of values"
                _make_vals(xyz_inst, spec[prop], prop, klass[0])
            else:
                #print "Single value"
                ci = _make_vals(xyz_inst, spec[prop], prop, klass, True)
                setattr(xyz_inst, prop, ci)
    return xyz_inst
    
def make_spsso_descriptor(spec):
    spsso = md.SPSSODescriptor(
            protocolSupportEnumeration = samlp.NAMESPACE,
            want_assertions_signed = True,
            authn_requests_signed = False
            )

    if "key" in spec:
        arr=[]
        for key in spec["key"]:
            x509_certificate = ds.X509Certificate()
            if key["filetype"] == "pem":
                x509_certificate.text = "".join(
                                        open(key["file"]).readlines()[1:-1])
            elif key["filetype"] == "der": 
                x509_certificate.text = open(key["file"]).read()
            x509_data = ds.X509Data(
                x509_certificate=x509_certificate)
            key_info = ds.KeyInfo(x509_data=x509_data)
            if "key_name" in key:
                key_info.key_name = ds.KeyName(key_name=key["key_name"])
            key_desc = md.KeyDescriptor(key_info=key_info)
            if "use" in key:
                key_desc.use = key["use"]
            arr.append(key_desc)
        spsso.key_descriptor = arr

    if "name_id_format" in spec:
        arr = []
        for nif in spec["name_id_format"]:
            format = md.NameIDFormat()
            format.text = nif
            arr.append(format)
        spsso.name_id_format = arr
        
    if "assertion_consumer_service" in spec:
        arr = []
        for acs in spec["assertion_consumer_service"]:
            service = md.AssertionConsumerService()
            service.binding = acs["binding"]
            service.location = acs["location"]
            service.index = acs["index"]
            arr.append(service)
        spsso.assertion_consumer_service = arr
        
    if "contact":
        pass
        
    return spsso
    
def make_entity_description(spec):
    """
    :param spec: dictionary with necessary information
    :return md.EntityDescriptor instans
    """
    
    ed = md.EntityDescriptor(
        entity_id = spec["entity_id"],
        )

    if "organisation" in spec:
        ed.organization = md.Organization(
            organization_name = [md.Organization(
                                    text=spec["organisation"]["name"])],
            organization_url = [md.OrganizationURL(
                                    text=spec["organisation"]["url"])])
        
    if "spsso" in spec:
        ed.sp_sso_descriptor = [
                            make_spsso_descriptor(sp) for sp in spec["spsso"]]
    
    return ed
