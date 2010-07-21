#!/usr/bin/env python
import os 
import getopt
import xmldsig as ds

from saml2 import utils, md, samlp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP, class_name, make_instance
from saml2.time_util import in_a_while
from saml2.s_utils import parse_attribute_map, factory
from saml2.saml import NAME_FORMAT_URI
from saml2.sigver import pre_signature_part, SecurityContext
from saml2.attribute_converter import from_local_name, ac_factory

HELP_MESSAGE = """
Usage: make_metadata [options] 1*configurationfile

Valid options:
hi:k:sv:x:
  -h            : Print this help message
  -i id         : The ID of the entities descriptor
  -k keyfile    : A file with a key to sign the metadata with
  -s            : sign the metadta
  -v            : How long, in days, the metadata is valid from the 
                    time of creation
  -x            : xmlsec1 binaries to be used for the signing
"""

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

DEFAULTS = {
    "want_assertions_signed": "true",
    "authn_requests_signed": "false",
    "want_authn_requests_signed": "true",
}

ORG_ATTR_TRANSL = {
    "organization_name": ("name", md.OrganizationName),
    "organization_display_name": ("display_name", md.OrganizationDisplayName),
    "organization_url": ("url", md.OrganizationURL)
}

def _localized_name(val, klass):
    try:
        (text,lang) = val
        return klass(text=text,lang=lang)
    except ValueError:
        return klass(text=val)

def do_organization_info(conf):
    """ decription of an organization in the configuration is
    a dictionary of keys and values, where the values might be tuples.
    
    "organization": {
        "name": ("AB Exempel", "se"),
        "display_name": ("AB Exempel", "se"),
        "url": "http://www.example.org"
    }
    """
    try:
        corg = conf["organization"]
        org = md.Organization()
        for dkey, (ckey, klass) in ORG_ATTR_TRANSL.items():
            if ckey not in corg:
                continue
            if isinstance(corg[ckey], basestring):
                setattr(org, dkey, [_localized_name(corg[ckey], klass)])
            elif isinstance(corg[ckey], list):
                setattr(org, dkey, [_localized_name(n, klass) for n in corg[ckey]])
            else:
                setattr(org, dkey, [_localized_name(corg[ckey], klass)])
        return org
    except KeyError:
        return None

def do_contact_person_info(conf):
    """
    """
    contact_person = md.ContactPerson
    cps = []
    try:
        for corg in conf["contact_person"]:
            cp = md.ContactPerson()
            for (key, classpec) in contact_person.c_children.values():
                try:
                    value = corg[key]
                    data = []
                    if isinstance(classpec, list):
                        # What if value is not a list ?
                        if isinstance(value, basestring):
                            data = [classpec[0](text=value)]
                        else:
                            for val in value:
                                data.append(classpec[0](text=val))
                    else:
                        data = classpec(text=value)
                    setattr(cp, key, data)
                except KeyError:
                    pass
            for (prop, classpec, req) in contact_person.c_attributes.values():
                try:
                    # should do a check for valid value
                    setattr(cp, prop, corg[prop])
                except KeyError:
                    pass
            cps.append(cp)
    except KeyError:
        pass
    return cps

def do_key_descriptor(cert):
    return md.KeyDescriptor(
        key_info=ds.KeyInfo(
            x509_data=ds.X509Data(
                x509_certificate=ds.X509Certificate(text=cert)
                )
            )
        )
   
def do_requested_attribute(attributes, acs, is_required="false"):
    lista = []
    for attr in attributes:
        attr = from_local_name(acs, attr, NAME_FORMAT_URI)
        args = {}
        for key in attr.keyswv():
            args[key] = getattr(attr,key)
        args["is_required"] = is_required
        lista.append(md.RequestedAttribute(**args))
    return lista

ENDPOINTS = {
    "sp": {
        "artifact_resolution_service": (md.ArtifactResolutionService, True),
        "single_logout_service": (md.SingleLogoutService, False),
        "manage_name_id_service": (md.ManageNameIDService, False),        
        "assertion_consumer_service": (md.AssertionConsumerService, True),
    },
    "idp":{
        "artifact_resolution_service": (md.ArtifactResolutionService, True),
        "single_logout_service": (md.SingleLogoutService, False),
        "manage_name_id_service": (md.ManageNameIDService, False),

        "single_sign_on_service": (md.SingleSignOnService, False),
        "name_id_mapping_service": (md.NameIDMappingService, False),
        
        "assertion_id_request_service": (md.AssertionIDRequestService, False),
    },
    "aa":{
        "artifact_resolution_service": (md.ArtifactResolutionService, True),
        "single_logout_service": (md.SingleLogoutService, False),
        "manage_name_id_service": (md.ManageNameIDService, False),

        "assertion_id_request_service": (md.AssertionIDRequestService, False),

        "attribute_service": (md.AttributeService, False)
    },
}

DEFAULT_BINDING = {
    "assertion_consumer_service": BINDING_HTTP_POST,
    "single_sign_on_service": BINDING_HTTP_POST,
    "single_logout_service": BINDING_HTTP_POST,
    "attribute_service": BINDING_SOAP,
    "artifact_resolution_service": BINDING_SOAP
}

def do_endpoints(conf, endpoints):
    service = {}

    for endpoint, (eclass, indexed) in endpoints.items():
        try:
            servs = []
            i = 1
            for args in conf[endpoint]:
                if isinstance(args, basestring): # Assume it's the location
                    args = {"location":args, "binding": DEFAULT_BINDING[endpoint]}
                if indexed:
                    args["index"] = "%d" % i
                servs.append(factory(eclass, **args))
                i += 1
                service[endpoint] = servs
        except KeyError:
            pass
    return service
    
def do_sp_sso_descriptor(sp, acs, cert=None):
    spsso = md.SPSSODescriptor()
    spsso.protocol_support_enumeration=samlp.NAMESPACE
    
    if sp["endpoints"]:
        for (endpoint, instlist) in do_endpoints(sp["endpoints"],
                                                ENDPOINTS["sp"]).items():
            setattr(spsso, endpoint, instlist)

    if cert:
        spsso.key_descriptor=do_key_descriptor(cert)
        
    for key in ["want_assertions_signed", "authn_requests_signed"]:
        try:
            setattr(spsso, key, "%s" % sp[key])
        except KeyError:
            setattr(spsso, key, DEFAULTS[key])
        
    requested_attributes = []
    if "required_attributes" in sp:
        requested_attributes.extend(do_requested_attribute(
                                                    sp["required_attributes"], 
                                                    acs, 
                                                    is_required="true"))
        
    if "optional_attributes" in sp:
        requested_attributes.extend(do_requested_attribute(
                                                    sp["optional_attributes"], 
                                                    acs, 
                                                    is_required="false"))
    
    if requested_attributes:
        spsso.attribute_consuming_service = [md.AttributeConsumingService(
            requested_attribute=requested_attributes,
            service_name= [md.ServiceName(lang="en",text=sp["name"])]
        )]
        try:
            spsso.attribute_consuming_service[0].service_description = [
                                md.ServiceDescription(text=sp["description"])]
        except KeyError:
            pass
        
    # if "discovery_service" in sp:        
    #     spsso.extensions= {"extension_elements":[
    #         {
    #         "tag":"DiscoveryResponse",
    #         "namespace":md.IDPDISC,
    #         "attributes": {
    #             "index":"1",
    #             "binding": md.IDPDISC,
    #             "location":sp["url"]
    #             }
    #         }
    #     ]}
        
    return spsso

def do_idp_sso_descriptor(idp, cert=None):
    idpsso = md.IDPSSODescriptor()
    idpsso.protocol_support_enumeration=samlp.NAMESPACE
    
    if idp["endpoints"]:
        for (endpoint, instlist) in do_endpoints(idp["endpoints"],
                                                ENDPOINTS["idp"]).items():
            setattr(idpsso, endpoint, instlist)

    if cert:
        idpsso.key_descriptor=do_key_descriptor(cert)
    
    for key in ["want_authn_requests_signed"]:
        try:
            setattr(idpsso, key, "%s" % idp[key])
        except KeyError:
            setattr(idpsso, key, DEFAULTS[key])

    return idpsso
    
def do_aa_descriptor(aa, cert):
    aa = md.AttributeAuthorityDescriptor()
    aa.protocol_support_enumeration=samlp.NAMESPACE

    if idp["endpoints"]:
        for (endpoint, instlist) in do_endpoints(aa["endpoints"],
                                                ENDPOINTS["aa"]).items():
            setattr(aasso, endpoint, instlist)

    if cert:
        aa.key_descriptor=do_key_descriptor(cert)
    
    return aa
    
def entity_descriptor(confd, valid_for):
    mycert = "".join(open(confd["cert_file"]).readlines()[1:-1])
    
    if "attribute_map_dir" in confd:
        attrconverters = ac_factory(confd["attribute_map_dir"])
    else:
        attrconverters = [AttributeConverter()]
        
    #if "attribute_maps" in confd:
    #    (forward,backward) = parse_attribute_map(confd["attribute_maps"])
    #else:
    #    backward = {}
        
    ed = md.EntityDescriptor(entity_id=confd["entityid"])
    
    if valid_for:
        ed.valid_until = in_a_while(hours=valid_for)

    ed.organization = do_organization_info(confd)
    ed.contact_person = do_contact_person_info(confd)
        
    if "sp" in confd["service"]:
        # The SP
        ed.sp_sso_descriptor = do_sp_sso_descriptor(confd["service"]["sp"],
                                    attrconverters, mycert)
    if "idp" in confd["service"]:
        ed.idp_sso_descriptor = do_idp_sso_descriptor(
                                            confd["service"]["idp"], mycert)
    if "aa" in confd["service"]:
        ed.attribute_authority_descriptor = do_aa_descriptor(
                                            confd["service"]["aa"], mycert)
            
    return ed

def entities_descriptor(eds, valid_for, name, id, sign, sc):
    entities = md.EntitiesDescriptor(entity_descriptor= eds)
    if valid_for:
        entities.valid_until = in_a_while(hours=valid_for)
    if name:
        entities.name = name
    if id:
        entities.id = id

    if sign:
            entities.signature = pre_signature_part(id)

    if sign:
            entities = sc.sign_statement_using_xmlsec("%s" % entities, 
                                    class_name(entities))
    return entities

    
def main(args):
    try:
        opts, args = getopt.getopt(args, "hi:k:sv:x:", 
                        ["help", "name", "id", "keyfile", "sign", 
                        "valid", "xmlsec"])
    except getopt.GetoptError, err:
        # print help information and exit:
        raise Usage(err) # will print something like "option -a not recognized"
        sys.exit(2)
        
    output = None
    verbose = False
    valid_for = 0
    name = ""
    id = ""
    sign = False
    xmlsec = ""
    keyfile = ""
    
    try:
        for o, a in opts:
            if o in ("-v", "--valid"):
                valid_for = int(a) * 24
            elif o in ("-h", "--help"):
                raise Usage(HELP_MESSAGE)
            elif o in ("-n", "--name"):
                name = a
            elif o in ("-i", "--id"):
                id = a
            elif o in ("-s", "--sign"):
                sign = True
            elif o in ("-x", "--xmlsec"):
                xmlsec = a
            elif o in ("-k", "--keyfile"):
                keyfile = a
            else:
                assert False, "unhandled option %s" % o
    except Usage, err:
        print >> sys.stderr, sys.argv[0].split("/")[-1] + ": " + str(err.msg)
        print >> sys.stderr, "\t for help use --help"
        return 2

    eds = []
    for conf in args:
        confd = eval(open(conf).read())
        eds.append(entity_descriptor(confd, valid_for))
    
    sc = SecurityContext(xmlsec, keyfile) 
    print entities_descriptor(eds, valid_for, name, id, sign, sc)
    
if __name__ == "__main__":
    import sys
    
    main(sys.argv[1:])
