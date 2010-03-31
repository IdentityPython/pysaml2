#!/usr/bin/env python
import os 
import getopt
from saml2 import utils, md, samlp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP, class_name, make_instance
from saml2.time_util import in_a_while
from saml2.utils import parse_attribute_map, args2dict
from saml2.saml import NAME_FORMAT_URI
from saml2.sigver import pre_signature_part, SecurityContext

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
}

ORG_ATTR_TRANSL = {
    "organization_name": "name",
    "organization_display_name": "display_name",
    "organization_url": "url",
}

PERSON_ATTR_TRANSL = {
    "company": "company",
    "given_name": "givenname",
    "sur_name": "surname",
    "email_address": "mail",
    "telephone_number": "phone",
    "type": "type",
}

def _localized_name(tup):
    if tup[1]:
        return args2dict(tup[0],lang=tup[1])
    else:
        return tup[0]

def do_organization_info(conf, desc):
    """ """
    try:
        corg = conf["organization"]                
        dorg = desc["organization"] = {}
        
        for (dkey, ckey) in ORG_ATTR_TRANSL.items():
            if ckey not in corg:
                continue
            if isinstance(corg[ckey], basestring):
                dorg[dkey] = [corg[ckey]]
            elif isinstance(corg[ckey], tuple):
                dorg[dkey] = [_localized_name(corg[ckey])]
            else:
                dorg[dkey] = []
                for val in corg[ckey]:
                    if isinstance(val,tuple):
                        dorg[dkey].append(_localized_name(val))
                    else:
                        dorg[dkey].append(val)
    except KeyError:
        pass

def do_contact_person_info(conf, desc):
    if "contact_person" in conf:
        desc["contact_person"] = []
        for corg in conf["contact_person"]:
            print corg
            dorg = {}            
            for (dkey, ckey) in PERSON_ATTR_TRANSL.items():
                try:
                    dorg[dkey] = corg[ckey]
                except:
                    pass
            desc["contact_person"].append(dorg)
        
def do_sp_sso_descriptor(sp, cert, backward_map):
    desc = {
        "protocol_support_enumeration": samlp.NAMESPACE,
        "assertion_consumer_service": {
            "binding": BINDING_HTTP_POST ,
            "location": sp["url"],
            "index": 0,
            },
        "key_descriptor":{
            "key_info": {
                "x509_data": {
                    "x509_certificate": cert
                    }
                }
            },
        }
        
    for key in ["want_assertions_signed", "authn_requests_signed"]:
        try:
            desc[key] = "%s" % sp[key]
        except KeyError:
            desc[key] = DEFAULTS[key]
        
    requested_attribute = []
    if "required_attributes" in sp:
        for attr in sp["required_attributes"]:
            try:
                requested_attribute.append({
                    "is_required": "true",
                    "friendly_name": attr,
                    "name_format": NAME_FORMAT_URI,
                    "name": backward_map[attr][0]
                })
            except KeyError:
                requested_attribute.append({
                    "is_required": "true",
                    "friendly_name": attr,
                    "name_format": NAME_FORMAT_URI,
                    "name": attr
                })
        
    if "optional_attributes" in sp:
        for attr in sp["optional_attributes"]:
            try:
                requested_attribute.append({
                    "friendly_name": attr,
                    "name_format": NAME_FORMAT_URI,
                    "name": backward_map[attr][0]
                })
            except KeyError:
                requested_attribute.append({
                    "friendly_name": attr,
                    "name_format": NAME_FORMAT_URI,
                    "name": attr
                })
    
    if requested_attribute:
        desc["attribute_consuming_service"] = {
            "requested_attribute": requested_attribute,
            "service_name": {
                "lang":"en",
                "text":sp["name"],
            }
        }
        
    if "discovery_service" in sp:        
        desc["extensions"] = {"extension_elements":[
            {
            "tag":"DiscoveryResponse",
            "namespace":md.IDPDISC,
            "attributes": {
                "index":"1",
                "binding": md.IDPDISC,
                "location":sp["url"]
                }
            }
        ]}
        
    return desc

def do_idp_sso_descriptor(idp, cert):
    return {
        "protocol_support_enumeration": samlp.NAMESPACE,
        "want_authn_requests_signed": True,
        "single_sign_on_service": {
            "binding": BINDING_HTTP_REDIRECT ,
            "location": idp["url"],
            },
        "key_descriptor":{
            "key_info": {
                "x509_data": {
                    "x509_certificate": cert
                    }
                }
            },
        }

def do_aa_descriptor(aa, cert):
    return {
        "protocol_support_enumeration": samlp.NAMESPACE,
        "attribute_service": {
            "binding": BINDING_SOAP ,
            "location": aa["url"],
            },
        "key_descriptor":{
            "key_info": {
                "x509_data": {
                    "x509_certificate": cert
                    }
                }
            },
        }

def entity_descriptor(confd, valid_for):
    mycert = "".join(open(confd["cert_file"]).readlines()[1:-1])
    
    if "attribute_maps" in confd:
        (forward,backward) = parse_attribute_map(confd["attribute_maps"])
    else:
        backward = {}
        
    ed = {
        "entity_id": confd["entityid"],
    }
    if valid_for:
        ed["valid_until"] = in_a_while(hours=valid_for)

    do_organization_info(confd, ed)
    do_contact_person_info(confd, ed)
        
    if "sp" in confd["service"]:
        # The SP
        ed["sp_sso_descriptor"] = do_sp_sso_descriptor(confd["service"]["sp"],
                                    mycert, backward)
    if "idp" in confd["service"]:
        ed["idp_sso_descriptor"] = do_idp_sso_descriptor(
                                            confd["service"]["idp"], mycert)
    if "aa" in confd["service"]:
        ed["attribute_authority_descriptor"] = do_aa_descriptor(
                                            confd["service"]["aa"], mycert)
            
    return ed

def entities_descriptor(eds, valid_for, name, id, sign, sc):
    d = {"entity_descriptor": eds}
    if valid_for:
        d["valid_until"] = in_a_while(hours=valid_for)
    if name:
        d["name"] = name
    if id:
        d["id"] = id

    if sign:
            d["signature"] = pre_signature_part(d["id"])

    statement = make_instance(md.EntitiesDescriptor, d)
    if sign:
            statement = sc.sign_statement_using_xmlsec("%s" % statement, 
                                    class_name(statement))
    return statement

    
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
