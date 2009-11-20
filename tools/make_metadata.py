#!/usr/bin/env python
import os 
from saml2 import utils, md, samlp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2.time_util import in_a_while
from saml2.utils import parse_attribute_map
from saml2.saml import NAME_FORMAT_URI

def do_sp_sso_descriptor(sp, cert, backward_map):
    desc = {
        "protocol_support_enumeration": samlp.NAMESPACE,
        "want_assertions_signed": True,
        "authn_requests_signed": False,
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
        
    requested_attribute = []
    if "required_attributes" in sp:
        for attr in sp["required_attributes"]:
            requested_attribute.append({
                "is_required": "true",
                "friendly_name": attr,
                "name_format": NAME_FORMAT_URI,
                "name": backward_map[attr]
            })
        
    if "optional_attributes" in sp:
        for attr in sp["optional_attributes"]:
            requested_attribute.append({
                "friendly_name": attr,
                "name_format": NAME_FORMAT_URI,
                "name": backward_map[attr]
            })
    
    if requested_attribute:
        desc["attribute_consuming_service"] = {
            "requested_attribute": requested_attribute,
            "service_name": {
                "lang":"en",
                "text":sp["name"],
            }
        }
        
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

def entity_descriptor(confd):
    mycert = "".join(open(confd["cert_file"]).readlines()[1:-1])
    
    backward_map = {}
    if "attribute_maps" in confd:
        (forward,backward) = parse_attribute_map(confd["attribute_maps"])
            
    ed = {
        "name": "http://%s/saml/test" % os.uname()[1],
        "valid_until": in_a_while(hours=96),
        "entity_id": confd["entityid"],
    }

    if "organization" in confd:
        org = {}
        for prop in ["name","display_name","url"]:
            if prop in confd["organization"]:
                org["organization_%s" % prop] = confd["organization"][prop]
        ed["organization"] = org

    if "contact" in confd:
        contacts = []
        for dic in confd["contact"]:
            cont = {}
            for prop in ["given_name","sur_name","email_address",
                        "contact_type","company","telephone_number"]:
                if prop in dic:
                    cont[prop] = dic[prop]
            contacts.append(cont)
        ed["contact_person"] = contacts
        
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

def entities_descriptor(eds):
    return utils.make_instance(md.EntitiesDescriptor,{
        "name": "urn:mace:umu.se:saml:test",
        "valid_until": in_a_while(hours=96),
        "entity_descriptor": eds})

if __name__ == "__main__":
    import sys
    eds = []
    for conf in sys.argv[1:]:
        confd = eval(open(conf).read())
        eds.append(entity_descriptor(confd))
    print entities_descriptor(eds)