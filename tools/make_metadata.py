#!/usr/bin/env python
import os 
from saml2 import utils, md, samlp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.time_util import in_a_while


def entity_descriptor(confd):
    mycert = "".join(open(confd["cert_file"]).readlines()[1:-1])
    
    ed = {
        "name": "http://%s/saml/test" % os.uname()[1],
        "valid_until": in_a_while(days=30),
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
        ed["sp_sso_descriptor"] = {
            "protocol_support_enumeration": samlp.NAMESPACE,
            "want_assertions_signed": True,
            "authn_requests_signed": False,
            "assertion_consumer_service": {
                "binding": BINDING_HTTP_POST ,
                "location": confd["service_url"],
                "index": 0,
                },
            "key_descriptor":{
                "key_info": {
                    "x509_data": {
                        "x509_certificate": mycert
                        }
                    }
                },
            }
    elif "idp" in confd["service"]:
        ed["idp_sso_descriptor"] = {
            "protocol_support_enumeration": samlp.NAMESPACE,
            "want_authn_requests_signed": True,
            "single_sign_on_service": {
                "binding": BINDING_HTTP_REDIRECT ,
                "location": confd["service_url"],
                },
            "key_descriptor":{
                "key_info": {
                    "x509_data": {
                        "x509_certificate": mycert
                        }
                    }
                },
            }
            
    return ed

if __name__ == "__main__":
    import sys
    for conf in sys.argv[1:]:
        confd = eval(open(conf).read())
        print utils.make_instance(md.EntityDescriptor, 
                                    entity_descriptor(confd))