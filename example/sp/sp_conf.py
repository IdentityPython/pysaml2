from saml2 import BINDING_HTTP_REDIRECT
from saml2.saml import NAME_FORMAT_URI

BASE= "http://localhost:8087/"

CONFIG = {
    "entityid" : "urn:mace:umu.se:saml:roland:sp",
    "description": "My SP",
    "service": {
        "sp":{
            "name" : "Rolands SP",
            "endpoints":{
                "assertion_consumer_service": [BASE],
                "single_logout_service" : [(BASE+"slo",
                                            BINDING_HTTP_REDIRECT)],
            },
            "required_attributes": ["surname", "givenname",
                                    "edupersonaffiliation"],
            "optional_attributes": ["title"],
            "idp": [ "urn:mace:umu.se:saml:roland:idp"],
        }
    },
    "debug" : 1,
    "key_file" : "pki/mykey.pem",
    "cert_file" : "pki/mycert.pem",
    "attribute_map_dir" : "./attributemaps",
    "metadata" : {
       "local": ["../idp/idp.xml"],
    },
    # -- below used by make_metadata --
    "organization": {
        "name": "Exempel AB",
        "display_name": [("Exempel AB","se"),("Example Co.","en")],
        "url":"http://www.example.com/roland",
    },
    "contact_person": [{
        "given_name":"John",
        "sur_name": "Smith",
        "email_address": ["john.smith@example.com"],
        "contact_type": "technical",
        },
    ],
    #"xmlsec_binary":"/usr/local/bin/xmlsec1",
    "name_form": NAME_FORMAT_URI,
    "logger": {
        "rotating": {
            "filename": "sp.log",
            "maxBytes": 100000,
            "backupCount": 5,
            },
        "loglevel": "debug",
    }
}
