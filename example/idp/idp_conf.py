from saml2 import BINDING_HTTP_REDIRECT
from saml2.saml import NAME_FORMAT_URI

BASE = "http://localhost:8088/"

CONFIG={
    "entityid" : "urn:mace:umu.se:saml:roland:idp",
    "description": "My IDP",
    "service": {
        "idp": {
            "name" : "Rolands IdP",
            "endpoints" : {
                "single_sign_on_service" : [BASE+"sso"],
                "single_logout_service" : [(BASE+"logout",
                                            BINDING_HTTP_REDIRECT)],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes":15},
                    "attribute_restrictions": None, # means all I have
                    "name_form": NAME_FORMAT_URI
                },
                "urn:mace:umu.se:saml:roland:sp": {
                    "lifetime": {"minutes": 5},
                }
            },
            "subject_data": "./idp.subject.db",
        }
    },
    "debug" : 1,
    "key_file" : "pki/mykey.pem",
    "cert_file" : "pki/mycert.pem",
    "metadata" : {
        "local": ["../sp/sp.xml"],
    },
    "organization": {
        "display_name": "Rolands Identiteter",
        "name": "Rolands Identiteter",
        "url": "http://www.example.com",
    },
    # This database holds the map between a subjects local identifier and
    # the identifier returned to a SP
    #"xmlsec_binary": "/usr/local/bin/xmlsec1",
    "attribute_map_dir" : "../attributemaps",
    "logger": {
        "rotating": {
            "filename": "idp.log",
            "maxBytes": 100000,
            "backupCount": 5,
            },
        "loglevel": "debug",
    }
}
