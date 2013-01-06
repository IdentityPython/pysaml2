from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT

#BASE = "http://lingon.ladok.umu.se:8088"
#BASE = "http://lingon.catalogix.se:8088"
BASE = "http://localhost:8088"

CONFIG={
    "entityid" : "%s/idp.xml" % BASE,
    "description": "My IDP",
    "service": {
        "idp": {
            "name" : "Rolands IdP",
            "endpoints" : {
                "single_sign_on_service":[(BASE+"/sso",BINDING_HTTP_REDIRECT),
                                          (BASE+"/post_sso", BINDING_HTTP_POST)],
                "single_logout_service":[(BASE+"/logout",
                                          BINDING_HTTP_REDIRECT),
                                         (BASE+"/logout_post",
                                             BINDING_HTTP_POST),
                                         (BASE+"/logout_soap",
                                             BINDING_SOAP)],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes":15},
                    "attribute_restrictions": None, # means all I have
                    "name_form": NAME_FORMAT_URI
                },
            },
            "subject_data": "./idp.subject.db",
            "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT]
        }
    },
    "debug" : 1,
    "key_file" : "pki/mykey.pem",
    "cert_file" : "pki/mycert.pem",
    "metadata" : {
        "local": ["../sp.xml"],
    },
    "organization": {
        "display_name": "Rolands Identiteter",
        "name": "Rolands Identiteter",
        "url": "http://www.example.com",
    },
    "contact_person": [{
        "contact_type": "technical",
        "given_name": "Roland",
        "sur_name": "Hedberg",
        "email_address": "technical@example.com"
    },{
        "contact_type": "support",
        "given_name": "Support",
        "email_address": "support@example.com"
    },
    ],
    # This database holds the map between a subjects local identifier and
    # the identifier returned to a SP
    #"xmlsec_binary": "/usr/local/bin/xmlsec1",
    "attribute_map_dir" : "../attributemaps",
    "logger": {
        "rotating": {
            "filename": "idp.log",
            "maxBytes": 500000,
            "backupCount": 5,
            },
        "loglevel": "debug",
    }
}
