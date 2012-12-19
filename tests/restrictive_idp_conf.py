from saml2 import BINDING_SOAP, BINDING_HTTP_REDIRECT
from saml2.saml import NAME_FORMAT_URI

BASE = "http://localhost:8089/"

try:
    from saml2.sigver import get_xmlsec_binary
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
except ImportError:
    xmlsec_path = '/usr/bin/xmlsec1'

CONFIG = {
    "entityid" : "urn:mace:example.com:saml:roland:idpr",
    "name" : "Rolands restrictied IdP",
    "service": {
        "idp": {
            "endpoints" : {
                "single_sign_on_service" : [
                        (BASE+"sso", BINDING_HTTP_REDIRECT)],
                "attribute_service" : [
                        (BASE+"aa", BINDING_SOAP)],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes":15},
                    "name_form": NAME_FORMAT_URI
                },
                "urn:mace:example.com:saml:roland:sp": {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions":{
                        "givenName": None,
                        "surName": None,
                        "mail": [".*@example.com"],
                        "eduPersonAffiliation": ["(employee|staff|faculty)"],
                    }
                }
            },
            "subject_data": "subject_data.db",
        }
    },
    "key_file" : "test.key",
    "cert_file" : "test.pem",
    "xmlsec_binary" : xmlsec_path,
    "metadata": {
        "local": ["sp_0.metadata"],
    },
    "attribute_map_dir" : "attributemaps",
}
