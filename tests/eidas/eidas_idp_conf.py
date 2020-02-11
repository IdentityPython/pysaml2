from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAME_FORMAT_BASIC
from saml2.saml import NAME_FORMAT_URI

from pathutils import full_path
from pathutils import xmlsec_path

BASE = "http://localhost:8088"

CONFIG = {
    "entityid": "https://example.org",
    "name": "Rolands IdP",
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso" % BASE, BINDING_HTTP_REDIRECT)],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                },
                "urn:mace:example.com:saml:roland:sp": {
                    "lifetime": {"minutes": 5},
                    "nameid_format": NAMEID_FORMAT_PERSISTENT,
                },
                "https://example.com/sp": {
                    "lifetime": {"minutes": 5},
                    "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    "name_form": NAME_FORMAT_BASIC
                }
            },
            "subject_data": full_path("subject_data.db"),
            "node_country": "GR",
            "application_identifier": "CEF:eIDAS-ref:2.0",
            "protocol_version": [1.1, 2.2],
            "want_authn_requests_signed": True
        },
    },
    "debug": 1,
    "key_file": full_path("test.key"),
    "cert_file": full_path("test.pem"),
    "xmlsec_binary": xmlsec_path,
    "metadata": [{
        "class": "saml2.mdstore.MetaDataFile",
        "metadata": [(full_path("metadata_sp_1.xml"), ),
                     (full_path("metadata_sp_2.xml"), ),
                     (full_path("vo_metadata.xml"), )],
    }],
    "attribute_map_dir": full_path("attributemaps"),
    "organization": {
        "name": ("AB Exempel", "se"),
        "display_name": ("AB Exempel", "se"),
        "url": "http://www.example.org",
    },
    "contact_person": [
        {
            "given_name": "Roland",
            "sur_name": "Hedberg",
            "telephone_number": "+46 70 100 0000",
            "email_address": ["tech@eample.com",
                              "tech@example.org"],
            "contact_type": "technical"
        },
        {
            "given_name": "Roland",
            "sur_name": "Hedberg",
            "telephone_number": "+46 70 100 0000",
            "email_address": ["tech@eample.com",
                              "tech@example.org"],
            "contact_type": "support"}
    ],
}
