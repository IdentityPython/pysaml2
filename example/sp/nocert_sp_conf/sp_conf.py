from saml2 import BINDING_HTTP_REDIRECT
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI
from saml2.sigver import get_xmlsec_binary, CertHandlerExtra
from saml2.entity_category.edugain import COC
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION
from saml2.entity_category.swamid import HEI
from saml2.entity_category.swamid import SFS_1993_1153
from saml2.entity_category.swamid import NREN
from saml2.entity_category.swamid import EU


#BASE= "http://130.239.200.146:8087"
BASE= "http://localhost:8087"
#BASE= "http://lingon.catalogix.se:8087"


class SpCertHandlerExtraClass(CertHandlerExtra):

    def use_generate_cert_func(self):
        return True

    def generate_cert(self, generate_cert_info, ca_cert_string, ca_key_string):
        print "Hello"
        return (ca_cert_string, ca_key_string)

    def use_validate_cert_func(self):
        return False

    def validate_cert(self, cert_str, ca_cert_string, ca_key_string):
        pass

CONFIG = {
    "entityid": "%s/LocalTestSPHans.xml" % BASE,
    "description": "Lokal test SP Hans",
    "entity_category": [COC, RESEARCH_AND_EDUCATION, HEI, SFS_1993_1153, NREN, EU],
    "only_use_keys_in_metadata": False,
    "cert_handler_extra_class": None,#MyCertGeneration(),
    "generate_cert_info": {
        "cn": "localhost",
        "country_code": "se",
        "state": "ac",
        "city": "Umea",
        "organization": "ITS Umea University",
        "organization_unit": "DIRG"
    },
    "tmp_key_file": "pki/tmp_mykey.pem",
    "tmp_cert_file": "pki/tmp_mycert.pem",
    "validate_certificate": True,
    "service": {
        "sp": {
            "authn_requests_signed": "true", #Will sign the request!
            "want_assertions_signed": "true", #Demands that the assertion is signed.
            "name": "LocalTestSPHans",
            "endpoints": {
                "assertion_consumer_service": [BASE],
                "single_logout_service": [(BASE + "/slo",
                                            BINDING_HTTP_REDIRECT)],
                "discovery_response": [
                    ("%s/disco" % BASE, BINDING_DISCO)
                ]
            },
            "required_attributes": ["surname", "givenname",
                                    "edupersonaffiliation"],
            "optional_attributes": ["title"],
        }
    },
    "debug": 1,
    "key_file": "pki/localhost.ca.key",
    "cert_file": "pki/localhost.ca.crt",
    "attribute_map_dir": "./attributemaps",
    "metadata": {
        "local": ["../idp2/idp_nocert.xml"]
    #    #"remote": [{"url": "http://130.239.201.5/role/idp.xml", "cert": None}],
    },
    #"metadata": {"local": ["/Users/haho0032/Develop/svn/trunk/pyOpSamlProxy/idp_nocert.xml"]},

    # -- below used by make_metadata --
    "organization": {
        "name": "Lokal test SP Hans",
        "display_name": [("Lokal test SP Hans", "se"), ("Lokal test SP Hans", "en")],
        "url": "http://130.239.200.146:8087",
    },
    "contact_person": [
    ],
    "xmlsec_binary": '/usr/local/bin/xmlsec1',
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

