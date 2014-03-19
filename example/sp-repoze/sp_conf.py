import uuid
from saml2 import BINDING_HTTP_REDIRECT
import saml2
from saml2.cert import OpenSSLWrapper
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI
#from saml2.sigver import CertHandlerExtra
from saml2.entity_category.edugain import COC
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION
from saml2.entity_category.swamid import HEI
from saml2.entity_category.swamid import SFS_1993_1153
from saml2.entity_category.swamid import NREN
from saml2.entity_category.swamid import EU


#BASE= "http://130.239.200.146:8087"
BASE= "http://localhost:8087"
#BASE= "http://lingon.catalogix.se:8087"

"""
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
"""

def generate_cert():
    sn = uuid.uuid4().urn
    cert_info = {
        "cn": "localhost",
        "country_code": "se",
        "state": "ac",
        "city": "Umea",
        "organization": "ITS",
        "organization_unit": "DIRG"
    }
    osw = OpenSSLWrapper()
    ca_cert_str = osw.read_str_from_file("/Users/haho0032/Develop/root_cert/localhost.ca.crt")
    ca_key_str = osw.read_str_from_file("/Users/haho0032/Develop/root_cert/localhost.ca.key")
    #ca_cert_str = osw.read_str_from_file("/Users/haho0032/Develop/githubFork/pysaml2/example/sp-repoze/pki/localhost.ca.crt")
    #ca_key_str = osw.read_str_from_file("/Users/haho0032/Develop/githubFork/pysaml2/example/sp-repoze/pki/localhost.ca.key")
    req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True, sn=sn, key_length=2048)
    cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)
    return cert_str, req_key_str

CONFIG = {
    "entityid": "%s/LocalTestSPHans.xml" % BASE,
    "description": "Lokal test SP Hans",
    "entity_category": [COC, RESEARCH_AND_EDUCATION, HEI, SFS_1993_1153, NREN, EU],
    "generate_cert_func": generate_cert,
    #Information needed for generated cert (NO CERT) solution.
    #"only_use_keys_in_metadata": False,
    #"cert_handler_extra_class": None,#MyCertGeneration(),
    #"generate_cert_info": {
    #    "cn": "localhost",
    #    "country_code": "se",
    #    "state": "ac",
    #    "city": "Umea",
    #    "organization": "ITS Umea University",
    #    "organization_unit": "DIRG"
    #},
    #"tmp_key_file": "pki/tmp_mykey.pem",
    #"tmp_cert_file": "pki/tmp_mycert.pem",
    #"validate_certificate": True,
    #############################################################
    "service": {
        "sp": {
            #Information needed for generated cert (NO CERT) solution.
            "authn_requests_signed": "true", #Will sign the request!
            "want_assertions_signed": "false", #Demands that the assertion is signed.
            "want_response_signed": "true",
            "allow_unsolicited": "true", #Allows the message not to be ment for this sp.
            #############################################################
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
    #Information needed for generated cert (NO CERT) solution.
    "key_file": "pki/mykey.pem",
    "cert_file": "pki/mycert.pem",
    #############################################################
    "attribute_map_dir": "./attributemaps",
    "metadata": {
        #"local": ["../idp2/idp_nocert.xml"],
        #"local": ["/Users/haho0032/Develop/svn/trunk/pyOpSamlProxy/idp_nocert.xml"],

        #Information needed for generated cert (NO CERT) solution.
        #"local": ["/Users/haho0032/Develop/github/IdProxy/idp_nocert.xml"],
        "local": ["/Users/haho0032/Develop/github/IdProxy/idp.xml"],
        #"local": ["../idp2/idp.xml"],
        #############################################################

        #"local": ["/Users/haho0032/Develop/github/IdProxy/idp.xml"],
    #    #"remote": [{"url": "http://130.239.201.5/role/idp.xml", "cert": None}],

    },


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

