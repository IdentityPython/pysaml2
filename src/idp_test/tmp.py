from saml2 import config, NAMEID_FORMAT_EMAILADDRESS
from saml2 import samlp
from saml2 import BINDING_HTTP_POST
from saml2 import VERSION

from saml2.client import Saml2Client
from saml2.s_utils import rndstr
from saml2.time_util import instant

__author__ = 'rolandh'

try:
    from xmlsec_location import xmlsec_path
except ImportError:
    xmlsec_path = '/opt/local/bin/xmlsec1'

cnf_dict = {
    "entityid" : "urn:mace:example.com:saml:roland:sp",
    "name" : "urn:mace:example.com:saml:roland:sp",
    "description": "Test SP",
    "service": {
        "sp": {
            "endpoints":{
                "assertion_consumer_service": ["http://lingon.catalogix.se:8087/"],
                },
            "required_attributes": ["surName", "givenName", "mail"],
            "optional_attributes": ["title"],
            "idp": ["urn:mace:example.com:saml:roland:idp"],
            }
    },
    "key_file" : "test.key",
    "cert_file" : "test.pem",
    "ca_certs": "cacerts.txt",
    "xmlsec_binary" : xmlsec_path,
    "metadata": {
        "local": ["idp.xml"],
        },
    "subject_data": "subject_data.db",
    "accepted_time_diff": 60,
    "attribute_map_dir" : "attributemaps",
}


conf = config.SPConfig()
conf.load(cnf_dict)
client = Saml2Client(conf)

binding= BINDING_HTTP_POST
query_id = rndstr()
service_url = "https://example.com"

authn_request = {
    #===== AuthRequest =====
    "subject":{
        "base_id":{
            "name_qualifier":None,
            "sp_name_qualifier":None,
            "text":None,
            "extension_elements":None,
            "extension_attributes":None,
        },
        "name_id":{
            "name_qualifier":None,
            "sp_name_qualifier":None,
            "format":None,
            "sp_provided_id": None,
            "text":None,
            "extension_elements":None,
            "extension_attributes":None,
        },
        "encrypted_id":{
            "encrypted_data":None,
            "encrypted_key":None,
            "text":None,
            "extension_elements":None,
            "extension_attributes":None,
        },
        "subject_confirmation":[{
            "base_id":{
                "name_qualifier":None,
                "sp_name_qualifier":None,
                "text":None,
                "extension_elements":None,
                "extension_attributes":None,
            },
            "name_id":{
                "name_qualifier":None,
                "sp_name_qualifier":None,
                "format":None,
                "sp_provided_id": None,
                "text":None,
                "extension_elements":None,
                "extension_attributes":None,
            },
            "encrypted_id":{
                "encrypted_data":None,
                "encrypted_key":None,
                "text":None,
                "extension_elements":None,
                "extension_attributes":None,
            },
            "subject_confirmation_data":{
                "not_before":None,
                "not_on_or_after":None,
                "recipient":None,
                "in_response_to":None,
                "address":None,
                "text":None,
                "extension_elements":None,
                "extension_attributes":None,
            },
            "text":None,
            "extension_elements":None,
            "extension_attributes":None,
        }],
        "text":None,
        "extension_elements":None,
        "extension_attributes":None,
    },
    #NameIDPolicy
    "name_id_policy":{
        "format":NAMEID_FORMAT_EMAILADDRESS,
        #   NAMEID_FORMAT_EMAILADDRESS = (
        #    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        #    NAMEID_FORMAT_UNSPECIFIED = (
        #    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
        #    NAMEID_FORMAT_ENCRYPTED = (
        #    "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")
        #    NAMEID_FORMAT_PERSISTENT = (
        #    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        #    NAMEID_FORMAT_TRANSIENT = (
        #    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
        #    NAMEID_FORMAT_ENTITY = (
        #    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")

        "sp_name_qualifier":None,
        "allow_create":None,
        #text=None,
        #extension_elements=None,
        #extension_attributes=None,
    },
    #saml.Conditions
    "conditions":{
        #Condition
        "condition":[{}],
        #AudienceRestriction
        "audience_restriction":[{}],
        #OneTimeUse
        "one_time_use":[{}],
        #ProxyRestriction
        "proxy_restriction":[{}],
        #not_before=None,
        #not_on_or_after=None,
        #text=None,
        #extension_elements=None,
        #extension_attributes=None,
    },
    #RequestedAuthnContext
    "requested_authn_context":{
        #saml.AuthnContextClassRef
        "authn_context_class_ref":None,
        #saml.AuthnContextDeclRef
        "authn_context_decl_ref":None,
        #AuthnContextComparisonType_
        "comparison":None,
        #text=None,
        #extension_elements=None,
        #extension_attributes=None,
    },
    #Scoping
    "scoping":{
        #IDPList
        "idp_list":{
            #IDPEntry
            "idp_entry":{
                "provider_id":None,
                "name":None,
                "loc":None,
                #text=None,
                #extension_elements=None,
                #extension_attributes=None,
            },
            #GetComplete
            "get_complete":{},
            #text=None,
            #extension_elements=None,
            #extension_attributes=None,
        },
        #RequesterID
        "requester_id":{},
        #proxy_count=None,
        #text=None,
        #extension_elements=None,
        #extension_attributes=None,
    },
    "force_authn":None,
    "is_passive":None,
    "protocol_binding":None,
    "assertion_consumer_service_index":None,
    "assertion_consumer_service_url":None,
    "attribute_consuming_service_index":None,
    "provider_name":None,
    #saml.Issuer
    "issuer":{},
    #ds.Signature
    "signature":{},
    #Extensions
    "extensions":{},
    "id":None,
    "version":None,
    "issue_instant":None,
    "destination":None,
    "consent":None,
    #text=None,
    #extension_elements=None,
    #extension_attributes=None,

}

request = samlp.AuthnRequest(
    id= query_id,
    version= VERSION,
    issue_instant= instant(),
    assertion_consumer_service_url= service_url,
    protocol_binding= binding
)
