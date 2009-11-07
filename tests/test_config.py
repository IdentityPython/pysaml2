#!/usr/bin/env python
# -*- coding: utf-8 -*-


from saml2.config import Config

c1 = {
    "service": ["sp"],
    "entityid" : "urn:mace:umu.se:saml:roland:sp",
#    "my_name" : "urn:mace:umu.se:saml:roland:sp",
    "service_url" : "http://lingon.catalogix.se:8087/",
#    "debug" : 1,
    "key_file" : "tests/mykey.pem",
    "cert_file" : "tests/mycert.pem",
    "xmlsec_binary" : "/opt/local/bin/xmlsec1",
    "metadata": { 
        "local": ["tests/metadata.xml", 
                    "tests/urn-mace-swami.se-swamid-test-1.0-metadata.xml"],
#        "remote":{
#            "edugain":{
#                "url": "https://www.example.com/?id=edugain&set=saml2",
#                "cert": "./edugain.pem",
#             }
#        }
    },
    "idp_entity_id": "urn:mace:umu.se:saml:roland:idp",
    "virtual_organization" : {
        "http://vo.example.org/biomed":{
            "nameid_format" : "urn:oid:2.16.756.1.2.5.1.1.1-NameID",
            "common_identifier": "swissEduPersonUniqueID",
        }
    }
}

def test_1():
    c = Config()
    c.load(c1)