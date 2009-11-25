#!/usr/bin/env python
# -*- coding: utf-8 -*-


from saml2.config import Config

sp1 = {
    "entityid" : "urn:mace:umu.se:saml:roland:sp",
    "service": {
        "sp": {
            "url" : "http://lingon.catalogix.se:8087/",
            "name": "test",
            "idp" : {
                "urn:mace:example.com:saml:roland:idp":None,
            },
        }
    },
    "key_file" : "tests/mykey.pem",
    "cert_file" : "tests/mycert.pem",
    "xmlsec_binary" : "/opt/local/bin/xmlsec1",
    "metadata": { 
        "local": ["tests/metadata.xml", 
                    "tests/urn-mace-swami.se-swamid-test-1.0-metadata.xml"],
    },
    "virtual_organization" : {
        "http://vo.example.org/biomed":{
            "nameid_format" : "urn:oid:2.16.756.1.2.5.1.1.1-NameID",
            "common_identifier": "swissEduPersonUniqueID",
        }
    }
}

def test_1():
    c = Config()
    c.load(sp1)
    
    print c
    assert False
