#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2.config import Config
from saml2.metadata import MetaData

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
    "key_file" : "mykey.pem",
    "cert_file" : "mycert.pem",
    "xmlsec_binary" : "/opt/local/bin/xmlsec1",
    "metadata": { 
        "local": ["metadata.xml", 
                    "urn-mace-swami.se-swamid-test-1.0-metadata.xml"],
    },
    "virtual_organization" : {
        "http://vo.example.org/biomed":{
            "nameid_format" : "urn:oid:2.16.756.1.2.5.1.1.1-NameID",
            "common_identifier": "swissEduPersonUniqueID",
        }
    }
}

sp2 = {
    "entityid" : "urn:mace:umu.se:saml:roland:sp",
    "service": {
        "sp":{
            "name" : "Rolands SP",
            "url" : "http://localhost:8087/",
            "required_attributes": ["surName", "givenName", "mail"],
            "optional_attributes": ["title"],
            "idp": {
                "" : "https://example.com/saml2/idp/SSOService.php",
            },
        }
    },
    "xmlsec_binary" : "/opt/local/bin/xmlsec1",
}

def _eq(l1,l2):
    return set(l1) == set(l2)

def test_1():
    c = Config()
    c.load(sp1)
    
    print c
    service = c["service"]
    assert service.keys() == ["sp"]
    sp = service["sp"] 
    assert _eq(sp.keys(),["url","name","idp"])
    md = c["metadata"]
    assert isinstance(md, MetaData)

    assert len(sp["idp"]) == 1
    assert sp["idp"].keys() == ["urn:mace:example.com:saml:roland:idp"]
    assert sp["idp"].values() == ["http://localhost:8088/sso/"]

def test_2():
    c = Config()
    c.load(sp2)
    
    print c
    service = c["service"]
    assert service.keys() == ["sp"]
    sp = service["sp"] 
    assert _eq(sp.keys(),['url', 'idp', 'optional_attributes', 'name', 
                            'required_attributes'])

    assert len(sp["idp"]) == 1
    assert sp["idp"].keys() == [""]
    assert sp["idp"].values() == [
                            "https://example.com/saml2/idp/SSOService.php"]
