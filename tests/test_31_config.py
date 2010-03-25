#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2.config import Config
from saml2.metadata import MetaData
from py.test import raises

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

IDP1 = {
    "entityid" : "urn:mace:umu.se:saml:roland:idp",
    "service": {
        "idp":{
            "name" : "Rolands IdP",
            "url" : "http://localhost:8088/",
            "assertions":{
                "default": {
                    "attribute_restrictions": {
                        "givenName": None,
                        "surName": None,
                        "eduPersonAffiliation": ["(member|staff)"],
                        "mail": [".*@example.com"],
                    }
                },
                "urn:mace:umu.se:saml:roland:sp": None
            }
        }
    },
    "xmlsec_binary" : "/usr/local/bin/xmlsec1",
}

def _eq(l1,l2):
    return set(l1) == set(l2)

def test_1():
    c = Config().load(sp1)
    
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
    c = Config().load(sp2)
    
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

def test_missing_must():
    no_service = {
        "entityid" : "urn:mace:umu.se:saml:roland:sp",
        "xmlsec_binary" : "/opt/local/bin/xmlsec1",
    }

    no_entity_id = {
        "service": {
            "sp": {
                "url" : "http://lingon.catalogix.se:8087/",
                "name" : "test"
            }
        },
        "xmlsec_binary" : "/opt/local/bin/xmlsec1",
    }

    no_xmlsec = {
        "entityid" : "urn:mace:umu.se:saml:roland:sp",
        "service": {
            "sp": {
                "url" : "http://lingon.catalogix.se:8087/",
                "name" : "test"
            }
        },
    }
    
    c = Config()
    raises(AssertionError, "c.load(no_service)")
    raises(AssertionError, "c.load(no_entity_id)")
    raises(AssertionError, "c.load(no_xmlsec)")
    
def test_minimum():
    minimum = {
        "entityid" : "urn:mace:example.com:saml:roland:sp",
        "service": {
            "sp": {
                "url" : "http://sp.example.org/",
                "name" : "test",
                "idp": {
                    "" : "https://example.com/idp/SSOService.php",
                },
            }
        },
        "xmlsec_binary" : "/usr/local/bin/xmlsec1",
    }

    c = Config().load(minimum)
    
    assert c != None
    
def test_idp():
    c = Config().load(IDP1)
    
    print c
    assert c.services() == ["idp"]
    assert c.idp_url() == "http://localhost:8088/"

    attribute_restrictions = c.idp_policy().get_attribute_restriction("")
    assert attribute_restrictions["eduPersonAffiliation"][0].match("staff")
    