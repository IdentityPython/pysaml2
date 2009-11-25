#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saml2 import utils
import zlib
import base64
import gzip
from saml2.sigver import make_temp
from saml2.config import do_assertions
from saml2.saml import Attribute, NAME_FORMAT_URI

def _eq(l1,l2):
    return set(l1) == set(l2)

def test_encode_decode():
    package = "1234567890abcdefghijklmnopqrstuvxyzåäö"

    intermediate = utils.deflate_and_base64_encode(package)
    res = utils.decode_base64_and_inflate(intermediate)
    assert package == res

AVA = [
    {
        "surName": ["Jeter"],
        "givenName": ["Derek"],
    },
    {
        "surName": ["Howard"],
        "givenName": ["Ryan"],
    },
    {
        "surName": ["Suzuki"],
        "givenName": ["Ischiro"],
    },
    {
        "surName": ["Hedberg"],
        "givenName": ["Roland"],
    },
]    

def test_filter_attribute_value_assertions_0():
    assertion = {
        "default": {
            "attribute_restrictions": {
                "surName": [".*berg"],
            }
        }
    }
    
    ass = do_assertions(assertion)
    print ass
    
    ava = utils.filter_attribute_value_assertions(AVA[3], 
                ass["default"]["attribute_restrictions"])
    
    print ava
    assert ava.keys() == ["surName"]
    assert ava["surName"] == ["Hedberg"]

def test_filter_attribute_value_assertions_1():
    assertion = {
        "default": {
            "attribute_restrictions": {
                "surName": None,
                "givenName": [".*er.*"],
            }
        }
    }
    
    ass = do_assertions(assertion)
    print ass
    
    ava = utils.filter_attribute_value_assertions(AVA[0], 
                ass["default"]["attribute_restrictions"])
    
    print ava
    assert _eq(ava.keys(), ["givenName","surName"])
    assert ava["surName"] == ["Jeter"]
    assert ava["givenName"] == ["Derek"]

    ava = utils.filter_attribute_value_assertions(AVA[1],
                ass["default"]["attribute_restrictions"])
    
    print ava
    assert _eq(ava.keys(), ["surName"])
    assert ava["surName"] == ["Howard"]
    
    
def test_filter_attribute_value_assertions_2():
    assertion = {
        "default": {
            "attribute_restrictions": {
                "givenName": ["^R.*"],
            }
        }
    }
    
    ass = do_assertions(assertion)
    print ass

    ava = utils.filter_attribute_value_assertions(AVA[0], 
                ass["default"]["attribute_restrictions"])
    
    print ava
    assert _eq(ava.keys(), [])
    
    ava = utils.filter_attribute_value_assertions(AVA[1], 
                ass["default"]["attribute_restrictions"])
    
    print ava
    assert _eq(ava.keys(), ["givenName"])
    assert ava["givenName"] == ["Ryan"]

    ava = utils.filter_attribute_value_assertions(AVA[3], 
                ass["default"]["attribute_restrictions"])
    
    print ava
    assert _eq(ava.keys(), ["givenName"])
    assert ava["givenName"] == ["Roland"]

def test_parse_attribute_map():
    (forward, backward) = utils.parse_attribute_map(["tests/attribute.map"])
    
    assert _eq(forward.keys(), backward.values())
    assert _eq(forward.values(), backward.keys())
    assert _eq(forward.keys(), ["urn:oid:2.5.4.4","urn:oid:2.5.4.42",
                    "urn:oid:2.5.4.12","urn:oid:2.5.4.12",
                    "urn:oid:0.9.2342.19200300.100.1.1",
                    "urn:oid:0.9.2342.19200300.100.1.3",
                    "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
                    "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"])
    assert _eq(backward.keys(),["surName","givenName","title","uid","mail",
                                    "eduPersonAffiliation",
                                    "eduPersonEntitlement"])
                                    

def test_identity_attribute_0():
    (forward, backward) = utils.parse_attribute_map(["tests/attribute.map"])
    a = Attribute(name="urn:oid:2.5.4.4", name_format=NAME_FORMAT_URI,
                    friendly_name="surName")
    
    assert utils.identity_attribute("name",a,forward) == "urn:oid:2.5.4.4"
    assert utils.identity_attribute("friendly",a,forward) == "surName"
                                    
def test_identity_attribute_1():
    (forward, backward) = utils.parse_attribute_map(["tests/attribute.map"])
    a = Attribute(name="urn:oid:2.5.4.4")
    
    assert utils.identity_attribute("name",a,forward) == "urn:oid:2.5.4.4"
    assert utils.identity_attribute("friendly",a,forward) == "surName"

def test_identity_attribute_2():
    (forward, backward) = utils.parse_attribute_map(["tests/attribute.map"])
    a = Attribute(name="urn:oid:2.5.4.5")
    
    assert utils.identity_attribute("name",a,forward) == "urn:oid:2.5.4.5"
    # if there would be a map it would be serialNumber
    assert utils.identity_attribute("friendly",a,forward) == "urn:oid:2.5.4.5"

def test_identity_attribute_3():
    a = Attribute(name="urn:oid:2.5.4.5")
    
    assert utils.identity_attribute("name",a) == "urn:oid:2.5.4.5"
    # if there would be a map it would be serialNumber
    assert utils.identity_attribute("friendly",a) == "urn:oid:2.5.4.5"

def test_identity_attribute_4():
    a = Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber")
    
    assert utils.identity_attribute("name",a) == "urn:oid:2.5.4.5"
    # if there would be a map it would be serialNumber
    assert utils.identity_attribute("friendly",a) == "serialNumber"
