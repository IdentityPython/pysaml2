#!/usr/bin/env python

from saml2 import samlp
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT
from saml2.config import IdPConfig
from saml2.server import Identifier
from saml2.assertion import Policy


def _eq(l1,l2):
    return set(l1) == set(l2)

CONFIG = IdPConfig().load({
    "entityid" :  "urn:mace:example.com:idp:2",
    "name" : "test",
    "service": {
        "idp": {
            "endpoints" : {
                "single_sign_on_service" : ["http://idp.example.org/"],
                },
            "policy": {
                "default": {
                    "lifetime": {"minutes":15},
                    "attribute_restrictions": None, # means all I have
                    "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                    "nameid_format": NAMEID_FORMAT_PERSISTENT
                }
            }
        }
    },
    "virtual_organization" : {
        "http://vo.example.org/biomed":{
            "nameid_format" : "urn:oid:2.16.756.1.2.5.1.1.1-NameID",
            "common_identifier": "uid",
        },
        "http://vo.example.org/design":{
        }
    }
})

NAME_ID_POLICY_1 = """<?xml version="1.0" encoding="utf-8"?>
<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol"
  SPNameQualifier="http://vo.example.org/biomed"
/>
"""

NAME_ID_POLICY_2 = """<?xml version="1.0" encoding="utf-8"?>
<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol"
  SPNameQualifier="http://vo.example.org/design"
/>
"""


class TestIdentifier():
    def setup_class(self):
        self.id = Identifier("subject.db", CONFIG.virtual_organization)
        
    def test_persistent_1(self):
        policy = Policy({
            "default": {
                "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                "nameid_format": NAMEID_FORMAT_PERSISTENT,
                "attribute_restrictions": {
                    "surName": [".*berg"],
                }
            }
        })
        
        nameid = self.id.construct_nameid(policy, "foobar", 
                                            "urn:mace:example.com:sp:1")
        
        assert _eq(nameid.keys(), ['text', 'sp_provided_id', 
                            'sp_name_qualifier', 'name_qualifier', 'format'])
        assert _eq(nameid.keyswv(), ['format', 'text', 'sp_name_qualifier'])
        assert nameid.sp_name_qualifier == "urn:mace:example.com:sp:1"
        assert nameid.format == NAMEID_FORMAT_PERSISTENT
        
        nameid_2 = self.id.construct_nameid(policy, "foobar", 
                                            "urn:mace:example.com:sp:1")
        
        assert nameid != nameid_2
        assert nameid.text == nameid_2.text
        
    def test_transient_1(self):
        policy = Policy({
            "default": {
                "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                "nameid_format": NAMEID_FORMAT_TRANSIENT,
                "attribute_restrictions": {
                    "surName": [".*berg"],
                }
            }
        })
        nameid = self.id.construct_nameid(policy, "foobar", 
                                            "urn:mace:example.com:sp:1")
        
        assert _eq(nameid.keyswv(), ['text', 'format', 'sp_name_qualifier'])
        assert nameid.format == NAMEID_FORMAT_TRANSIENT
        
    def test_vo_1(self):
        policy = Policy({
            "default": {
                "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                "nameid_format": NAMEID_FORMAT_PERSISTENT,
                "attribute_restrictions": {
                    "surName": [".*berg"],
                }
            }
        })
        
        name_id_policy = samlp.name_id_policy_from_string(NAME_ID_POLICY_1)
        nameid = self.id.construct_nameid(policy, "foobar", 
                                            "urn:mace:example.com:sp:1", 
                                            {"uid": "foobar01"},
                                            name_id_policy)
        
        assert _eq(nameid.keyswv(), ['text', 'sp_name_qualifier', 'format'])
        assert nameid.sp_name_qualifier == 'http://vo.example.org/biomed'
        assert nameid.format == \
                CONFIG.virtual_organization['http://vo.example.org/biomed'][
                                                                "nameid_format"]
        assert nameid.text == "foobar01"

    def test_vo_2(self):
        policy = Policy({
            "default": {
                "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                "nameid_format": NAMEID_FORMAT_PERSISTENT,
                "attribute_restrictions": {
                    "surName": [".*berg"],
                }
            }
        })
        
        name_id_policy = samlp.name_id_policy_from_string(NAME_ID_POLICY_2)
        
        nameid = self.id.construct_nameid(policy, "foobar", 
                                            "urn:mace:example.com:sp:1", 
                                            {"uid": "foobar01"},
                                            name_id_policy)
        
        assert _eq(nameid.keyswv(), ['text', 'sp_name_qualifier', 'format'])
        assert nameid.sp_name_qualifier == 'http://vo.example.org/design'
        assert nameid.format == NAMEID_FORMAT_PERSISTENT
        assert nameid.text != "foobar01"
        
