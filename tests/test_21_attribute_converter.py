#!/usr/bin/env python

from saml2 import attribute_converter, saml

from attribute_statement_data import *

def _eq(l1,l2):
    return set(l1) == set(l2)

BASIC_NF = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'
URI_NF = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'

class TestAC():
    def setup_class(self):
        self.acs = attribute_converter.ac_factory("attributemaps")
        
    def test_setup(self):
        assert len(self.acs) == 2
        assert _eq([a.format for a in self.acs],[BASIC_NF, URI_NF] )

        
    def test_ava_fro_1(self):
        ats = saml.attribute_statement_from_string(STATEMENT1)
        #print ats
        for ac in self.acs:
            try:
                ava = ac.fro(ats)
                break
            except attribute_converter.UnknownNameFormat:
                pass
        print ava.keys()
        assert _eq(ava.keys(),['givenName', 'displayName', 'uid', 
            'eduPersonNickname', 'street', 'eduPersonScopedAffiliation', 
            'employeeType', 'eduPersonAffiliation', 'eduPersonPrincipalName', 
            'sn', 'postalCode', 'physicalDeliveryOfficeName', 'ou', 
            'eduPersonTargetedID', 'cn'])

    def test_ava_fro_2(self):
        ats = saml.attribute_statement_from_string(STATEMENT2)
        #print ats
        for ac in self.acs:
            try:
                ava = ac.fro(ats)
                break
            except attribute_converter.UnknownNameFormat:
                pass
        print ava.keys()
        assert _eq(ava.keys(),['uid', 'swissEduPersonUniqueID', 
                            'swissEduPersonHomeOrganizationType', 
                            'eduPersonEntitlement', 
                            'eduPersonAffiliation', 'sn', 'mail', 
                            'swissEduPersonHomeOrganization', 'givenName'])

    def test_to_attrstat_1(self):
        ava = { "givenName": "Roland", "sn": "Hedberg" }
        
        statement = attribute_converter.from_local(self.acs, ava, BASIC_NF)
        
        assert statement != None
        assert len(statement["attribute"]) == 2
        a0 = statement["attribute"][0]
        a1 = statement["attribute"][1]
        if a0["friendly_name"] == 'sn':
            assert a0["name"] == 'urn:mace:dir:attribute-def:sn'
            assert a0["name_format"] == BASIC_NF
            assert a1["friendly_name"] == "givenName"
            assert a1["name"] == 'urn:mace:dir:attribute-def:givenName'
            assert a1["name_format"] == BASIC_NF
        elif a0["friendly_name"] == 'givenName':
            assert a0["name"] == 'urn:mace:dir:attribute-def:givenName'
            assert a0["name_format"] == BASIC_NF
            assert a1["friendly_name"] == "sn"
            assert a1["name"] == 'urn:mace:dir:attribute-def:sn'
            assert a1["name_format"] == BASIC_NF
        else:
            assert False
        
    def test_to_attrstat_2(self):
        ava = { "givenName": "Roland", "surname": "Hedberg" }
        
        statement = attribute_converter.from_local(self.acs, ava, URI_NF)
                
        assert len(statement["attribute"]) == 2
        a0 = statement["attribute"][0]
        a1 = statement["attribute"][1]
        if a0["friendly_name"] == 'surname':
            assert a0["name"] == 'urn:oid:2.5.4.4'
            assert a0["name_format"] == URI_NF
            assert a1["friendly_name"] == "givenName"
            assert a1["name"] == 'urn:oid:2.5.4.42'
            assert a1["name_format"] == URI_NF
        elif a0["friendly_name"] == 'givenName':
            assert a0["name"] == 'urn:oid:2.5.4.42'
            assert a0["name_format"] == URI_NF
            assert a1["friendly_name"] == "surname"
            assert a1["name"] == 'urn:oid:2.5.4.4'
            assert a1["name_format"] == URI_NF
        else:
            assert False
                