#!/usr/bin/env python

from saml2 import attribute_converter, saml

from attribute_statement_data import *

def _eq(l1,l2):
    return set(l1) == set(l2)

BASIC_NF = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'
URI_NF = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
SAML1 = 'urn:mace:shibboleth:1.0:attributeNamespace:uri'

def test_default():
    acs = attribute_converter.ac_factory()
    assert acs

class TestAC():
    def setup_class(self):
        self.acs = attribute_converter.ac_factory("attributemaps")
        
    def test_setup(self):
        print self.acs
        assert len(self.acs) == 3
        assert _eq([a.name_format for a in self.acs],[BASIC_NF, URI_NF, SAML1] )

    def test_ava_fro_1(self):
        ats = saml.attribute_statement_from_string(STATEMENT1)
        #print ats
        ava = None

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
        ava = None
        for ac in self.acs:
            try:
                ava = ac.fro(ats)
                break
            except attribute_converter.UnknownNameFormat:
                pass
        print ava.keys()
        assert _eq(ava.keys(),['uid', 'swissedupersonuniqueid',
                               'swissedupersonhomeorganizationtype',
                               'eduPersonEntitlement', 'eduPersonAffiliation',
                               'sn', 'mail', 'swissedupersonhomeorganization',
                               'givenName'])

    def test_to_attrstat_1(self):
        ava = { "givenName": "Roland", "sn": "Hedberg" }
        
        statement = attribute_converter.from_local(self.acs, ava, BASIC_NF)
        
        assert statement is not None
        assert len(statement) == 2
        a0 = statement[0]
        a1 = statement[1]
        if a0.friendly_name == 'sn':
            assert a0.name == 'urn:mace:dir:attribute-def:sn'
            assert a0.name_format == BASIC_NF
            assert a1.friendly_name == "givenName"
            assert a1.name == 'urn:mace:dir:attribute-def:givenName'
            assert a1.name_format == BASIC_NF
        elif a0.friendly_name == 'givenname':
            assert a0.name == 'urn:mace:dir:attribute-def:givenName'
            assert a0.name_format == BASIC_NF
            assert a1.friendly_name == "sn"
            assert a1.name == 'urn:mace:dir:attribute-def:sn'
            assert a1.name_format == BASIC_NF
        else:
            assert False
        
    def test_to_attrstat_2(self):
        ava = { "givenName": "Roland", "surname": "Hedberg" }
        
        statement = attribute_converter.from_local(self.acs, ava, URI_NF)
                
        assert len(statement) == 2
        a0 = statement[0]
        a1 = statement[1]
        if a0.friendly_name == 'surname':
            assert a0.name == 'urn:oid:2.5.4.4'
            assert a0.name_format == URI_NF
            assert a1.friendly_name == "givenName"
            assert a1.name == 'urn:oid:2.5.4.42'
            assert a1.name_format == URI_NF
        elif a0.friendly_name == 'givenname':
            assert a0.name == 'urn:oid:2.5.4.42'
            assert a0.name_format == URI_NF
            assert a1.friendly_name == "surname"
            assert a1.name == 'urn:oid:2.5.4.4'
            assert a1.name_format == URI_NF
        else:
            assert False
                
    def test_to_local_name(self):
    
        attr = [saml.Attribute(friendly_name="surName", 
                name="urn:oid:2.5.4.4",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
            saml.Attribute(friendly_name="efternamn", 
                name="urn:oid:2.5.4.42",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
            saml.Attribute(friendly_name="titel", 
                name="urn:oid:2.5.4.12",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")]
                
        lan = [attribute_converter.to_local_name(self.acs, a) for a in attr]
        
        assert _eq(lan, ['sn', 'givenName', 'title'])

    def test_ava_fro_1(self):
    
        attr = [saml.Attribute(friendly_name="surName", 
                name="urn:oid:2.5.4.4",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
            saml.Attribute(friendly_name="efternamn", 
                name="urn:oid:2.5.4.42",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
            saml.Attribute(friendly_name="titel", 
                name="urn:oid:2.5.4.12",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")]
            
        result = attribute_converter.ava_fro(self.acs, attr)
        
        print result
        assert result == {'givenName': [], 'sn': [], 'title': []}

    def test_to_local_name_from_basic(self):
        attr = [saml.Attribute(
                name="urn:mace:dir:attribute-def:eduPersonPrimaryOrgUnitDN")]

        lan = [attribute_converter.to_local_name(self.acs, a) for a in attr]

        assert _eq(lan, ['eduPersonPrimaryOrgUnitDN'])

    def test_to_and_for(self):
        ava = { "givenName": "Roland", "surname": "Hedberg" }

        basic_ac = [a for a in self.acs if a.name_format == BASIC_NF][0]

        attr_state = saml.AttributeStatement(basic_ac.to_(ava))

        oava = basic_ac.fro(attr_state)

        assert _eq(ava.keys(), oava.keys())
        