#!/usr/bin/env python

from saml2.population import Population
from saml2.time_util import in_a_while

IDP_ONE = "urn:mace:example.com:saml:one:idp"
IDP_OTHER = "urn:mace:example.com:saml:other:idp"

def _eq(l1, l2):
    return set(l1) == set(l2)

class TestPopulationMemoryBased():
    def setup_class(self):
        self.population = Population()
        
    def test_add_person(self):
        session_info = {
            "name_id": "123456",
            "issuer": IDP_ONE,
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "givenName": "Anders",
                "surName": "Andersson",
                "mail": "anders.andersson@example.com"
            }
        }
        self.population.add_information_about_person(session_info)
        
        issuers = self.population.issuers_of_info("123456")
        assert issuers == [IDP_ONE]
        subjects = self.population.subjects()
        assert subjects == ["123456"]
        # Are any of the sources gone stale
        stales = self.population.stale_sources_for_person("123456")
        assert stales == []
        # are any of the possible sources not used or gone stale
        possible = [IDP_ONE, IDP_OTHER]
        stales = self.population.stale_sources_for_person("123456", possible)
        assert stales == [IDP_OTHER]

        (identity, stale) = self.population.get_identity("123456")
        assert stale == []
        assert identity == {'mail': 'anders.andersson@example.com', 
                            'givenName': 'Anders', 
                            'surName': 'Andersson'}

        info = self.population.get_info_from("123456", IDP_ONE)
        assert info.keys() == ["not_on_or_after", "name_id", "ava"]
        assert info["name_id"] == '123456' 
        assert info["ava"] == {'mail': 'anders.andersson@example.com', 
                                'givenName': 'Anders', 
                                'surName': 'Andersson'}

    def test_extend_person(self):
        session_info = {
            "name_id": "123456",
            "issuer": IDP_OTHER,
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "eduPersonEntitlement": "Anka"
            }
        }
        
        self.population.add_information_about_person(session_info)
        
        issuers = self.population.issuers_of_info("123456")
        assert _eq(issuers, [IDP_ONE, IDP_OTHER])
        subjects = self.population.subjects()
        assert subjects == ["123456"]
        # Are any of the sources gone stale
        stales = self.population.stale_sources_for_person("123456")
        assert stales == []
        # are any of the possible sources not used or gone stale
        possible = [IDP_ONE, IDP_OTHER]
        stales = self.population.stale_sources_for_person("123456", possible)
        assert stales == []

        (identity, stale) = self.population.get_identity("123456")
        assert stale == []
        assert identity == {'mail': 'anders.andersson@example.com', 
                            'givenName': 'Anders', 
                            'surName': 'Andersson',
                            "eduPersonEntitlement": "Anka"}

        info = self.population.get_info_from("123456", IDP_OTHER)
        assert info.keys() == ["not_on_or_after", "name_id", "ava"]
        assert info["name_id"] == '123456' 
        assert info["ava"] == {"eduPersonEntitlement": "Anka"}
    
    def test_add_another_person(self):
        session_info = {
            "name_id": "abcdef",
            "issuer": IDP_ONE,
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "givenName": "Bertil",
                "surName": "Bertilsson",
                "mail": "bertil.bertilsson@example.com"
            }
        }
        self.population.add_information_about_person(session_info)

        issuers = self.population.issuers_of_info("abcdef")
        assert issuers == [IDP_ONE]
        subjects = self.population.subjects()
        assert _eq(subjects, ["123456", "abcdef"])
        
        stales = self.population.stale_sources_for_person("abcdef")
        assert stales == []
        # are any of the possible sources not used or gone stale
        possible = [IDP_ONE, IDP_OTHER]
        stales = self.population.stale_sources_for_person("abcdef", possible)
        assert stales == [IDP_OTHER]

        (identity, stale) = self.population.get_identity("abcdef")
        assert stale == []
        assert identity == {"givenName": "Bertil",
                            "surName": "Bertilsson",
                            "mail": "bertil.bertilsson@example.com"
                            }

        info = self.population.get_info_from("abcdef", IDP_ONE)
        assert info.keys() == ["not_on_or_after", "name_id", "ava"]
        assert info["name_id"] == 'abcdef' 
        assert info["ava"] == {"givenName": "Bertil",
                                "surName": "Bertilsson",
                                "mail": "bertil.bertilsson@example.com"
                                }

    def test_modify_person(self):
        session_info = {
            "name_id": "123456",
            "issuer": IDP_ONE,
            "not_on_or_after": in_a_while(minutes=15),
            "ava": {
                "givenName": "Arne",
                "surName": "Andersson",
                "mail": "arne.andersson@example.com"
            }
        }
        self.population.add_information_about_person(session_info)
        
        issuers = self.population.issuers_of_info("123456")
        assert _eq(issuers, [IDP_ONE, IDP_OTHER])
        subjects = self.population.subjects()
        assert _eq(subjects, ["123456", "abcdef"])
        # Are any of the sources gone stale
        stales = self.population.stale_sources_for_person("123456")
        assert stales == []
        # are any of the possible sources not used or gone stale
        possible = [IDP_ONE, IDP_OTHER]
        stales = self.population.stale_sources_for_person("123456", possible)
        assert stales == []

        (identity, stale) = self.population.get_identity("123456")
        assert stale == []
        assert identity == {'mail': 'arne.andersson@example.com', 
                            'givenName': 'Arne', 
                            'surName': 'Andersson',
                            "eduPersonEntitlement": "Anka"}

        info = self.population.get_info_from("123456", IDP_OTHER)
        assert info.keys() == ["not_on_or_after", "name_id", "ava"]
        assert info["name_id"] == '123456' 
        assert info["ava"] == {"eduPersonEntitlement": "Anka"}