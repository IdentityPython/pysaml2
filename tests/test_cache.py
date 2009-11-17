#!/usr/bin/env python

from saml2.cache import Cache
from saml2.time_util import in_a_while, str_to_time

def _eq(l1,l2):
    return set(l1) == set(l2)
    
class TestClass:
    def setup_class(self):
        self.cache = Cache()
        
        
    def test_0(self):
        not_on_or_after = str_to_time(in_a_while(days=1))
        self.cache.set("1234", "abcd", {"givenName":["Derek"]},
                        not_on_or_after)
                        
        (ava, inactive) = self.cache.get_all("1234")
        assert inactive == []
        assert ava.keys() == ["givenName"]
        assert ava["givenName"] == ["Derek"]
        
    def test_1(self):
        not_on_or_after = str_to_time(in_a_while(hours=1))
        self.cache.set("1234", "bcde", {"surName":["Jeter"]},
                        not_on_or_after)
                        
        (ava, inactive) = self.cache.get_all("1234")
        assert inactive == []
        assert _eq(ava.keys(), ["givenName","surName"])
        assert ava["givenName"] == ["Derek"]
        assert ava["surName"] == ["Jeter"]

    def test_2(self):
        ava = self.cache.get("1234","bcde")
        assert _eq(ava.keys(), ["surName"])
        assert ava["surName"] == ["Jeter"]
        
    def test_issuers(self):
        assert _eq(self.cache.issuers("1234"), ["abcd", "bcde"])
        
    def test_4(self):
        self.cache.reset("1234", "bcde")
        assert self.cache.active("1234","bcde") == False
        assert self.cache.active("1234","abcd")
        
        (ava, inactive) = self.cache.get_all("1234")
        assert inactive == ['bcde']
        assert _eq(ava.keys(), ["givenName"])
        assert ava["givenName"] == ["Derek"]
