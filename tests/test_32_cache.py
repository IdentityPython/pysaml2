#!/usr/bin/env python

import time
import py
from saml2.cache import Cache
from saml2.time_util import in_a_while, str_to_time

SESSION_INFO_PATTERN = {"ava":{}, "came from":"", "not_on_or_after":0,
                    "issuer":"", "session_id":-1}


def _eq(l1,l2):
    return set(l1) == set(l2)
    

class TestClass:
    def setup_class(self):
        self.cache = Cache()
        
        
    def test_set(self):
        not_on_or_after = str_to_time(in_a_while(days=1))
        session_info = SESSION_INFO_PATTERN.copy()
        session_info["ava"] = {"givenName":["Derek"]}
        self.cache.set("1234", "abcd", session_info,
                        not_on_or_after)
                        
        (ava, inactive) = self.cache.get_identity("1234")
        assert inactive == []
        assert ava.keys() == ["givenName"]
        assert ava["givenName"] == ["Derek"]
        
    def test_add_ava_info(self):        
        not_on_or_after = str_to_time(in_a_while(days=1))
        session_info = SESSION_INFO_PATTERN.copy()
        session_info["ava"] = {"surName":["Jeter"]}
        self.cache.set("1234", "bcde", session_info,
                        not_on_or_after)
                        
        (ava, inactive) = self.cache.get_identity("1234")
        assert inactive == []
        assert _eq(ava.keys(), ["givenName","surName"])
        assert ava["givenName"] == ["Derek"]
        assert ava["surName"] == ["Jeter"]

    def test_from_one_target_source(self):        
        session_info = self.cache.get("1234","bcde")
        ava = session_info["ava"]
        assert _eq(ava.keys(), ["surName"])
        assert ava["surName"] == ["Jeter"]
        session_info = self.cache.get("1234","abcd")
        ava = session_info["ava"]
        assert _eq(ava.keys(), ["givenName"])
        assert ava["givenName"] == ["Derek"]
        
    def test_entities(self):
        assert _eq(self.cache.entities("1234"), ["abcd", "bcde"])
        py.test.raises(Exception, "self.cache.entities('6666')")
        
    def test_remove_info(self):
        self.cache.reset("1234", "bcde")
        assert self.cache.active("1234", "bcde") == False
        assert self.cache.active("1234", "abcd")
        
        (ava, inactive) = self.cache.get_identity("1234")
        assert inactive == ['bcde']
        assert _eq(ava.keys(), ["givenName"])
        assert ava["givenName"] == ["Derek"]
    
    def test_active(self):
        assert self.cache.active("1234", "bcde") == False
        assert self.cache.active("1234", "abcd")
        
    def test_subjects(self):
        assert self.cache.subjects() == ["1234"]
        
    def test_second_subject(self):
        not_on_or_after = str_to_time(in_a_while(days=1))
        session_info = SESSION_INFO_PATTERN.copy()
        session_info["ava"] = {"givenName":["Ichiro"],
                                "surName":["Suzuki"]}
        self.cache.set("9876", "abcd", session_info,
                        not_on_or_after)

        (ava, inactive) = self.cache.get_identity("9876")
        assert inactive == []
        assert _eq(ava.keys(), ["givenName","surName"])
        assert ava["givenName"] == ["Ichiro"]
        assert ava["surName"] == ["Suzuki"]
        assert _eq(self.cache.subjects(), ["1234","9876"])
        
    def test_receivers(self):
        assert _eq(self.cache.receivers("9876"), ["abcd"])
        
        not_on_or_after = str_to_time(in_a_while(days=1))
        session_info = SESSION_INFO_PATTERN.copy()
        session_info["ava"] = {"givenName":["Ichiro"],
                                "surName":["Suzuki"]}
        self.cache.set("9876", "bcde", session_info,
                        not_on_or_after)
        
        assert _eq(self.cache.receivers("9876"), ["abcd", "bcde"])
        assert _eq(self.cache.subjects(), ["1234","9876"])
        
    def test_timeout(self):
        not_on_or_after = str_to_time(in_a_while(seconds=1))
        session_info = SESSION_INFO_PATTERN.copy()
        session_info["ava"] = {"givenName":["Alex"],
                                "surName":["Rodriguez"]}
        self.cache.set("1000", "bcde", session_info,
                        not_on_or_after)
                        
        time.sleep(2)
        (ava, inactive) = self.cache.get_identity("1000")
        assert inactive == ["bcde"]
        assert ava == {}
    
    