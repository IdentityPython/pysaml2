__author__ = 'rolandh'

from saml2 import config
from saml2.client import Saml2Client
from saml2.time_util import str_to_time, in_a_while

SESSION_INFO_PATTERN = {"ava":{}, "came from":"", "not_on_or_after":0,
                    "issuer":"", "session_id":-1}

def add_derek_info(sp):
    not_on_or_after = str_to_time(in_a_while(days=1))
    session_info = SESSION_INFO_PATTERN.copy()
    session_info["ava"] = {"givenName":["Derek"], "umuselin":["deje0001"]}
    session_info["issuer"] = "urn:mace:example.com:saml:idp"
    session_info["name_id"] = "abcdefgh"
    session_info["not_on_or_after"] = not_on_or_after
    # subject_id, entity_id, info, timestamp
    sp.users.add_information_about_person(session_info)

class TestVirtualOrg():
    def setup_class(self):
        conf = config.SPConfig()
        conf.load_file("server_conf")
        self.sp = Saml2Client(conf)

        vo_name = conf.vorg.keys()[0]
        self.vo = conf.vorg[vo_name]
        add_derek_info(self.sp)

    def test_mta(self):
        aas = self.vo.members_to_ask("abcdefgh")
        print aas
        assert len(aas) == 1
        assert 'urn:mace:example.com:saml:aa' in aas

    def test_unknown_subject(self):
        aas = self.vo.members_to_ask("01234567")
        print aas
        assert len(aas) == 2

    def test_id(self):
        id = self.vo.get_common_identifier("abcdefgh")
        print id
        assert id == "deje0001"

    def test_id_unknown(self):
        id = self.vo.get_common_identifier("01234567")
        assert id is None

class TestVirtualOrg_2():
    def setup_class(self):
        conf = config.SPConfig()
        conf.load_file("server_conf")
        vo_name = conf.vorg.keys()[0]
        self.sp = Saml2Client(conf, virtual_organization=vo_name)
        add_derek_info(self.sp)

    def test_mta(self):
        aas = self.sp.vorg.members_to_ask("abcdefgh")
        print aas
        assert len(aas) == 1
        assert 'urn:mace:example.com:saml:aa' in aas

    def test_unknown_subject(self):
        aas = self.sp.vorg.members_to_ask("01234567")
        print aas
        assert len(aas) == 2

    def test_id(self):
        id = self.sp.vorg.get_common_identifier("abcdefgh")
        print id
        assert id == "deje0001"

    def test_id_unknown(self):
        id = self.sp.vorg.get_common_identifier("01234567")
        assert id is None
