from saml2 import metadata
from saml2 import samlp
from saml2.client import Saml2Client
from saml2.server import Server
from saml2.config import SPConfig
from eidas.sp_conf import CONFIG


class TestSP:
    def setup_class(self):
        self.server = Server("idp_conf")

        self.conf = SPConfig()
        self.conf.load_file("sp_conf")

        self.client = Saml2Client(self.conf)

    def teardown_class(self):
        self.server.close()

    def test_authn_request_force_authn(self):
        req_str = "{0}".format(self.client.create_authn_request(
            "http://www.example.com/sso", message_id="id1")[-1])
        req = samlp.authn_request_from_string(req_str)
        assert req.force_authn == "true"

    def test_sp_type_only_in_request(self):
        entd = metadata.entity_descriptor(self.conf)
        req_str = "{0}".format(self.client.create_authn_request(
            "http://www.example.com/sso", message_id="id1")[-1])
        req = samlp.authn_request_from_string(req_str)
        sp_type_elements = filter(lambda x: x.tag == "SPType",
                                  req.extensions.extension_elements)
        assert any(filter(lambda x: x.text == "public", sp_type_elements))
        assert not any(filter(lambda x: x.tag == "SPType",
                          entd.extensions.extension_elements))

    def test_sp_type_in_metadata(self):
        CONFIG["service"]["sp"]["sp_type_in_metadata"] = True
        sconf = SPConfig()
        sconf.load(CONFIG)
        custom_client = Saml2Client(sconf)

        req_str = "{0}".format(custom_client.create_authn_request(
            "http://www.example.com/sso", message_id="id1")[-1])
        req = samlp.authn_request_from_string(req_str)
        sp_type_elements = filter(lambda x: x.tag == "SPType",
                                  req.extensions.extension_elements)
        assert not any(filter(lambda x: x.text == "public", sp_type_elements))

        entd = metadata.entity_descriptor(sconf)
        assert any(filter(lambda x: x.tag == "SPType",
                          entd.extensions.extension_elements))

    def test_node_country_in_metadata(self):
        entd = metadata.entity_descriptor(self.conf)
        assert any(filter(lambda x: x.tag == "NodeCountry",
                          entd.extensions.extension_elements))


if __name__ == '__main__':
    TestSP()
