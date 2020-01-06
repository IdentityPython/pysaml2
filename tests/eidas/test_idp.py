from saml2 import metadata
from saml2.config import IdPConfig


class TestIdP:
    def setup_class(self):
        self.conf = IdPConfig()
        self.conf.load_file("idp_conf")

    def test_node_country_in_metadata(self):
        entd = metadata.entity_descriptor(self.conf)
        assert any(filter(lambda x: x.tag == "NodeCountry",
                          entd.extensions.extension_elements))
