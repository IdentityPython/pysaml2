import pytest
import copy
from saml2 import BINDING_HTTP_POST
from saml2 import metadata
from saml2 import samlp
from saml2.client import Saml2Client
from saml2.server import Server
from saml2.config import eIDASSPConfig
from eidas.sp_conf import CONFIG
from saml2.utility.config import ConfigValidationError


class TestSP:
    def setup_class(self):
        self.server = Server("idp_conf")

        self.conf = eIDASSPConfig()
        self.conf.load_file("sp_conf")

        self.client = Saml2Client(self.conf)

    def teardown_class(self):
        self.server.close()

    @pytest.fixture(scope="function")
    def config(self):
        return copy.deepcopy(CONFIG)

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

    def test_sp_type_in_metadata(self, config):
        config["service"]["sp"]["sp_type_in_metadata"] = True
        sconf = eIDASSPConfig()
        sconf.load(config)
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


class TestSPConfig:
    @pytest.fixture(scope="function")
    def raise_error_on_warning(self, monkeypatch):
        def r(*args, **kwargs):
            raise ConfigValidationError()
        monkeypatch.setattr("saml2.utility.config.logger.warning", r)

    @pytest.fixture(scope="function")
    def config(self):
        return copy.deepcopy(CONFIG)

    def test_singlelogout_declared(self, config, raise_error_on_warning):
        config["service"]["sp"]["endpoints"]["single_logout_service"] = \
            [("https://example.com", BINDING_HTTP_POST)]
        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()

    def test_artifact_resolution_declared(self, config, raise_error_on_warning):
        config["service"]["sp"]["endpoints"]["artifact_resolution_service"] = \
            [("https://example.com", BINDING_HTTP_POST)]
        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()

    def test_manage_nameid_service_declared(self, config, raise_error_on_warning):
        config["service"]["sp"]["endpoints"]["manage_name_id_service"] = \
            [("https://example.com", BINDING_HTTP_POST)]
        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()

    def test_no_keydescriptor(self, config):
        del config["cert_file"]
        del config["encryption_keypairs"]
        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()
