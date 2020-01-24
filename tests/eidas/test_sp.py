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

    def test_application_identifier_in_metadata(self):
        entd = metadata.entity_descriptor(self.conf)
        entity_attributes = next(filter(lambda x: x.tag == "EntityAttributes",
                                        entd.extensions.extension_elements))
        app_identifier = [
            x for x in entity_attributes.children
            if getattr(x, "attributes", {}).get("Name") ==
               "http://eidas.europa.eu/entity-attributes/application-identifier"
        ]
        assert len(app_identifier) == 1
        assert self.conf._sp_application_identifier \
               == next(x.text for y in app_identifier for x in y.children)

    def test_multiple_protocol_version_in_metadata(self):
        entd = metadata.entity_descriptor(self.conf)
        entity_attributes = next(filter(lambda x: x.tag == "EntityAttributes",
                                        entd.extensions.extension_elements))
        protocol_version = next(
            x for x in entity_attributes.children
            if getattr(x, "name", "") ==
               "http://eidas.europa.eu/entity-attributes/protocol-version"
        )
        assert len(protocol_version.attribute_value) == 2
        assert set(str(x) for x in self.conf._sp_protocol_version) \
               == set([x.text for x in protocol_version.attribute_value])

    def test_protocol_version_in_metadata(self, config):
        config["service"]["sp"]["protocol_version"] = 1.2

        conf = eIDASSPConfig()
        conf.load(config)

        entd = metadata.entity_descriptor(conf)
        entity_attributes = next(filter(lambda x: x.tag == "EntityAttributes",
                                        entd.extensions.extension_elements))
        protocol_version = next(
            x for x in entity_attributes.children
            if getattr(x, "name", "") ==
            "http://eidas.europa.eu/entity-attributes/protocol-version"
        )
        assert len(protocol_version.attribute_value) == 1
        assert {str(conf._sp_protocol_version)} \
               == set([x.text for x in protocol_version.attribute_value])

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

    def test_no_nodecountry(self, config):
        del config["service"]["sp"]["node_country"]
        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()

    def test_nodecountry_wrong_format(self, config):
        config["service"]["sp"]["node_country"] = "gr"
        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()

    def test_no_application_identifier_warning(self, config, raise_error_on_warning):
        del config["service"]["sp"]["application_identifier"]

        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()

    def test_application_identifier_wrong_format(self, config):
        config["service"]["sp"]["application_identifier"] = "TEST:Node.1"

        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()

    def test_application_identifier_ok_format(self, config):
        conf = eIDASSPConfig()
        conf.load(config)
        conf.validate()

    def test_no_protocol_version_warning(self, config, raise_error_on_warning):
        del config["service"]["sp"]["protocol_version"]

        conf = eIDASSPConfig()
        conf.load(config)

        with pytest.raises(ConfigValidationError):
            conf.validate()
