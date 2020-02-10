import pytest
import copy
from saml2 import BINDING_HTTP_POST
from saml2 import metadata
from saml2 import samlp
from saml2.client import Saml2Client
from saml2.server import Server
from saml2.config import eIDASSPConfig, eIDASIdPConfig
from eidas.idp_conf import CONFIG
from saml2.utility.config import ConfigValidationError


class TestIdP:
    def setup_class(self):
        self.server = Server("idp_conf")

        self.conf = eIDASIdPConfig()
        self.conf.load_file("idp_conf")

        sp_conf = eIDASSPConfig()
        sp_conf.load_file("sp_conf")

        self.client = Saml2Client(sp_conf)

    def teardown_class(self):
        self.server.close()

    @pytest.fixture(scope="function")
    def config(self):
        return copy.deepcopy(CONFIG)

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
        assert self.conf._idp_application_identifier \
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
        assert set(str(x) for x in self.conf._idp_protocol_version) \
               == set([x.text for x in protocol_version.attribute_value])

    def test_protocol_version_in_metadata(self, config):
        config["service"]["idp"]["protocol_version"] = 1.2

        conf = eIDASIdPConfig()
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
        assert {str(conf._idp_protocol_version)} \
               == set([x.text for x in protocol_version.attribute_value])


class TestIdPConfig:
    @staticmethod
    def assert_validation_error(config):
        conf = eIDASIdPConfig()
        conf.load(config)
        with pytest.raises(ConfigValidationError):
            conf.validate()

    @pytest.fixture(scope="function")
    def technical_contacts(self, config):
        return [
            x for x in config["contact_person"]
            if x["contact_type"] == "technical"
        ]

    @pytest.fixture(scope="function")
    def support_contacts(self, config):
        return [
            x for x in config["contact_person"]
            if x["contact_type"] == "support"
        ]

    @pytest.fixture(scope="function")
    def raise_error_on_warning(self, monkeypatch):
        def r(*args, **kwargs):
            raise ConfigValidationError()
        monkeypatch.setattr("saml2.config.logger.warning", r)

    @pytest.fixture(scope="function")
    def config(self):
        return copy.deepcopy(CONFIG)

    def test_singlelogout_declared(self, config, raise_error_on_warning):
        config["service"]["idp"]["endpoints"]["single_logout_service"] = \
            [("https://example.com", BINDING_HTTP_POST)]
        self.assert_validation_error(config)

    def test_artifact_resolution_declared(self, config, raise_error_on_warning):
        config["service"]["idp"]["endpoints"]["artifact_resolution_service"] = \
            [("https://example.com", BINDING_HTTP_POST)]
        self.assert_validation_error(config)

    def test_manage_nameid_service_declared(self, config, raise_error_on_warning):
        config["service"]["idp"]["endpoints"]["manage_name_id_service"] = \
            [("https://example.com", BINDING_HTTP_POST)]
        self.assert_validation_error(config)

    def test_no_keydescriptor(self, config):
        del config["cert_file"]
        self.assert_validation_error(config)

    def test_no_nodecountry(self, config):
        del config["service"]["idp"]["node_country"]
        self.assert_validation_error(config)

    def test_nodecountry_wrong_format(self, config):
        config["service"]["idp"]["node_country"] = "gr"
        self.assert_validation_error(config)

    def test_no_application_identifier_warning(self, config, raise_error_on_warning):
        del config["service"]["idp"]["application_identifier"]

        self.assert_validation_error(config)

    def test_empty_application_identifier_warning(self, config, raise_error_on_warning):
        config["service"]["idp"]["application_identifier"] = ""

        self.assert_validation_error(config)

    def test_application_identifier_wrong_format(self, config):
        config["service"]["idp"]["application_identifier"] = "TEST:Node.1"

        self.assert_validation_error(config)

    def test_application_identifier_ok_format(self, config, raise_error_on_warning):
        conf = eIDASIdPConfig()
        conf.load(config)
        conf.validate()

    def test_no_protocol_version_warning(self, config, raise_error_on_warning):
        del config["service"]["idp"]["protocol_version"]

        self.assert_validation_error(config)

    def test_empty_protocol_version_warning(self, config, raise_error_on_warning):
        config["service"]["idp"]["protocol_version"] = ""

        self.assert_validation_error(config)

    def test_no_organization_info_warning(self, config, raise_error_on_warning):
        del config["organization"]

        self.assert_validation_error(config)

    def test_empty_organization_info_warning(self, config, raise_error_on_warning):
        config["organization"] = {}

        self.assert_validation_error(config)

    def test_no_technical_contact_person(self,
                                         config,
                                         technical_contacts,
                                         raise_error_on_warning):
        for contact in technical_contacts:
            contact["contact_type"] = "other"

        self.assert_validation_error(config)

    def test_technical_contact_person_no_email(self,
                                               config,
                                               technical_contacts,
                                               raise_error_on_warning):

        for contact in technical_contacts:
            del contact["email_address"]

        self.assert_validation_error(config)

    def test_technical_contact_person_empty_email(self,
                                                  config,
                                                  technical_contacts,
                                                  raise_error_on_warning):

        for contact in technical_contacts:
            del contact["email_address"]

        self.assert_validation_error(config)

    def test_no_support_contact_person(self,
                                       config,
                                       support_contacts,
                                       raise_error_on_warning):
        for contact in support_contacts:
            contact["contact_type"] = "other"

        self.assert_validation_error(config)

    def test_support_contact_person_no_email(self,
                                             config,
                                             support_contacts,
                                             raise_error_on_warning):

        for contact in support_contacts:
            del contact["email_address"]

        self.assert_validation_error(config)

    def test_support_contact_person_empty_email(self,
                                                config,
                                                support_contacts,
                                                raise_error_on_warning):

        for contact in support_contacts:
            del contact["email_address"]

        self.assert_validation_error(config)

    def test_entityid_no_https(self, config):
        config["entityid"] = "urn:mace:example.com:saml:roland:idp"

        self.assert_validation_error(config)
