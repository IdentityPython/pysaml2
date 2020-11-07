from datetime import datetime
from unittest.mock import Mock
from unittest.mock import patch

from saml2.config import config_factory
from saml2.response import authn_response
from saml2.sigver import SignatureError

from dateutil import parser

from pytest import raises

from pathutils import dotname
from pathutils import full_path


XML_RESPONSE_XSW = full_path("saml2_response_xsw.xml")


class TestAuthnResponse:
    def setup_class(self):
        self.conf = config_factory("sp", dotname("server_conf"))
        self.ar = authn_response(self.conf, "http://lingon.catalogix.se:8087/")

    @patch('saml2.response.validate_on_or_after', return_value=True)
    def test_verify_signed_xsw(self, mock_validate_on_or_after):
        self.ar.issue_instant_ok = Mock(return_value=True)

        with open(XML_RESPONSE_XSW) as fp:
            xml_response = fp.read()

        self.ar.outstanding_queries = {"id12": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        self.ar.loads(xml_response, decode=False)

        assert self.ar.came_from == 'http://localhost:8088/sso'
        assert self.ar.session_id() == "id12"
        assert self.ar.issuer() == 'urn:mace:example.com:saml:roland:idp'

        with raises(SignatureError):
            self.ar.verify()

        assert self.ar.ava is None
        assert self.ar.name_id is None
