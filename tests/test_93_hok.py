#!/usr/bin/env python
# -*- coding: utf-8 -*-
from contextlib import closing
from datetime import datetime
from dateutil import parser
from string import translate, whitespace
from saml2.authn_context import INTERNETPROTOCOLPASSWORD

from saml2.server import Server
from saml2.response import authn_response
from saml2.config import config_factory

from pathutils import dotname, full_path

# Example SAML response iwth 'holder-of-key' subject confirmtaions
# containing DER-base64 copies (without PEM enclosure) of test_1.crt and test_2.crt 
HOLDER_OF_KEY_RESPONSE_FILE = full_path("saml_hok.xml") 

TEST_CERT_1 = full_path("test_1.crt")
TEST_CERT_2 = full_path("test_2.crt")


class TestHolderOfKeyResponse:
    def test_hok_response_is_parsed(self):
        """Verifies that response with 'holder-of-key' subject confirmations is parsed successfully."""
        conf = config_factory("idp", dotname("server_conf"))
        resp = authn_response(conf, "https://sp:443/.auth/saml/login", asynchop=False, allow_unsolicited=True)
        with open(HOLDER_OF_KEY_RESPONSE_FILE, 'r') as fp:
            authn_response_xml = fp.read()
        resp.loads(authn_response_xml, False)
        resp.do_not_verify = True

        resp.parse_assertion()

        assert resp.get_subject() is not None
        assert len(resp.assertion.subject.subject_confirmation) == 2
        actual_certs = [sc.subject_confirmation_data.key_info[0].x509_data[0].x509_certificate.text.strip() 
                            for sc in resp.assertion.subject.subject_confirmation]
        expected_certs = [self._read_cert_without_pem_enclosure(TEST_CERT_1),
                          self._read_cert_without_pem_enclosure(TEST_CERT_2)]
        assert actual_certs == expected_certs

    def _read_cert_without_pem_enclosure(self, path):
        with open(path, 'r') as fp:
            lines = fp.readlines()
        lines_without_enclosure = lines[1:-1]
        return ''.join(lines_without_enclosure).translate(None, whitespace)


if __name__ == "__main__":
    t = TestHolderOfKeyResponse()
    t.setup_class()
    t.test_hok_response_is_parsed()
