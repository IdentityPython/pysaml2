from unittest import TestCase

import saml2

class TestPySAML2(TestCase):

    def test_import_to_satisfy_Jenkins(self):
        self.assertEqual(saml2.BINDING_HTTP_POST, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')


