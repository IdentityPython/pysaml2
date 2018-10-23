class TestSaml2Tophat():
    def test_loads_saml2_tophat(self):
        import saml2
        import saml2_tophat
        assert dir(saml2) == dir(saml2_tophat)
