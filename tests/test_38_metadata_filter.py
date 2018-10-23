from saml2_tophat import md
from saml2_tophat import saml
from saml2_tophat import config
from saml2_tophat import xmldsig
from saml2_tophat import xmlenc

from saml2_tophat.filter import AllowDescriptor
from saml2_tophat.mdstore import MetadataStore
from saml2_tophat.attribute_converter import ac_factory
from saml2_tophat.extension import mdui
from saml2_tophat.extension import idpdisc
from saml2_tophat.extension import dri
from saml2_tophat.extension import mdattr
from saml2_tophat.extension import ui

from pathutils import full_path

__author__ = 'roland'

sec_config = config.Config()


ATTRCONV = ac_factory(full_path("attributemaps"))

METADATACONF = {
    "1": [{
        "class": "saml2_tophat.mdstore.MetaDataFile",
        "metadata": [(full_path("swamid-2.0.xml"), )],
    }],
}

def test_swamid_sp():
    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True,
                        filter=AllowDescriptor(["spsso"]))

    mds.imp(METADATACONF["1"])
    sps = mds.with_descriptor("spsso")
    assert len(sps) == 417
    idps = mds.with_descriptor("idpsso")
    assert idps == {}

def test_swamid_idp():
    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True,
                        filter=AllowDescriptor(["idpsso"]))

    mds.imp(METADATACONF["1"])
    sps = mds.with_descriptor("spsso")
    assert len(sps) == 0
    idps = mds.with_descriptor("idpsso")
    assert len(idps) == 275

if __name__ == "__main__":
    test_swamid_idp()
