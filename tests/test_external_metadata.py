
from saml2 import metadata, utils
from saml2 import NAMESPACE as SAML2_NAMESPACE
from saml2 import BINDING_SOAP
from saml2 import md, saml, samlp
from saml2 import time_util
from saml2.saml import NAMEID_FORMAT_TRANSIENT

def test_edugain():
    md = metadata.MetaData(xmlsec_binary="/opt/local/bin/xmlsec1")
    md.import_external_metadata(
        "https://hbe.edugain.bridge.feide.no/simplesaml/module.php/aggregator/?id=edugain&set=saml2",
        "tests/edugain.pem")
    
    print md.entity.keys()
    assert md.entity