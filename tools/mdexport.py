#!/usr/bin/env python
import sys
from saml2 import metadata
from saml2 import saml
from saml2 import md
from saml2.attribute_converter import ac_factory

from saml2.mdie import to_dict

from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
import xmldsig
import xmlenc

__author__ = 'rolandh'

"""
A script that imports and verifies metadata and dumps it in a basic
dictionary format.
"""

MDIMPORT = {
    "swamid": {
        "url": "https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2",
        "cert":"kalmar2.pem"
    },
    "incommon": {
        "url": "file://InCommon-metadata.xml"
    },
    "test": {
        "url": "file://mdtest.xml"
    }
}

ATTRCONV = ac_factory("attributemaps")

ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc
}


metad = metadata.MetaData(xmlsec_binary="/opt/local/bin/xmlsec1",
                       attrconv=ATTRCONV)

for src in sys.argv[1:]:
    spec = MDIMPORT[src]
    url = spec["url"]
    if url.startswith("file://"):
        metad.import_metadata(open(url[7:]).read(), src)
    else:
        metad.import_external_metadata(url, spec["cert"])

_dict = to_dict(metad.entity, ONTS.values())

import json
print json.dumps(_dict, indent=2)

