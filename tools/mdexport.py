#!/usr/bin/env python
import sys

from saml2 import saml
from saml2 import md
from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
import xmldsig
import xmlenc

from saml2.mdstore import MetaDataFile, MetaDataExtern

__author__ = 'rolandh'

"""
A script that imports and verifies metadata and then dumps it in a basic
dictionary format.
"""

MDIMPORT = {
    "swamid": {
        "url": "https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2",
        "cert":"kalmar2.pem",
        "type": "external"
    },
    "incommon": {
        "file": "InCommon-metadata.xml",
        "type": "local"
    },
    "test": {
        "file": "mdtest.xml",
        "type": "local"
    }
}

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

item = MDIMPORT[sys.argv[1]]

metad = None

if item["type"] == "local":
    metad = MetaDataFile(sys.argv[1], ONTS.values(), item["file"])
elif item["type"] == "external":
    metad = MetaDataExtern(sys.argv[1], ONTS.values(),
                           item["url"], "/opt/local/bin/xmlsec1", item["cert"])

if metad:
    metad.load()
    print metad.dumps()

