#!/usr/bin/env python
import sys

from saml2_tophat import saml
from saml2_tophat import md
from saml2_tophat.extension import mdui
from saml2_tophat.extension import idpdisc
from saml2_tophat.extension import dri
from saml2_tophat.extension import mdattr
from saml2_tophat.extension import ui
from saml2_tophat.extension import shibmd
from saml2_tophat import xmldsig
from saml2_tophat import xmlenc

from saml2_tophat.mdstore import MetaDataFile, MetaDataExtern

__author__ = 'rolandh'

"""
A script that imports and verifies metadata and then dumps it in a basic
dictionary format.
"""


MDIMPORT = {
    "swamid": {
        "url": "https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2_tophat",
        "cert": "kalmar2.pem",
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


def main():
    item = MDIMPORT[sys.argv[1]]

    metad = None

    if item["type"] == "local":
        metad = MetaDataFile(sys.argv[1], item["file"])
    elif item["type"] == "external":
        metad = MetaDataExtern(sys.argv[1], item["url"],
                               "/opt/local/bin/xmlsec1", item["cert"])

    if metad:
        metad.load()
        print(metad.dumps())


if __name__ == '__main__':
    main()
