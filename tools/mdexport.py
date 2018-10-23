#!/usr/bin/env python
from saml2_tophat.sigver import _get_xmlsec_cryptobackend
from saml2_tophat.sigver import SecurityContext
from saml2_tophat.httpbase import HTTPBase

from saml2_tophat import saml
from saml2_tophat import md
from saml2_tophat.attribute_converter import ac_factory
from saml2_tophat import xmldsig
from saml2_tophat import xmlenc

import argparse

from saml2_tophat.mdstore import MetaDataFile, MetaDataExtern, load_extensions

__author__ = 'rolandh'

"""
A script that imports and verifies metadata and then dumps it in a basic
dictionary format.
"""

parser = argparse.ArgumentParser()
parser.add_argument('-t', dest='type')
parser.add_argument('-u', dest='url')
parser.add_argument('-c', dest='cert')
parser.add_argument('-a', dest='attrsmap')
parser.add_argument('-o', dest='output')
parser.add_argument('-x', dest='xmlsec')
parser.add_argument(dest="item")
args = parser.parse_args()


metad = None

if args.type == "local":
    metad = MetaDataFile(args.item, args.item)
elif args.type == "external":
    ATTRCONV = ac_factory(args.attrsmap)
    httpc = HTTPBase()
    crypto = _get_xmlsec_cryptobackend(args.xmlsec)
    sc = SecurityContext(crypto)
    metad = MetaDataExtern(ATTRCONV, args.url, sc, cert=args.cert, http=httpc)

if metad is not None:
    metad.load()
    txt = metad.dumps()
    if args.output:
        f = open(args.output, "w")
        f.write(txt)
        f.close()
    else:
        print(txt)
