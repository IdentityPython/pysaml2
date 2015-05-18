#!/usr/bin/env python
import sys
import time
from saml2.attribute_converter import ac_factory
from saml2.mdstore import MetaDataMD, MetaDataFile

__author__ = 'rolandh'

from saml2 import xmldsig
from saml2 import xmlenc
from saml2 import md
from saml2 import saml
from saml2.extension import dri
from saml2.extension import idpdisc
from saml2.extension import mdattr
from saml2.extension import mdui
from saml2.extension import ui

ONTS = {
    dri.NAMESPACE: dri,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    mdattr.NAMESPACE: mdattr,
    mdui.NAMESPACE: mdui,
    saml.NAMESPACE: saml,
    ui.NAMESPACE: ui,
    xmlenc.NAMESPACE: xmlenc,
    xmldsig.NAMESPACE: xmldsig,
}

start = time.time()
for i in range(1, 10):
    mdmd = MetaDataMD(ONTS, ac_factory("../tests/attributemaps"), "swamid2.md")
    mdmd.load()

    _ = mdmd.keys()

print(time.time() - start)

start = time.time()
for i in range(1, 10):
    mdf = MetaDataFile(ONTS.values(), ac_factory("../tests/attributemaps"),
                       "../tests/swamid-2.0.xml")
    mdf.load()
    _ = mdf.keys()

print(time.time() - start)
