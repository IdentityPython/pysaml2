#!/usr/bin/env python
import time
from saml2_tophat.attribute_converter import ac_factory
from saml2_tophat.mdstore import MetaDataMD, MetaDataFile

__author__ = 'rolandh'

start = time.time()
for i in range(1, 10):
    mdmd = MetaDataMD(ac_factory("../tests/attributemaps"), "swamid2.md")
    mdmd.load()

    _ = mdmd.keys()

print(time.time() - start)

start = time.time()
for i in range(1, 10):
    mdf = MetaDataFile(ac_factory("../tests/attributemaps"),
                       "../tests/swamid-2.0.xml")
    mdf.load()
    _ = mdf.keys()

print(time.time() - start)
