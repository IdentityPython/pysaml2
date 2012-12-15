#!/usr/bin/env python
import sys

__author__ = 'rolandh'

from saml2.mdie import from_dict

import xmldsig
import xmlenc
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

_dict = eval(open(sys.argv[1]).read())
res = from_dict(_dict, ONTS)

print res