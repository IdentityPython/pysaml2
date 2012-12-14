#!/usr/bin/env python
from saml2 import metadata, element_to_extension_element
from saml2 import SamlBase
from saml2 import extension_elements_as_dict
from saml2 import saml
from saml2 import md
from saml2.attribute_converter import ac_factory

from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
import xmldsig
import xmlenc

__author__ = 'rolandh'

"""
A script that imports and verifies metadata and stores it in a pysaml2 format
"""

MDIMPORT = {
    "swamid": {
        "url": "https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2",
        "cert":"kalmar2.pem"
    },
#    "incommon": {
#        "url": "file://InCommon-metadata.xml"
#    }
}

ATTRCONV = ac_factory("attributemaps")

def _eval(val):
    if isinstance(val, basestring):
        val = val.strip()
        if not val:
            return None
        else:
            return val
    elif isinstance(val, dict) or isinstance(val, SamlBase):
        return to_dict(val)
    elif isinstance(val, list):
        lv = []
        for v in val:
            if isinstance(v, dict) or isinstance(v, SamlBase):
                lv.append(to_dict(v))
            else:
                lv.append(v)
        return lv
    return val

def to_dict(_dict):
    res = {}
    if isinstance(_dict, SamlBase):
        res["__type__"] = "%s&%s" % (_dict.c_namespace,_dict.c_tag)
        for key in _dict.keyswv():
            val = getattr(_dict, key)
            if key == "extension_elements":
                _eed = extension_elements_as_dict(val, [idpdisc, mdui,
                                                        ui, dri, mdattr,
                                                        saml])
                _val = {}
                for key, _v in _eed.items():
                    _val[key] = _eval(_v)
            else:
                _val = _eval(val)
            if _val:
                res[key] = _val
    else:
        for key, val in _dict.items():
            _val = _eval(val)
            if _val:
                res[key] = _val
    return res

metad = metadata.MetaData(xmlsec_binary="/opt/local/bin/xmlsec1",
                       attrconv=ATTRCONV)

for key, spec in MDIMPORT.items():
    url = spec["url"]
    if url.startswith("file://"):
        metad.import_metadata(open(url[7:]).read(),key)
    else:
        metad.import_external_metadata(url, spec["cert"])

_dict = to_dict(metad.entity)

#print _dict
SKIP = ["__type__", "_certs"]

def _kwa(val, onts):
    return dict([(k,_x(v, onts)) for k,v in val.items() if k not in SKIP])

def _x(val, onts):
    if isinstance(val, dict):
        if "__type__" in val:
            ns, typ = val["__type__"].split("&")
            cls = getattr(onts[ns], typ)
            if cls is md.Extensions:
                lv = []
                for key, ditems in val.items():
                    if key in SKIP:
                        continue
                    for _k, items in ditems.items():
                        for item in items:
                            ns, typ = item["__type__"].split("&")
                            cls = getattr(onts[ns], typ)
                            kwargs = _kwa(item, onts)
                            inst = cls(**kwargs)
                            lv.append(element_to_extension_element(inst))
                return lv
            else:
                kwargs = _kwa(val, onts)
                inst = cls(**kwargs)
            return inst
        else:
            res = {}
            for key, v in val.items():
                res[key] = _x(v, onts)
            return res
    elif isinstance(val, basestring):
        return val
    elif isinstance(val, list):
        return [_x(v, onts) for v in val]
    else:
        return val

def from_dict(_dict, onts):
    res = {}
    for key, val in _dict.items():
        res[key] = _x(val, onts)

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

res = from_dict(_dict, ONTS)

print res[res.keys()[0]]