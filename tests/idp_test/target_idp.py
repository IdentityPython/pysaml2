#!/usr/bin/env python
from saml2.saml import NAME_FORMAT_URI

__author__ = 'rolandh'

import json

BASE = "http://localhost:8088"

metadata = open("./idp/idp.xml").read()

info = {
    "entity_id": "%s/idp.xml" % BASE,
    "interaction": [
        {
            "matches": {
                "url": "%s/sso/redirect" % BASE,
                "title": 'IDP test login'
            },
            "page-type": "login",
            "control": {
                "type": "form",
                "set": {"login": "roland", "password": "dianakra"}
            }
        },
        {
            "matches": {
                "url": "%s/sso/post" % BASE,
                "title": 'IDP test login'
            },
            "page-type": "login",
            "control": {
                "type": "form",
                "set": {"login": "roland", "password": "dianakra"}
            }
        },
        {
            "matches": {
                "url": "%s/sso/redirect" % BASE,
                "title": "SAML 2.0 POST"
            },
            "page-type": "other",
            "control": {
                "index": 0,
                "type": "form",
            }
        },
        {
            "matches": {
                "url": "%s/sso/post" % BASE,
                "title": "SAML 2.0 POST"
            },
            "page-type": "other",
            "control": {
                "index": 0,
                "type": "form",
                "set": {}
            }
        },
        {
            "matches": {
                "url": "%s/slo/post" % BASE,
                "title": "SAML 2.0 POST"
            },
            "page-type": "other",
            "control": {
                "index": 0,
                "type": "form",
                "set": {}
            }
        }
    ],
    "metadata": metadata,
    "name_format": NAME_FORMAT_URI
    "constraints": {
        "signature_algorithm": [  # allowed for assertion & response signature
            ds.SIG_RSA_SHA1,
            ds.SIG_RSA_SHA224,
            ds.SIG_RSA_SHA256,
            ds.SIG_RSA_SHA384,
            ds.SIG_RSA_SHA512,
        ],
        "digest_algorithm": [
            ds.DIGEST_SHA1,
            ds.DIGEST_SHA224,
            ds.DIGEST_SHA256,
            ds.DIGEST_SHA384,
            ds.DIGEST_SHA512,
            ds.DIGEST_RIPEMD160,
        ],
    }
}

print json.dumps(info)