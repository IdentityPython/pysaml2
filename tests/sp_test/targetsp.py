#!/usr/bin/env python
from saml2.saml import AUTHN_PASSWORD

__author__ = 'rolandh'

import json

BASE = "http://localhost:8087"
#BASE= "http://lingon.catalogix.se:8087"

metadata = open("./sp/sp.xml").read()

AUTHN = {"class_ref": AUTHN_PASSWORD,
         "authn_auth": "http://lingon.catalogix.se/login"}

info = {
    "start_page": BASE,
    "entity_id": "%s/sp.xml" % BASE,
    "result": {
        "matches": {
            "content": "<h2>Your identity are"
        },
    },
    "metadata": metadata,
    "args":
        {
            "AuthnResponse": {
                "sign_assertion": True,
                "authn": AUTHN
            }
        },
    # This is the set of attributes and values that are returned in the
    # SAML Assertion
    "identity": {
        "given_name": "Roland",
        "sn": "Hedberg"
    },
    # This is the value of the NameID that is return in the Subject in the
    # Assertion
    "userid": "roland"
}

print json.dumps(info, indent=4, sort_keys=True)