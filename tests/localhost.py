#!/usr/bin/env python
__author__ = 'rolandh'

import json

BASE = "http://localhost:8088"

metadata = open("./idp/idp.xml").read()

info = {
    "entity_id": "%s/idp.xml" % BASE,
    "sp_config": "sp_local_conf.py",
    "interaction": [
        {
            "matches": {
                "url": "%s/login" % BASE,
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
            "control": {
                "type": "response",
                "pick": {"form": {"action":"%s/acs" % BASE}}
            }
        },
        {
            "matches": {
                "url": "%s/sso/post" % BASE,
                "title": "SAML 2.0 POST"
            },
            "control": {
                "type": "response",
                "pick": {"form": {"action":"%s/acs" % BASE}}
            }
        },
        {
            "matches": {
                "url": "%s/slo/post" % BASE,
                "title": "SAML 2.0 POST"
            },
            "control": {
                "type": "response",
                "pick": {"form": {"action":"%s/sls" % BASE}}
            }
        }
    ],
    "metadata": metadata
}

print json.dumps(info)