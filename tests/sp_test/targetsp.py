#!/usr/bin/env python

__author__ = 'rolandh'

import json

BASE = "http://localhost:8087"
#BASE= "http://lingon.catalogix.se:8087"

metadata = open("./sp/sp.xml").read()

info = {
    "start_page": BASE,
    "entity_id": "%s/sp.xml" % BASE,
    "result": {
        "matches": {
            "content": "<h2>Your identity are"
        },
    },
    "metadata": metadata,
}

print json.dumps(info)