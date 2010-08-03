../../tools/parse_xsd2.py -d defs_xmldsig.py xmldsig-core-schema.xsd > xd.py
../../tools/parse_xsd2.py -i xd xenc-schema.xsd > xe.py
../../tools/parse_xsd2.py -i xd -i xe -d defs_saml.py saml-schema-assertion-2.0.xsd.xml > sa.py
../../tools/parse_xsd2.py -i xd -i sa -d defs_samlp.py saml-schema-protocol-2.0.xsd.xml > sp.py
../../tools/parse_xsd2.py -i xd -i xe -i sa saml-schema-metadata-2.0.xsd > sm.py