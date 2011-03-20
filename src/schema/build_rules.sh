../../tools/parse_xsd2.py -d defs_xmldsig.py xmldsig-core-schema.xsd > xd.py
../../tools/parse_xsd2.py -i xd xenc-schema.xsd > xe.py
../../tools/parse_xsd2.py -i xd -i xe -d defs_saml.py saml-schema-assertion-2.0.xsd > sa.py
../../tools/parse_xsd2.py -i xd -i xe -i sa -d defs_samlp.py saml-schema-protocol-2.0.xsd > sp.py
../../tools/parse_xsd2.py -i xd -i xe -i sa saml-schema-metadata-2.0.xsd > sm.py

../../tools/parse_xsd2.py -i xd -i xe -i sa -i sm ui.xsd > ui.py
../../tools/parse_xsd2.py -i xd -i xe -i sa -i sm -i ui dri.xsd > dri.py

../../tools/parse_xsd2.py -i xd shibboleth-metadata-1.0.xsd > shb.py

