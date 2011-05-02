echo "xmldsig"
../../tools/parse_xsd2.py -d defs_xmldsig.py xmldsig-core-schema.xsd > xd.py
echo "xenc"
../../tools/parse_xsd2.py -i xd xenc-schema.xsd > xe.py
echo "saml assertion"
../../tools/parse_xsd2.py -i xd -i xe -d defs_saml.py saml-schema-assertion-2.0.xsd > sa.py
echo "saml protocol"
../../tools/parse_xsd2.py -i xd -i xe -i sa -d defs_samlp.py saml-schema-protocol-2.0.xsd > sp.py
echo "saml metadata"
../../tools/parse_xsd2.py -i xd -i xe -i sa saml-schema-metadata-2.0.xsd > sm.py
echo "saml metadata ui"
../../tools/parse_xsd2.py -i xd -i xe -i sa -i sm sstc-saml-metadata-ui-v1.0.xsd > mdui.py
echo "dri"
../../tools/parse_xsd2.py -i xd -i xe -i sa -i sm -i ui dri.xsd > dri.py
echo "metadata attr"
../../tools/parse_xsd2.py -i xd -i xe -i sa sstc-metadata-attr.xsd > mdattr.py
echo "shib metadata"
../../tools/parse_xsd2.py -i xd shibboleth-metadata-1.0.xsd > shb.py

