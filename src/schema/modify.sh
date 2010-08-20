cp xd.py ../xmldsig/__init__.py
sed 's/import xd as ds/import xmldsig as ds/' < xe.py > ../xmlenc/__init__.py
sed -e 's/import xd as ds/import xmldsig as ds/' -e 's/import xe as xenc/import xmlenc as xenc/' -e 's/AttributeValue(SamlBase)/AttributeValue(AttributeValueBase)/' < sa.py > ../saml2/saml.py
sed -e 's/import xd as ds/import xmldsig as ds/' -e 's/import sa as saml/from saml2 import saml/' < sp.py > ../saml2/samlp.py
sed -e 's/import xd as ds/import xmldsig as ds/' -e 's/import xe as xenc/import xmlenc as xenc/' -e 's/import sa as saml/from saml2 import saml/' < sm.py > ../saml2/md.py
