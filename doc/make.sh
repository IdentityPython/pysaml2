#!/bin/sh
rm -f saml2test*
sphinx-apidoc -F -o ../doc/ ../src/saml2test
make clean
make html