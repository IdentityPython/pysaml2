#!/usr/bin/env python

__author__ = 'rohe0002'

from idp_test import saml2int
from idp_test import SAML2client

cli = SAML2client(saml2int)
cli.run()