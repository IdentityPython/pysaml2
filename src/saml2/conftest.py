import py
import os
import time
from subprocess import Popen

CONTACT = """<?xml version="1.0" encoding="utf-8"?>
<ContactPerson xmlns="urn:oasis:names:tc:SAML:2.0:metadata" contactType="technical">
  <GivenName>Roland</GivenName>
  <SurName>Hedberg</SurName>
  <EmailAddress>roland.hedberg@adm.umu.se</EmailAddress>
</ContactPerson>"""

def pytest_funcarg__idp_metadata(request):
    f = open('/Users/rolandh/code/om2/pysaml2/src/saml2/xeno_metadata.xml')
    data = f.read()
    f.close
    return data

def pytest_funcarg__contact(request):
    return CONTACT
