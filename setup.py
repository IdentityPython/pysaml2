#!/usr/bin/env python
import re

import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

install_requires = [
    # core dependencies
    'requests >= 1.0.0',
    'future',
    'cryptography',
    'pytz',
    'pyOpenSSL',
    'python-dateutil',
    'defusedxml',
    'six'
]

extras_require = {
    's2repoze': [
        'paste',
        'zope.interface',
        'repoze.who'
    ]
}

version = ''
with open('src/saml2/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name='pysaml2',
    version=version,
    description='Python implementation of SAML Version 2',
    # long_description = read("README"),
    author='Roland Hedberg',
    author_email='roland.hedberg@adm.umu.se',
    license='Apache 2.0',
    url='https://github.com/IdentityPython/pysaml2',

    packages=['saml2', 'saml2/xmldsig', 'saml2/xmlenc', 'saml2/s2repoze',
              'saml2/s2repoze.plugins', "saml2/profile", "saml2/schema",
              "saml2/extension", "saml2/attributemaps", "saml2/authn_context",
              "saml2/entity_category", "saml2/userinfo", "saml2/ws"],

    package_dir={'': 'src'},
    package_data={'': ['xml/*.xml']},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5"
        "Programming Language :: Python :: 3.6"
    ],

    scripts=["tools/parse_xsd2.py", "tools/make_metadata.py",
             "tools/mdexport.py", "tools/merge_metadata.py"],
    install_requires=install_requires,
    extras_require=extras_require,
    zip_safe=False,
)
