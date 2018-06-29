"""Setup.py entry point for package."""

import re

import setuptools


version = ''
VERSION_REGEX = r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]'
with open('src/saml2/__init__.py', 'r') as fd:
    content = fd.read()
    version = re.search(VERSION_REGEX, content, re.MULTILINE).group(1)

setuptools.setup(
    name='pysaml2',
    version=version,
    description='Python implementation of SAML Version 2 Standard',
    license='Apache 2.0',
    url='https://github.com/IdentityPython/pysaml2',
    packages=[
        'saml2',
        'saml2/attributemaps',
        'saml2/authn_context',
        'saml2/entity_category',
        'saml2/extension',
        'saml2/profile',
        'saml2/s2repoze',
        'saml2/s2repoze.plugins',
        'saml2/schema',
        'saml2/userinfo',
        'saml2/ws',
        'saml2/xmldsig',
        'saml2/xmlenc',
    ],
    package_dir={
        '': 'src',
    },
    package_data={
        '': [
            'xml/*.xml',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    scripts=[
        'tools/make_metadata.py',
        'tools/mdexport.py',
        'tools/merge_metadata.py',
        'tools/parse_xsd2.py',
    ],
    install_requires=[
        'cryptography',
        'defusedxml',
        'future', 'pyOpenSSL',
        'python-dateutil',
        'pytz',
        'requests >= 1.0.0',
        'six',
    ],
    extras_require={
        's2repoze': [
            'paste',
            'zope.interface',
            'repoze.who',
        ],
    },
    zip_safe=False,
)
