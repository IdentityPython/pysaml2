#!/usr/bin/env python
#
# Copyright (C) 2007 SIOS Technology, Inc.
# Copyright (C) 2011 Umea Universitet, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


install_requires = [
    # core dependencies
    'decorator',
    'requests >= 1.0.0',
    'paste',
    'zope.interface',
    'repoze.who',
    'm2crypto'
]

tests_require = [
    'mongodict',
    'pyasn1',
    'pymongo',
    'python-memcached == 1.51',
    'pytest',
    'mako',
    #'pytest-coverage',
]


# only for Python 2.6
if sys.version_info < (2, 7):
    install_requires.append('importlib')

setup(
    name='pysaml2',
    version='1.0.3',
    description='Python implementation of SAML Version 2 to be used in a WSGI environment',
    # long_description = read("README"),
    author='Roland Hedberg',
    author_email='roland.hedberg@adm.umu.se',
    license='Apache 2.0',
    url='https://github.com/rohe/pysaml2',

    packages=['saml2', 'xmldsig', 'xmlenc', 's2repoze', 's2repoze.plugins',
              "saml2/profile", "saml2/schema", "saml2/extension",
              "saml2/attributemaps", "saml2/authn_context",
              "saml2/entity_category"],

    package_dir={'': 'src'},
    package_data={'': ['xml/*.xml']},

    classifiers=["Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],

    scripts=["tools/parse_xsd2.py", "tools/make_metadata.py"],

    tests_require=tests_require,
    extras_require={
        'testing': tests_require,
    },
    install_requires=install_requires,
    zip_safe=False,
    test_suite='tests',
    cmdclass={'test': PyTest},
)
