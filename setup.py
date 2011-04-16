#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
# Copyright (C) 2010 Umea Universitet, Sweden
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

from distutils.core import  Command
from setuptools import setup


class PyTest(Command):
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        import sys, subprocess
        errno = subprocess.call([sys.executable, 'runtests.py'])
        raise SystemExit(errno)


setup(
    name='pysaml2',
    version='0.3.0',
    description='Python implementation of SAML Version 2 to for instance be used in a WSGI environment',
#    long_description = read("README"),
    author='Roland Hedberg',
    author_email='roland.hedberg@adm.umu.se',
    license='Apache 2.0',
    url='https://code.launchpad.net/~roland-hedberg/pysaml2/main',

    packages=['saml2', 'xmldsig', 'xmlenc', 's2repoze',
                's2repoze.plugins'],

    package_dir = {'':'src'},

    classifiers = ["Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],

    scripts=["tools/parse_xsd2.py", "tools/make_metadata.py"],

    install_requires=[
        # core dependencies
        'decorator',
        'httplib2',
        # only for Python 2.6
        #'importlib',
        # for the tests:
        'pyasn1',
        'python-memcached',
        "pytest",
        "pytest-coverage",
        # for s2repoze:
        'paste',
        'zope.interface',
        'repoze.who == 1.0.18',
        # extras
        'pymongo'
        ],
    zip_safe=False,

    cmdclass = {'test': PyTest},
)
