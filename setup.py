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

from distutils.core import setup


setup(
    name='python-saml2',
    version='0.0.6',
    description='Python library for SAML Version 2',
    long_description = read("README"),
    author='Roland Hedberg',
    author_email='roland.hedberg@adm.umu.se',
    license='Apache 2.0',
    url='https://code.launchpad.net/~roland-hedberg/pysaml2/main',
    packages=['saml2', 'xmldsig', 'xmlenc', 's2repoze', 
                's2repoze.plugins'],
    package_dir = {'saml2':'src/saml2', 'xmldsig':'src/xmldsig',
                    'xmlenc': 'src/xmlenc', 
                    's2repoze': 'src/s2repoze'},
    classifiers = ["Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"]
)
