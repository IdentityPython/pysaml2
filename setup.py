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

from setuptools import setup, find_packages


setup(
    name='pysaml2',
    version='0.3.0',
    description='Python implementation of SAML Version 2 to be used with WSGI applications',
#    long_description = read("README"),
    author='Roland Hedberg',
    author_email='roland.hedberg@adm.umu.se',
    license='Apache 2.0',
    url='https://code.launchpad.net/~roland-hedberg/pysaml2/main',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
    scripts=["tools/parse_xsd2.py", "tools/make_metadata.py"],
    install_requires=[
        # core dependencies
        'decorator',
        'httplib2',
        # for the tests:
        'pyasn1',
        'python-memcached',
        # for s2repoze:
        'paste',
        'zope.interface',
        'repoze.who<2.0',
        ],
    zip_safe=False,
)
