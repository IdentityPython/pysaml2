#!/usr/bin/python
#
# Copyright (C) 2013 Umea Universitet, Sweden
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

from setuptools import setup

__author__ = 'rohe0002'

setup(
    name="saml2test",
    version="0.4.3",
    description="SAML2 test tool",
    author = "Roland Hedberg",
    author_email = "roland.hedberg@adm.umu.se",
    license="Apache 2.0",
    packages=["idp_test", "idp_test/package", "saml2test", "sp_test", "utility"],
    package_dir = {"": "src"},
    classifiers = [
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = ["pysaml2",
                        "mechanize",
                        "argparse",
                        "beautifulsoup4",
                        "mako"],
    zip_safe=False,
    scripts=["script/idp_testdrv.py", "script/sp_testdrv.py"]
    )