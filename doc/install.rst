.. _install:

Quick install guide
===================

Before you can use PySAML2, you'll need to get it installed. This guide 
will guide you to a simple, minimal installation.

Install PySAML2
---------------

For all this to work you need to have Python installed. 
The development has been done using 2.7.
There is now a 3.X version.

Prerequisites
^^^^^^^^^^^^^

You have to have ElementTree, which is either part of your Python distribution
if it's recent enough, or if the Python is too old you have to install it,
for instance by getting it from the Python Package Instance by using 
easy_install.

You also need xmlsec1 which you can download from http://www.aleksey.com/xmlsec/

If you're on OS X you can get xmlsec1 installed from MacPorts or Fink.

Depending on how you are going to use PySAML2 you might also need

* Mako
* pyASN1
* repoze.who
* python-memcache
* memcached
* bsddb3

Quick build instructions
^^^^^^^^^^^^^^^^^^^^^^^^

Once you have installed all the necessary prerequisites a simple::

    python setup.py install

will install the basic code.

Note for rhel/centos 6: cffi depends on libffi-devel, and cryptography on openssl-devel to compile
So you might want first to do:
yum install libffi-devel openssl-devel

After this you ought to be able to run the tests without an hitch.
The tests are based on the pypy test environment, so::

    cd tests
    py.test 

is what you should use. If you don't have py.test, get it it's part of pypy! 
It's really good!

Hints
-----

RHEL/CentOS installation issues
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A number of packages may not install from pypi. Instead, you may want to use packages supplied with the OS:

    yum -y install swig openssl-devel m2crypto xmlsec1 pyOpenSSL libffi-devel

OS X installation issues
^^^^^^^^^^^^^^^^^^^^^^^^

A number of packages may not install from pypi. Instead, you may want to use macports:

    sudo port install swig xmlsec py27-m2crypto py27-crypto db53

Starting with XCode 5.1 there is an issue with unrecognised gcc command line options.
A temporary fix is described in http://alyssafrazee.com/dangit-mavericks.html
So to install cryptography and bsddb3 you might want to try:
sudo ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future pip install cryptography bsddb3

If the message "ImportError: No module named _bsddb" pops up on starting idp.py, this fix should help:
http://marc-abramowitz.com/archives/2007/11/28/hacking-os-xs-python-dbhash-and-bsddb-modules-to-work/


Generate the HTML documentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
install Sphinx
cd pysaml2/doc
make html
cd _build

List implemented signature algorithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For a list of xmldsig algorithtms implemented for signature validation, run this program from the command line:
saml2/sigver.py -s
