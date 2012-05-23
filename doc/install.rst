.. _install:

Quick install guide
===================

Before you can use PySAML2, you'll need to get it installed. This guide 
will guide you to a simple, minimal installation.

Install PySAML2
---------------

For all this to work you need to have Python installed. 
The development has been done using 2.6.
There is no 3.X version yet.

Prerequisites
^^^^^^^^^^^^^

You have to have ElementTree, which is either part of your Python distribution
if it's recent enough, or if the Python is too old you have to install it,
for instance by getting it from the Python Package Instance by using 
easy_install.

You also need xmlsec which you can download from http://www.aleksey.com/xmlsec/

If you're on OS X you can get xmlsec installed from MacPorts or Fink.

Depending on how you are going to use PySAML2 you might also need

* Mako
* pyASN1
* repoze.who (make sure you get 1.0.16 and not 2.0)
* decorator
* python-memcache
* memcached

Quick build instructions
^^^^^^^^^^^^^^^^^^^^^^^^

Once you have installed all the necessary prerequisites a simple::

    python setup.py install

will install the basic code.

After this you ought to be able to run the tests without an hitch.
The tests are based on the pypy test environment, so::

    cd tests
    py.test 

is what you should use. If you don't have py.test, get it it's part of pypy! 
It's really good !

