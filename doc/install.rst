.. _install:

Quick install guide
===================

Before you can use Pysaml2, you'll need to get it installed. This guide 
will guide you to a simple, minimal installation.

Install Pysaml2
---------------

For all this to work you need to have Python installed. 
The development has been done using 2.6, but it might work with earlier 
versions. There is no 3.X version yet.

Prerequisites
^^^^^^^^^^^^^

You have to have ElementTree, which is either part of your Python distribution
if it's recent enough, or if the Python is too old you have to install it,
for instance by getting it from the Python Package Instance by using 
easy_install.

You also need xmlsec which you can download from http://www.aleksey.com/xmlsec/

If you're on OS X you can get xmlsec installed from MacPorts or Fink.


Quick build instructions
^^^^^^^^^^^^^^^^^^^^^^^^

Once you have installed all the necessary prerequisites a simple::

    python setup.py install

will install the basic code.

After this you ought to be able to run the tests without an hitch.
The tests are based on the pypy test environment, so::

    py.test tests

is what you should use. If you don't have py.test, get it ! It's good !

