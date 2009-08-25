.. _install:

Quick install guide
===================

Before you can use Pysaml2, you'll need to get it installed. This guide 
will guide you to a simple, minimal installation.

Install Pysaml2
------------

For all this to work you need to have Python installed. Right now it has to be 
a 2.X version, where X > 4 .

Prerequisites
^^^^^^^^^^^^^

You have to download and install the following packages.



Quick build instructions
^^^^^^^^^^^^^^^^^^^^^^^^

  Once you have installed all the necessary prerequisites a simple::
  
    python setup.py install
    
  will install the basic code.

  After this you ought to be able to run the tests without an hitch.
  The tests are based on the pypy test environment, so::
  
    py.test tests
    
  is what you should use.

