.. _howto:

How to use PySAML2
===================

:Release: |release|
:Date: |today|

Before you can use Pysaml2, you'll need to get it installed. 
If you have not done it yet, read the :ref:`install`

Well, now you have it installed and you want to do something.

And I'm sorry to tell you this; but there isn't really a lot you can do with 
this code on its own.

Sure you can send a AuthenticationRequest to an IdentityProvider or a 
AttributeQuery to an AttributeAuthority, but in order to get what they
return you have to sit behind a Web server. Well that is not really true since
the AttributeQuery would be over SOAP and you would get the result over the
connection you have to the AttributeAuthority.

But anyway, you may get my point. This is middleware stuff!

PySAML2 is built to fit into a 
`WSGI  <http://www.python.org/dev/peps/pep-0333/>`_ application

But it can be used in a non-WSGI environment too. 

So you will find descriptions of both cases here.

The configuration is the same regardless of whether you are using PySAML2 in a 
WSGI or non-WSGI environment.

Debugging Responses
===================

In the event that you are trying to do anything using custom properties, you
will very likely want to look into the response data to debug at some point. 
The simplest way to do this is to set a custom level for the logger in the 
relevant part of the PySAML2 module.

.. code-block:: python

   import logging, saml2.response
    # override default loglevel to see details of SAML response returned
    saml2.response.logger.setLevel(logging.DEBUG)


.. toctree::
   :maxdepth: 1

   config

   
