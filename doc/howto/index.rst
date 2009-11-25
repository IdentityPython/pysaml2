.. _howto:

How to use PySAML2
===================

:Release: |version|
:Date: |today|

Before you can use Pysaml2, you'll need to get it installed. 
If you have done it yet, read the :ref:`install`

Well, now you have it installed and you want to do something.

And I'm sorry to tell you this; but there isn't really a lot you can do with 
this code on it's own.

Sure you can send a AuthenticationRequest to an IdentityProvider or a 
AttributeQuery to an AttributeAuthority but in order to get what they
return you have to sit behind a Web server. Well that is not really true since
the AttributeQuery would be over SOAP and you would get the result over the
conenction you have to the AttributeAuthority.

But anyway, you get may get my point. This is middleware stuff here !

PySAML2 is built to fit into a 
`WSGI  <http://www.python.org/dev/peps/pep-0333/>`_ application

There are more than one WSGI framework out there, so when I started this work
I just picked one I liked, namely `Repoze <http://repoze.org/>`_ .
Or to be more specific I choose to work within the context of
`Repoze.who <http://static.repoze.org/whodocs/>`_.

So the descriptions in the following chapters are based on the usage of
pySAML2 together with repoze.who .

.. toctree::
   :maxdepth: 1

   config
   sp
   idp
   
