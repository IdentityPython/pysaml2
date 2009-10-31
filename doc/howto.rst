.. _howto:

How to use PySAML2
===================

Before you can use Pysaml2, you'll need to get it installed. 
If you have done it yet, read :ref:`install`

Well, now you have it installed and you want to do something.

And I'm sorry to tell you this; but there isn't really a lot you can do with 
this code on it's own.

Sure you can send a AuthenticationRequest to an IdentityProvider or a 
AttributeQuery to an AttributeAuthority but in order to get what they
return you have to sit behind a Web server. Well that is not really true since
the AttributeQuery would be over SOAP and you would get the result over the
conenction you have to the AttributeAuthority.

But anyway, you get may get my point. This is middleware stuff here !

Supposted to be used built-in in a webapplication.
To be more specific it is built to fit into a 
`WSGI  <http://www.python.org/dev/peps/pep-0333/>`_ application

So to get an example of where PySAML2 could fit in, you should download 
my repoze.who.plugin.saml2 package which you can find here:

bzr branch lp:~roland-hedberg/repoze.who.plugins.saml2/main

and go from there.
