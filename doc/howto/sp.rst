.. _howto_sp:

How to make a SAML2 service provider (SP).
==========================================

How it works
------------

A SP handles authentication, by the use of an Identity Provider, and possibly 
attribute aggregation.
Both of these functions can be seen as parts of the normal Repoze.who
setup. Namely the Challenger, Identifier and MetadataProvider parts so that
is also how it is implemented.

Normal for Repoze.who Identifier and MetadataProvider plugins are that
they place information they gather in environment variables. The convention is 
to place identity information in the environment under the key 
*repoze.who.identity*.
The information is structured as a dictionary with keys like *login*, and 
*repoze.who.userid*.

This SP follows this pattern and places the information gathered from 
the Identity Provider that handled the authentication and possible extra 
information received from attribute authorities in the above mentioned 
dictionary under the key *user*.

To summaries: in environ["repoze.who.identity"]["user"] you will find a 
dictionary with attributes and values describing the identity of a subject, 
the attribute names used depends on what's returned from the Identity 
Provider and possible Attribute Authorities. 

Accessing the information from an application is done by doing something 
like this::

    user_info = environ["repoze.who.identity"]["user"]

If a WAYF is going to be used, then the pattern is the following:

unauthenticated user + no IdP selected
    In this case, if there is a WAYF page specified in the 
    SP part of the repoze.who configuration file, 
    the user is redirected to that page. If no WAYF page is known an exception
    is raised.
    
unauthenticated user + selected IdP
    This is after the WAYF has been used, the entity ID of the selected IdP
    is expected to be in the environment variable *s2repose.wayf_selected*.
    If so the user is redirected to that IdP.
    
The set up
----------

There are two configuration files you have to deal with, first the 
pySAML2 configuration file which you can read more about here 
:ref:`howto_config` and secondly the repoze.who configuration file.
And it is the later one I will deal with here.

The **sp** plugin configuration has the following arguments

use
    Which module to use and which factory function in that module that should 
    be run to initiate the plugin.
    
rememberer_name
    Which plugin to use for remembering users
    
saml_conf
    Where the pySAML2 configuration file can be found
    
virtual_organization
    Which virtual organization this SP belongs to, can only be none or one.
    
debug
    Debug state, an integer. Presently just on (!= 0)/off (0) is supported.
    
cache
    If no cache file is defined, an in-memory cache will be used to 
    remember information received from IdPs and AAs. If a file name
    is given that file will be used for persistent storage of the cache.
    
wayf
    The webpage where the WAYF service is situated.
    
An example::

    [plugin:saml2sp]
    use = s2repoze.plugins.sp:make_plugin
    rememberer_name = auth_tkt
    saml_conf = sp.conf
    virtual_organization=urn:mace:umu.se:vo:it-enheten:cms
    debug = 1
    cache = /tmp/sp.cache
    wayf = wayf.html

Once you have configured the plugin you have to tell the server to use the
plugin in different ingress and egress operations as specified in
`Middleware responsibilities <http://docs.repoze.org/who/narr.html>`_

A typical SP configuration would be to use it in all aspects::

    [identifiers]
    plugins =
          saml2sp
          auth_tkt
          
    [authenticators]
    plugins = saml2sp

    [challengers]
    plugins = saml2sp

    [mdproviders]
    plugins = saml2sp

Other information
-----------------

The SP keeps tabs on all outstanding authentication requests it has. 
This is kept in the local variable *outstanding_queries*.
Presently if an authentication reponse is received that does not match an
outstanding request the reponse is ignored. This is going to change in the
future.

The format of *outstanding_queries* is a dictionary with the session IDs as
keys and which URL that was accessed that triggered the SP to send the
request.

