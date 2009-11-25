.. _howto_sp:

How to make a SAML2 service provider (SP).
==========================================

How it works
------------

A SP handles authentication, by the use of an Identity Provider, and possibly 
attribute aggregation.
Both of these functions can be seen as parts of the normal Repoze.who
setup. Namely the Challenger, Identifier and MetadataProvider parts.

Normal for Repoze.who Identifier and MetadataProvider plugins are that
they place information they gather in environment variables. The convention is 
to place identity information in the environment under the key 
*repoze.who.identity*.
The information is structured as a dictionary with keys like *login*, and 
*repoze.who.userid*.

The SP follows this pattern and places the information gathered from 
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


The set up
----------

There are two configuration files you have to deal with, first the 
pySAML2 configuration file which you can read more about here 
:ref:`howto_config` and secondly the repoze.who configuration file.

The plugin configuration has the following arguments

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
    Debug state, and integer. Presently just on/off.
    
cache
    If no cache file is defined, a in memory cache will be used to 
    remember information received from IdPs and AAs. If a file name
    is given that file will be used for persistent storage of the cache.
    
An example::

    [plugin:saml2sp]
    use = s2repoze.plugins.sp:make_plugin
    saml_conf = sp.conf
    virtual_organization=urn:mace:umu.se:vo:it-enheten:cms
    rememberer_name = auth_tkt
    debug = 1

Once you have configured the plugin you have to tell the server to use the
plugin in different ingress and egress operations as specified in
`Middleware responsibilities <http://docs.repoze.org/who/narr.html>`_ ::

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
