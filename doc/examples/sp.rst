.. _example_sp:

An extremly simple example of a SAML2 service provider.
=======================================================

How it works
------------

A SP works with authentication and possibly attribute aggregation.
Both of these functions can be seen as parts of the normal Repoze.who
setup. Namely the Challenger, Identifier and MetadataProvider parts.

Normal for Repoze.who Identifier and MetadataProvider plugins are that
they place information in environment variables. The convention is to place
identity information in environ["repoze.who.identity"].
This is a dictionary with keys like 'login', and 'repoze.who.userid'.

The SP follows this pattern and places the information gathered from 
the IdP that handled the authentication and possible extra information
received from attribute authorities in the above mentioned dictionary under
the key 'user'.

So in environ["repoze.who.identity"] you will find a dictionary with 
attributes and values, the attribute names used depends on what's returned
from the IdP/AA. If there exists both a name and a friendly name, for
instance, the friendly name is used as the key.

Setup
-----

I you look in the example/sp directory of the distribution you will see
the necessary files:

application.py 
    which is the web application. In this case it will just print the
    information provided by the IdP in a table.
    
sp_conf.py
    The SPs configuration 
    
who.ini
    The repoze.who configuration file
    
And then there are two files with certificates, mykey.pem with the private
certificate and mycert.pem with the public part.

I'll go through these step by step.

The application
---------------

Build to use the wsgiref's simple_server, which is fine for testing but
not for production.


SP configuration
----------------

The configuration is written as described in :ref:`howto_config`. It means among other
things that it's easily testable as to the correct syntax.

You can see the whole file in example/sp/sp_conf.py, here I will go through
it line by line::

        "service": ["sp"],

Tells the software what type of services the software are suppost to
supply. It is used to check for the 
completeness of the configuration and also when constructing metadata from
the configuration. More about that later. Allowed values are: "sp" 
(service provider), "idp" (identity provider) and "aa" (attribute authority).
::

        "entityid" : "urn:mace:example.com:saml:sp",
        "service_url" : "http://example.com:8087/",
        
The ID of the entity and the URL on which it is listening.::

        "idp_url" : "https://example.com/saml2/idp/SSOService.php",

Since this is a very simple SP it only need to know about one IdP, therefor there
is really no need for a metadata file or a WAYF-function or anything like that.
It needs the URL of the IdP and that's all.::

        "my_name" : "My first SP",
        
This is just for informal purposes, not really needed but nice to do::

        "debug" : 1,
        
Well, at this point in time you'd really like to have as much information
as possible as to what's going on, right ? ::

        "key_file" : "./mykey.pem",
        "cert_file" : "./mycert.pem",

The necessary certificates.::

        "xmlsec_binary" : "/opt/local/bin/xmlsec1",

Right now the software is built to use xmlsec binaries and not the python
xmlsec package. There are reasons for this but I won't go into them here.::

        "organization": {
            "name": "Example Co",
            #display_name
            "url":"http://www.example.com/",            
        },

Information about the organization that is behind this SP, only used when
building metadata. ::

        "contact": [{
            "given_name":"John",
            "sur_name": "Smith",
            "email_address": "john.smith@example.com",
            #contact_type
            #company
            #telephone_number
        }]

Another piece of information that only is matters if you build and distribute
metadata.

So, now to that part. In order to allow the IdP to talk to you you may have
to provide the one running the IdP with a metadata file.
If you have a SP configuration file similar to the one I've walked you
through here, but with your information. You can make the metadata file
by running the make_metadata script you can find in the tools directory. 

Change directory to where you have the configuration file and do ::

    make_metadata.py sp_conf.py > metadata.xml
    


Repoze configuration
--------------------

I'm not going through the INI file format here. You should read
`Middleware Responsibilities <http://static.repoze.org/whodocs/narr.html>`_ 
to get a good introduction to the concept.

The configuration of the pysaml2 part in the applications middleware are
first the special module configuration, namely::

    [plugin:saml2auth]
    use = s2repoze.plugins.sp:make_plugin
    saml_conf = sp_conf.py
    rememberer_name = auth_tkt
    debug = 1
    path_logout = .*/logout.*

Which contains a specification ("use") of which function in which module 
should be used to initialize the part. After that comes the name of the 
file ("saml_conf") that contains the PySaml2 configuration. The third line
("rememberer_name") points at the plugin that should be used to 
remember the user information.

After this, the plugin is referenced in a couple of places::

    [identifiers]
    plugins =
          saml2auth
          auth_tkt
          
    [authenticators]
    plugins = saml2auth

    [challengers]
    plugins = saml2auth

    [mdproviders]
    plugins = saml2auth

Which means that the plugin is used in all phases.

The application
---------------

Is as said before extremly simple. The only thing that is connected to
the PySaml2 configuration are at the bottom, namely where the server are.
You have to ascertain that this coincides with what is specified in the 
PySaml2 configuration. Apart from that there really are no thing in 
application.py that demands that you use PySaml2 as middleware. If you 
switched to using the LDAP or CAS plugins nothing would change in the 
application. In the application configuration yes! But not in the application.
And that is really how it should be done.

There is one assumption and that is that the middleware plugin that gathers
information about the user places the extra information in as value on the
"user" property in the dictionary found under the key "repoze.who.identity"
in the environment.
