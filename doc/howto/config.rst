.. _howto_config:

Configuration of pySAML2 entities
=================================

Whether you plan to run a pySAML2 Service Provider, Identity provider or an
attribute authority you have to configure it. The format of the configuration
file is the same disregarding which type of service you plan to run.
What differs is the directives.
Below you will find a list of all the used directives in alphabetic order.
The configuration is written as a python dictionary which means that the
directives are the toplevel keys.

.. note:: You can build metadata files directly from the configuration.
    The make_metadata.py script in the pySAML2 tools directory can do it 
    for you.
    
    
Configuration directives
------------------------

attribute_maps
^^^^^^^^^^^^^^

A simple key/value file that contains the unique name of attributes and
their friendly names separated by a blank, one attribute per line::

    urn:oid:2.5.4.4, surName
    urn:oid:2.5.4.42 givenName
    urn:oid:2.5.4.12 title
    urn:oid:0.9.2342.19200300.100.1.1 uid
    urn:oid:0.9.2342.19200300.100.1.3 mail
    urn:oid:1.3.6.1.4.1.5923.1.1.1.1 eduPersonAffiliation
    urn:oid:1.3.6.1.4.1.5923.1.1.1.7 eduPersonEntitlement

To be used by a SP or an IdP when translating back and forth between 
user friendly names and universally unique names.

cert_file
^^^^^^^^^

A file that contains CA certificates that the service will use in
HTTPS sessions to verify the server certificate. 
*cert_file* must be a PEM formatted certificate chain file.

debug
^^^^^

Whether debug information should be sent to the logfile.

entityid
^^^^^^^^

The globally unique identifier of the entity.

key_file
^^^^^^^^

*key_file* is the name of a PEM formatted file that contains the private key
of the service. This is presently used both to encrypt assertions and as
client key in a HTTPS session.

metadata
^^^^^^^^

Contains a list of places where metadata can be found. This can be either
a file accessible on the server the service runs on or somewhere on the net.::

    "metadata" : {
        "local": [
            "metadata.xml", "vo_metadata.xml"
            ],
        "remote": [
            "https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral&set=saml2"
            ],
    },

service
^^^^^^^

Which services the server will provide, those are combinations of "idp","sp" 
and "aa".
So if one server is supposted to be both SP and AA (attribute authority) then 
the configuration could look something like this::

    "service": {
        "aa":{
            "name" : "VO AA",
            "url": "http://localhost:8090/soap",
        },
        "sp":{
            "name" : "VO SP",
            "url" : "http://localhost:8090/sp",
        }
    },
    
There are two options common to all services: 'name' and 'url'. With the 
obvious meanings. 
There also exits special option for SPs namely: 'idp', 'optional_attributes'
and 'required_attributes'.
Both IdPs and AAs can have the option 'assertions' 

assertions (idp/aa)
"""""""""""""""""""

If the server is an IdP or and AA then there might be reasons to things
differently depending on who is asking, this is where that is specified.
The keys are 'default' and SP entity identifiers, default is used whenever
there is no entry for a specific SP.
An example might be::

    "assertions": {
        "default": {
            "lifetime": {"minutes":15},
            "attribute_restrictions": None # means all I have
        },
        "urn:mace:umu.se:saml:roland:sp": {
            "lifetime": {"minutes": 5},
            "attribute_restrictions":{
                 "givenName": None,
                 "surName": None,
            }
        }
    }
    
*lifetime* is the maximum amount of time before the information should be 
regarded as stale. In an Assertion this is represented in the NotOnOrAfter 
attribute.
By default there is no restrictions as to which attributes should be
return. Instead all the attributes and values that is gathered by the 
database backends will be returned if nothing else is stated.
In the example above the SP with the entityid "urn:mace:umu.se:saml:roland:sp" 
has an attribute restriction: only the attributes
'givenName' and 'surName' are to be returned. There is no limitations as to
what values on these attributes that can be returned.

If restrictions on values are deemed necessary those are represented by 
regular expressions.::

    "assertions": {
        "urn:mace:umu.se:saml:roland:sp": {
            "lifetime": {"minutes": 5},
            "attribute_restrictions":{
                 "mail": [".*\.umu\.se$"],
            }
        }
    }

Here only mailaddresses that ends with ".umu.se" will be returned.

idp (sp)
""""""""

Defines the set of IdPs that this SP can use. If there is a metadata loaded
then the value is expected to be a dictionary with entity identifiers as
keys and possibly the IdP url as values. If the url is not defined then an
attempt is made to learn it from the metadata.
A typical configuration would look something like this::

    "idp": {
        "urn:mace:umu.se:saml:roland:idp": None,
    },

In this case the SP has only one IdP it can use, a typical situation when
you are using SAML for services within one organization. At configuration
time the url of the IdP might not be know so the evaluation of it is left 
until a metadata file is present. If more than one IdP can be used then
the WAYF function (NOT IMPLEMENTED YET) would use the metadata file to 
find out the names for the different IdPs.
On the other hand if the SP only uses one specific IdP then the usage of
metadata file might be overkill so this construct can be used instead::

    "idp": {
        "" : "https://example.com/saml2/idp/SSOService.php",
    },

Since the user is immediately sent to the IdP the entity identifier of the IdP
is immaterial. In this case the key is expected to be the user friendly
name of the IdP.

There is a third choice and that is to leave the configuration blank, that
is an empty dictionary, in which case all the IdP present in the metadata
will be regarded as eligable services to use. ::

    "idp": {
    },

optional_attributes (sp)
""""""""""""""""""""""""

Attributes that this SP would like to receive from IdPs.

required_attributes (sp)
""""""""""""""""""""""""

Attributes that this SP demands to receive from IdPs.


subject_data
^^^^^^^^^^^^

The name of a shelve database where the map between a local identifier and 
a distributed identifier is kept.

xmlsec_binary
^^^^^^^^^^^^^

Presently xmlsec1 binaries are use for all the signing and encryption stuff.
This option defines where the binary is situatied.

virtual_organization
^^^^^^^^^^^^^^^^^^^^

Gives information about common identifiers for virtual_organizations::

    "virtual_organization" : {
        "urn:mace:example.com:it:tek":{
            "nameid_format" : "urn:oid:1.3.6.1.4.1.1466.115.121.1.15-NameID",
            "common_identifier": "umuselin",
        }
    },

Keys are identifiers for virtual organizations, the arguments per organization
is 'nameid_format' and 'common_identifier'. Usefull if all the IdPs and AAs
that are involved in a virtual organization has common attribute values
for users that are part of the VO.

Example
-------

We start with a simple Service provider configuration::

    {
        "entityid" : "urn:mace:example.com:saml:roland:sp",
        "service": {
            "sp":{
                "name" : "Rolands SP",
                "url" : "http://www.example.com:8087/",
                "required_attributes": ["surName", "givenName", "mail"],
                "optional_attributes": ["title"],
                "idp": {
                    "urn:mace:example.com:saml:roland:idp": None,
                },
            }
        },
        "key_file" : "./mykey.pem",
        "cert_file" : "./mycert.pem",
        "xmlsec_binary" : "/opt/local/bin/xmlsec1",
        "metadata" : { 
            "local": ["metadata.xml", "vo_metadata.xml"],
        },
        "attribute_maps": ["attribute.map"],
    }
