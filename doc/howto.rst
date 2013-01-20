.. _howto:

How to use SAML2test
====================

:Release: |release|
:Date: |today|

Before you can use SAML2test, you must get it installed.
If you have not done so yet, read :ref:`install`.

When you want to test a SAML2 entity with this tool you need 3 things:

* A configuration of the tool, an example can be found in tests/config_file.py
* A metadata file representing the tool
* A configuration file that describes how to interact with the entity.
    The metadata for the entity is part of this file. More about this below.

Tool configuration
::::::::::::::::::

This is a normal PySAML2 configuration file. You can have more than one and
then chose which one to use at run time by supplying the test script with
an argument. If no configuration is explicitly chosen the default name is
**config_file.py** .

Interaction configuration file
::::::::::::::::::::::::::::::

The configuration is structured as a Python dictionary.
The keys are **entity_id**, **interaction** and **metadata**.

entity_id
.........

**entity_id** is really only necessary if there is more than one entity
represented in the metadata. If not provided and if the **metadata** only
describes one entity that entity's entityID is used.

interaction
...........

The really hard part is the **interaction** part. This is where the
the script is told how to fake that there is a human behind the keyboard.

It consists of a lists of dictionaries with the keys: **matches**,
**page-type** and **control**.

matches
-------

**matches** is used to identify a page or a form within a page.
There are four different things that can be used to match the form:

* url : The action url
* title : The title of the form, substring matching is used.
* content: Something in the form, again substring matching is used, and finally
* class:

Normally the front-end will pick out the necessary information by
using a users interaction with the entity. If you are running this
directly from the prompt then you have to provide the information.
You can build this information by using the fact that the script will
dump any page it doesn't know what to do with.

An example::


    {
        "matches": {
            "url": "http://localhost:8088/login",
            "title": 'IDP test login'
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "roland", "password": "dianakra"}
        }
    }

The action here is to set the control *login* to 'roland' and the control
*password* to 'dianakra' and then post the form.

Or if the server uses HTTP Post binding::

    {
        "matches": {
            "url": "http://localhost:8088/sso/redirect",
            "title": "SAML 2.0 POST"
        },
        "control": {
            "type": "response",
            "pick": {"form": {"action":"http://localhost:8088/acs"}}
        }
    },

Here the action is just to post the form, no information is added to the form.

page-type
---------

**page-type** is used to mark the page as *login* or *user-consent*.
This is used in specific conversation where one or the other is expected
in certain circumstances.

control
-------

**control** specifies what the script should enter where and which button
to press.

metadata
........

This is then the metadata for the entity to be tested. As noted previously
the metadata can actually describe more than one entity. In this case
the **entity_id** must be specified explicitly.

Running the script
::::::::::::::::::

Script parameters::

    $ saml2c.py --help
    usage: saml2c.py [-h] [-d] [-v] [-C CA_CERTS] [-J JSON_CONFIG_FILE] [-m] [-l]
                     [-c SPCONFIG]
                     [oper]

    positional arguments:
      oper                 Which test to run

    optional arguments:
      -h, --help           show this help message and exit
      -d                   Print debug information
      -v                   Print runtime information
      -C CA_CERTS          CA certs to use to verify HTTPS server certificates, if
                           HTTPS is used and no server CA certs are defined then
                           no cert verification will be done
      -J JSON_CONFIG_FILE  Script configuration
      -m                   Return the SP metadata
      -l                   List all the test flows as a JSON object
      -c SPCONFIG          Configuration file for the SP


To see what tests are available::

    $ saml2c.py -l
    [
        {
            "id": "basic-authn",
            "descr": "AuthnRequest using HTTP-redirect",
            "name": "Absolute basic SAML2 AuthnRequest"
        }, {
            "id": "basic-authn-post",
            "descr": "AuthnRequest using HTTP-POST",
            "name": "Basic SAML2 AuthnRequest using HTTP POST"
        }, {
            "id": "log-in-out",
            "descr": "AuthnRequest using HTTP-redirect followed by a logout",
            "name": "Absolute basic SAML2 log in and out"
        }, {
            "id": "authn-assertion_id_request",
            "descr": "AuthnRequest followed by an AssertionIDRequest",
            "name": "AuthnRequest and then an AssertionIDRequest"
        }, {
            "id": "authn-authn_query",
            "descr": "AuthnRequest followed by an AuthnQuery",
            "name": "AuthnRequest and then an AuthnQuery"
        }
    ]

A typical command would then be (reformated to be more readable)::

    $ saml2c.py -J localhost.json 'log-in-out'
    {
        "status": 1,
        "tests": [
            {
                "status": 1,
                "id": "check-saml2int-metadata",
                "name": "Checks that the Metadata follows the profile"
            }, {
                "status": 1,
                "id": "check-http-response",
                "name": "Checks that the HTTP response status is within the 200 or 300 range"
            }, {
                "status": 1,
                "id": "check-http-response",
                "name": "Checks that the HTTP response status is within the 200 or 300 range"
            }, {
                "status": 1,
                "id": "check-http-response",
                "name": "Checks that the HTTP response status is within the 200 or 300 range"
            }, {
                "status": 1,
                "id": "check-saml2int-attributes",
                "name": "Any <saml2:Attribute> elements exchanged via any SAML 2.0 messages, assertions, or metadata MUST contain a NameFormat of urn:oasis:names:tc:SAML:2.0:attrname-format:uri."
            }, {
                "status": 1,
                "id": "verify-content",
                "name": "Basic content verification class, does required and max/min checks"
            }, {
                "status": 1,
                "id": "check-logout-support",
                "name": ""
            }, {
                "status": 1,
                "id": "verify-content",
                "name": "Basic content verification class, does required and max/min checks"
            }, {
                "status": 1,
                "id": "verify-logout",
                "name": ""
            }
        ],
        "id": "log-in-out"
    }

First you have the status for the whole test was '1', which is the same as OK,
for this test run.
The used status code are:

0. INFORMATION
1. OK
2. WARNING
3. ERROR
4. CRITICAL
5. INTERACTION

Then you get all the separate sub tests that has been run during the
conversation.

If things go wrong you will get a trace log dump to stderr.
If all goes well but you still want to see all the interaction you can do::

    $ saml2c.py -J localhost.json -d 'basic-authn' 2> tracelog
    < same output as above >
    $ cat tracelog
    0.017364 SAML Request: <?xml version='1.0' encoding='UTF-8'?>
    <ns0:AuthnRequest xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="http://localhost:8087/acs/redirect" Destination="http://localhost:8088/sso/redirect" ID="id-8c9a57670d1bc374898297702285ba74" IssueInstant="2013-01-20T09:02:44Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" ProviderName="SAML2 test tool" Version="2.0"><ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:8087/sp.xml</ns1:Issuer><ns0:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" /></ns0:AuthnRequest>
    0.036136 <-- REDIRECT TO: http://localhost:8088/login?came_from=%2Fsso%2Fredirect&key=331035cf0e26cdefc15759582e34994ac8e54971
    0.040084 <-- CONTENT:


    <html>
    <head><title>IDP test login</title>
        <link rel="stylesheet" type="text/css" href="/css/main.css" media="screen">
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    </head>
    <body>
        <div class="header">
            <h1><a href="/">Login</a></h1>
        </div>


    <h1>Please log in</h1>
    <p class="description">
        To register it's quite simple: enter a login and a password
    </p>

    <form action="/verify" method="post">
        <input type="hidden" name="key" value="331035cf0e26cdefc15759582e34994ac8e54971"/>
        <input type="hidden" name="came_from" value="/sso/redirect"/>

        <div class="label">
            <label for="login">Username</label>
        </div>
        <div>
            <input type="text" name="login" value=""/><br/>
        </div>

        <div class="label">
            <label for="password">Password</label>
        </div>
        <div>
            <input type="password" name="password"
                   value=""/>
        </div>

        <input class="submit" type="submit" name="form.submitted" value="Log In"/>
    </form>

    <div>
            <div class="footer">
                <p>&#169; Copyright 2011 Ume&#229; Universitet &nbsp;</p>
            </div>
        </div>
    </body>
    </html>

    0.042697 >> login <<
    0.042715 <-- FUNCTION: select_form
    0.042744 <-- ARGS: {u'set': {u'login': u'roland', u'password': u'dianakra'}, u'type': u'form', 'location': 'http://localhost:8088/login?came_from=%2Fsso%2Fredirect&key=331035cf0e26cdefc15759582e34994ac8e54971', '_trace_': <idp_test.Trace object at 0x101e79750>, 'features': None}
    0.055864 <-- REDIRECT TO: http://localhost:8088/sso/redirect?id=zLvrjojPLLgbnDyq&key=331035cf0e26cdefc15759582e34994ac8e54971

    ... and so on ...
