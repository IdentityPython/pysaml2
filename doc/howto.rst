.. _howto:

How to use SAML2test
====================

:Release: |release|
:Date: |today|

Before you can use SAML2test, you must get it installed.
If you have not done so yet, read `Install <install.rst>`_.

When you want to test a SAML2 entity with this tool you need following things:

#. The Test Driver Configuration, an example can be found in tests/idp_test/config.py
#. Attribute Maps mapping URNs, OIDs and friendly names
#. Key files for the test tool
#. A metadata file representing the tool
#. The Test Target Configuration file describes how to interact with the entity to be tested.  The metadata for the entity is part of this file. An example can be found in tests/idp_test/test_target_config.py.

These files should be stored outside the saml2test package to have a clean separation between the package and a particular test configuration. To create a directory for the configuration files copy the saml2test/tests including its contents.


(1) Test Driver Configuration
:::::::::::::::::::::::::::::

This is a normal `PySAML2 configuration file <http://pythonhosted.org/pysaml2/howto/config.html>`_. You can have more than one and then chose which one to use at run time by supplying the test script with an argument. If no configuration is explicitly provided than **tests/ipd_test/config.py** is provided as a default.

This configuration mostly contains the test tool’s metadata structured as a Python dictionary. It doesn't vary a lot between testing different IdPs, except for the value of BASE, and optionally these control options:

In addition to the configuration directives documented for the PySAML2 configuration file these may be used:

accepted_time_diff
..................
Default: 60

logger
......
Specify the logging options for the test run.

only_use_keys_in_metadata
.........................
If true it ignore the validation path of signing keys. As of V0.4.0, this does not apply to TLS keys (which does not conform to [SAML MetaIOP].
If false it does validate the signing certificate against the default CA keys of pysaml2. Add the directory to python path, like:
export PYTHONPATH=/some_path/saml2test.conf   # Remember: no trailing slash in PYTHONPATH

secret
......
Not being used currently

You could also change organization and contact information if you'd like to.

(2) Attribute Mapping
:::::::::::::::::::::
Attributes that may be contained in a SAML assertion must be defined in the attribute mapping as documented in the `PySAML2 config guide <http://pythonhosted.org/pysaml2/howto/config.html#attribute-map-dir>`_. If the ‚to‘ and ‚fro‘ mappings are exactly the same just one of them is required. But sometimes it is necessary to have both "to" and "from" because translation isn't symmetric. Like having "sn" and "surname" mapping to the same urn.

You may copy the default mapping into your test configuration directory:
cp -pr saml2test/tests/attributemaps .

There must be one file per attribute namespace, i.e. attrname-format:basic needs to go into basic.py, and attrname-format:uri needs to go into saml_uri.py.

(3) Key Files
:::::::::::::
The test tool’s metadata needs key files, both a private key and a certificate. The default files are provided in same2test/tests/keys as:
mykey.pem
mycert.pem
To change file names, the references in the Tool Configuration need be be changed as well.

(4) Test Tool Metadata
::::::::::::::::::::::
The test tool’s metadata is generated from the contents of the Tool Configuration, e.g.:
make_metadata.py config.py > testdrv_metadata.xml

The resulting SAML2 metadata needs to be imported to the test target.


(5) Test Target Configuration File
::::::::::::::::::::::::::::::::::
This configuration is contained in the "info" Python dictionary.

The keys are:

entity_id
.........

**entity_id** is really only necessary if there is more than one entity
represented in the metadata. If not provided and if the **metadata** only
describes one entity that entity's entityID is used.

start_page
..........

URL for the initial request the test driver issues when executing an SP test.

args
....

Contains a Python dictionary controlling some aspects of an Authnentication Response" with following structure::

    "AuthnResponse": {
        "sign_assertion": True,
        "authn":  {"class_ref": AUTHN_PASSWORD_PROTECTED, # Authentication Context Class Reference
                   "authn_auth": "http://authnservice.example.com/login"}  # Authenticating Authority
    },

identity
........

Contains a list of key-value pairs with attribute names and values, that the embedded IDP will include in assertions.
Attribute Names in this context are friendly names, not URNs/OIDs.
To obtain these attributes from the IDP there are three options:
    #. include an EntityCategory in the EntityDescriptor of the SP. The EntityCategory must be defined in pysaml2.
    #. include RequestedAttributes in the EntityDescriptor of the SP.
    #. include RequestedAttributes in the AuthnRequest.
These methods work additive. Attributes must be registered in the attribute map.

userid
......

The UserID used as a base for the Assertion/Subject/NameID.


interaction
...........

The really hard part is the **interaction** part. This is where the
the script is told how to fake that there is a human behind the keyboard.

It consists of a lists of dictionaries with the keys: **matches**,
**page-type** and **control**.

The idea is to use **matches** to **activated** a corresponding set of **controls**.

matches
-------

**matches** is used to identify a page or a form within a page.
There are four different things that can be used to match the page:

* url : The action url
* title : The title of the page, substring matching is used.
* content: Something in the page, again substring matching is used, and finally
* class: (currently not used)

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

Running the script testing an IDP
:::::::::::::::::::::::::::::::::

Synopsis::

    $ idp_testdrv.py --help
    usage: idp_testdrv.py [-h] [-d] [-H] [-C CA_CERTS] [-J TT_CONFIG_FILE] [-m] [-l]
                     [-c TD_CONFIG]
                     [oper]

    positional arguments:
      oper                 Which test to run

    optional arguments:
      -C CA_CERTS            CA certs to use to verify HTTPS server certificates, if
                             HTTPS is used and no server CA certs are defined then
                             no cert verification will be done. For a generic validation you may use the ca_bundle.crt
                             file that comes with Mozilla.
      -c TD_CONFIG, --config Test driver configuration module at the current directory or the path specified
                             with the -P option. Do not use relative paths or the .py filename extension
      -d, --debug            Print debug information to stderr
      -H, --prettyprint      Status output as human readable python dictionary
      -h, --help             show this help message and exit
      -J TT_CONFIG_FILE      Test target configuration in JSON format
      -L, --log              Print HTTP log information # TODO: update documentation
      -l, --list             List all the test operations as a JSON object
      -m, --metadata         Return the SP metadata
      -O, --operations       Operations module (generated from Repository as idp_saml2base.py)
      -P, --configpath       Path to the configuration file for the SP
      -t, --testpackage      Module describing tests (e.g. idp_samlbase.py generated from repository)
      -Y, --pysamllog        Print pySAML2 logs to stderr

    Output on stdout is a JSON dicitionary containing the test summary (overwrite with -H).
    Output to stderr is the log file


Remember to generate the test target's config file in json format from python.


Running the script testing an SP
::::::::::::::::::::::::::::::::

Synopsis::

    $ sp_testdrv.py --help
    usage: sp_testdrv.py [-h] [-H] [-d] [-C CA_CERTS] [-J TT_CONFIG_FILE] [-m] [-l] [-c TD_CONFIG] [oper]

    positional arguments:
      oper                 Which test to run (mandatory except for options -h, -l and -m)

    optional arguments:
      -C CA_CERTS           CA certs to use to verify HTTPS server certificates, if
                            HTTPS is used and no server CA certs are defined then
                            no cert verification will be done. For a generic validation you may use the ca_bundle.crt
                            file that comes with Mozilla.
      -c TD_CONFIG, --config Test driver configuration module at the current directory or the path specified
                            with the -P option. Do not use relative paths or filename extension
      -d, --debug           Print debug information to stderr
      -h, --help            show this help message and exit
      -H, --prettyprint      Status output as human readable python dictionary
      -J TT_CONFIG_FILE     Test target configuration in JSON format
      -k                    Print HTTP response contents into separate files
      -L, --log             Path to the logfile directory
      -l, --list            List all the test flows as a JSON object
      -m, --metadata        Return the SP metadata
      -O, --operations      Operations module (generated from Repository as idp_saml2base.py)
      -P, --configpath      Path to the configuration file for the SP
      -t, --testpackage     Module describing tests (e.g. sp_testbase.py generated from repository)
      -Y, --pysamllog       Print pySAML2 logs to stderr

    Output on stdout is a JSON dicitionary containing the test summary (overwrite with -H).
    Output to stderr is the log file

Examples
::::::::

To see what tests are available::

    $ idp_testdrv.py -l
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

    $ idp_testdrv.py -J localhost.json 'log-in-out'
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
2. WARNING  (the test target's behavior is according to the spec but may not be as expected )
3. ERROR (the test target's behavior is not according to the spec)
4. CRITICAL (the test driver threw an exception)
5. INTERACTION (interaction needed but matching rule does not match - applies to final page in SP test as well)

Then you get all the separate sub tests that has been run during the
conversation.

If things go wrong you will get a trace log dump to stderr.
If all goes well but you still want to see all the interaction you can do::

    $ idp_testdrv.py -J localhost.json -d 'basic-authn' 2> tracelog
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

