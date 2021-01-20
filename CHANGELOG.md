# Changelog


## 6.5.0 (2021-01-20) - Security release

- Fix processing of invalid SAML XML documents - [CVE-2021-21238]
- Fix unspecified xmlsec1 key-type preference - [CVE-2021-21239]
- Add more tests regarding XSW attacks
- Add XML Schemas for SAML2 and common extensions
- Fix the XML parser to not break on ePTID AttributeValues
- Fix the initialization value of the return_addrs property of the StatusResponse object
- Fix SWAMID entity-category policy regarding eduPersonTargetedID
- data: use importlib to load package data (backwards compatibility through the importlib_resources package)
- docs: improve the documentation for the signing_algorithm and digest_algorithm options
- examples: fix the logging configuration of the example-IdP
- tests: allow tests to pass on 32bit systems by properly choosing dates in test XML documents
- tests: improvements on the generation of response and assertion objects
- tests: expand tests on python-3.9 and python-3.10-dev


## 6.4.1 (2020-12-08)

- Indicate minimum required python version during installation


## 6.4.0 (2020-12-08)

- Add preferred signing and digest algorithms configuration options:
    Use the new configuration options `signing_algorithm` and `digest_algorithm`.
- Fix signed SAML AuthnRequest and Response when HTTP-Redirect binding is used:
    Previously, the query params `Signature` and `SigAlg` were not included.
- Ignore duplicate RequestedAttribute entries when filtering attributes
- tests: Avoid reuse of old test data files


## 6.3.1 (2020-11-11)

- Fix extraction of RegistrationInfo when no information is available
- Fix http_info struct to include status-code


## 6.3.0 (2020-10-30)

- Allow to specify policy configurations based on the registration authority.
- Add new configuration option `logout_responses_signed` to sign logout responses.
- When available and appropriate return the ResponseLocation along with the Location
  attribute.
- Always use base64.encodebytes; base64.encodestring has been dropped.
- Examples: fix IdP example that was outputing debug statements on stdout that became
  part of its metadata.
- CI/CD: Use Ubuntu bionic as the host to run the CI/CD process.
- CI/CD: Pre-releases are now available on [test.pypi.org][pypi.test.pysaml2]. Each
  commit/merge on the master branch autotically creates a new pre-release. To install a
  prelease, run:

  ```sh
  $ pip install -U -i https://test.pypi.org/simple --extra-index-url https://pypi.org/simple pysaml2
  ```

  [pypi.test.pysaml2]: https://test.pypi.org/project/pysaml2/#history


## 6.2.0 (2020-10-05)

- Fix the generated xsd:ID format for EncryptedData and EncryptedKey elements
- Set the default value for the NameFormat attribute to unspecified when parsing
- Support arbitrary entity attributes
- Replace all asserts with proper checks
- Allow request signing in artifact2message
- Support logging configuration through the python logger
- Fix wrong identifiers for ecdsa algos
- Fix automatic inversion of attribute map files
- Factor out common codepaths in attribute_converter
- Remove uneeded exception logging
- Docs: Update configuration options documentation
- Examples: Support both str and bytes in SAML requests on the example idp
- Examples: Update to key generation to 2048 bits


## 6.1.0 (2020-07-10)

- Fix signed logout requests flag


## 6.0.0 (2020-07-10)

- Differentiate between metadata NameIDFormat and AuthnRequest NameIDPolicy Format
  - Users using `name_id_format` to set the `<NameIDPolicy Format="...">` attribute now
    need to use the new configuration option `name_id_policy_format`.
- Fix documentation formatting


## 5.4.0 (2020-07-10)

- Fix generation of signed metadata
- Add attribute mappings used by SwedenConnect (DIGG, INERA and PKIX specifications)
- Update SWAMID entity category
- Document the `additional_cert_files` configuration option


## 5.3.0 (2020-06-25)

- Fix check for nameid_format set to the string "None" in the configuration


## 5.2.0 (2020-06-23)

- Fix presence of empty eIDAS RequestedAttributes element on AuthnRequest
- Refactor create_authn_request method to be easier to reason about
- Fix NameIDPolicy checks for allowed Format and allowCreate values


## 5.1.0 (2020-06-09)

- support eIDAS RequestedAttributes per AuthnRequest
- fix xmlsec1 --id-attr configuration option value
- do not remove existing disco URL query params
- load attribute maps in predictable order
- better error message when AudienceRestriction does not validate
- always use base64.encodebytes instead of base64.encodestring
- update the eIDAS attribute mapping for legal person
- fix py_compile warnings
- fix pylint errors and warnings
- various small fixes
- add Python3.8 as supported
- tests: fix validity dates
- docs: document default value for 'want_response_signed'


## 5.0.0 (2020-01-13) - Security release

- Fix XML Signature Wrapping (XSW) vulnerabilities - [CVE-2020-5390]
- Add freshness period feature for MetaDataMDX
- Fix bug in duration calculation in time_util library
- Fix ipv6 validation to accommodate for addresses with brackets
- Fix xmlsec temporary files deletions
- Add method to get supported algorithms from metadata
- Add mdstore method to extract assurance certifications
- Add mdstore method to extract contact_person data
- Add attribute mappings from the Swiss eduPerson Schema
- Make AESCipher and Fernet interfaces compatible
- Remove deprecated saml2.aes module
- Remove deprecated saml2.extensions.ui module
- Replace deprecated mongodb operations
- Rename ToOld error to TooOld
- Fix pytest warnings
- Mock tests that need a network connection
- Start dropping python2 support


## 4.9.0 (2019-11-03)

- Add mdstore methods to extract mdui uiinfo elements
- Add attribute mapping for umbrellaID attributes
- Fix logic error in pick_binding method for Entity class
- Validate the audience of assertions regardless of a response being unsolicited
- Fix PKCS_9 saml_url prefix
- docs: Fix warnings from docs generation
- docs: Update release instructions regarding branch releases
- docs: Fix list formatting on IdP example page
- docs: Update pysaml2 options doc with `name_id_format_allow_create`
- misc: fix various typos


## 4.8.0 (2019-07-08)

- Refactor the way ForceAuthn is set: check for "true" and "1"
- Allow to set NameQualifier and SPNameQualifier attributes for ePTID
- Parse assertions with Holder-of-Key profile
- Add created_at timestamps to all mongodb documents
- Look for existing persistent id's before creating new ones
- Do not add AllowCreate property for default transient NameID
- Enable entity category import from module search path
- Add SAML subject identifier attributes to saml2_uri attributemap
- Fix deprecation warning regarding the cgi module - use the html module when available
- Misc minor improvements
- tests: Be compatible with latest pytest
- tests: Make tests pass after 2024
- tests: Add py37 as a test target
- docs: Correct instructions to run tests
- docs: Fix misc typos
- examples: Set cherrypy version explicitly


## 4.7.0 (2019-04-02)

- Add support for MDQ signature verification
- Raise XmlsecError if xmlsec1 operations do not succeed
- Handle non standard response error status codes correctly
- Remove the hardcoded warning filter; pass -Wd to the python
  interpreter to enable warnings
- Remove the python-future dependency and only use six
- Minor python2 and python3 compatibility fixes
  (unicode strings and example code)
- Minor documentation fixes


## 4.6.5 (2018-12-04)

- Fix for response status error case handling (introduced in v4.6.5)
- Added assurance-certification support
- Added entity-category-support support

Thanks @rectalogic @skanct


## 4.6.4 (2018-11-22)

- Make use of the sign argument to entity.Entity::apply_binding when binding is
  HTTP-Redirect. Reminder: use [authn_requests_signed configuration option][0]
  to indicate that Authentication Requests sent by the SP must be signed
- Add want_assertions_or_response_signed configuration option - see
  [documentation][1] about the introduced behaviour
- Fix code for idp and sp examples
- Do not require assertion conditions
- Fix response encoding format
- Various code improvements for config, sigver, client_base, client,
  ecp_client, ecp, s2repoze and entity modules
- Support non-ascii attribute values for encryption and decryption

Thanks to @johanlundberg @skoranda @yuqing0708 @erakli

  [0]: https://github.com/IdentityPython/pysaml2/blob/master/docs/howto/config.rst#authn-requests-signed
  [1]: https://github.com/IdentityPython/pysaml2/blob/master/docs/howto/config.rst#want-assertions-or-response-signed


## 4.6.3 (2018-10-08)

Do not map between attribute FriendlyName and attribute Name when no
attributemaps are provided.

## 4.6.2 (2018-09-06)

Refactor AttributeValueBase::set_text method.

- set_text is doing too many things. At least the structure is a bit cleaner;
  though, still complex.
- set_text will set the type if no type has been set.
- set_text should not modify the type if it has already been set,
- set_text should not depend on the type's namespace.
- set_text should not interfere with the 'anyType' type.
- set_text will raise a ValueError if the value cannot be represented by the
  type.
- set_text will raise a ValueError if the type is unknown.

## 4.6.1 (2018-08-29)

- Allow multiple AttributeStatement tags per Assertion
- Raise ValueError for invalid attribute type
- Make NameID element optional
- tests: fix test that depended on actual datetime
- build: Set minimum build-tool version through pyproject.toml

## 4.6.0 (2018-08-07) - Security release

- Allow configuration and specification of id attribute name
- Retrieve SLO endpoint by the appropriate service type
- Deprecate AESCipher and aes.py module
- Add saml2.cryptography module
- Always generate a random IV for AES operations / Address CVE-2017-1000246
- Remove unused and broken RSA code
- Add more nameid-format definitions
- Remove invalid nameid-format
- Retrieve pacakge version from pkg_resources
- Fully replace Cryptodome library with cryptography
- Fix SSRF caused by URI attribute of Reference element
- Omit relay state in HTTP-POST response when empty
- Fix eidas natural person attribute URIs
- Add eidas attributes for legal person to saml2_uri attributemap
- Fix deprecation and resource warnings.
- Fix date format to show month, not minutes
- Fix typos
- s2repoze: Define session_info variable before use
- s2repoze: Correctly pull the SAMLRequest from Redirect LogoutRequests
- s2repoze: Include SCRIPT_NAME when checking whether current URL is a logout endpoint
- tests: Document and test all supported Python versions
- tests: Generate and upload coverage reports to codecov
- tests: Include dependencies information in test report
- tests: Run tests in verbose mode
- tests: Clean up unclosed files causing ResourceWarnings
- build: Set minimal version for cryptography package
- build: Set the correct version in the docs
- build: Update build manifest to include the correct files
- build: Switch from setup.py to setup.cfg
- docs: Add editorconfig file with basic rules
- docs: Update gitignore file
- docs: Remove downloads badge as it is no longer available
- docs: Update all pypi.python.org URLs to pypi.org
- docs: Updated license and renamed the file.
- examples: Do not request a signed response - backwards compatibility
- examples: Fix wsgiserver usage for example sp
- examples: Fix cherrypy.wsgiserver usage

## 0.4.2 (2012-03-27)

- Add default attribute mappings

## 0.4.1 (2012-03-18)

- Auto sign authentication and logout requests following config options.
- Add backwards compatibility with ElementTree in python < 2.7.
- Fix minor bugs in the tests.
- Support one more nameid format.


  [CVE-2017-1000246]: https://github.com/advisories/GHSA-cq94-qf6q-mf2h
  [CVE-2020-5390]: https://github.com/advisories/GHSA-qf7v-8hj3-4xw7
  [CVE-2021-21238]: https://github.com/IdentityPython/pysaml2/security/advisories/GHSA-f4g9-h89h-jgv9
  [CVE-2021-21239]: https://github.com/IdentityPython/pysaml2/security/advisories/GHSA-5p3x-r448-pc62
