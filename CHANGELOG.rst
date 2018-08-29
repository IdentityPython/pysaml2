Changelog
=========

4.6.1 (2018-08-29)
------------------

- Allow multiple AttributeStatement tags per Assertion
- Raise ValueError for invalid attribute type
- Make NameID element optional
- tests: fix test that depended on actual datetime
- build: Set minimum build-tool version through pyproject.toml

4.6.0 (2018-08-07)
------------------

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

0.4.2 (2012-03-27)
------------------
- Add default attribute mappings

0.4.1 (2012-03-18)
------------------
- Auto sign authentication and logout requests following config options.
- Add backwards compatibility with ElementTree in python < 2.7.
- Fix minor bugs in the tests.
- Support one more nameid format.
