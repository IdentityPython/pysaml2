#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for saml2.saml"""

__author__ = 'tmatsuo@sios.com (Takashi MATSUO)'

import unittest
try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree
import saml2
from saml2 import saml, test_data, ds_test_data
import xmldsig as ds

class NameIDTest(unittest.TestCase):

    def setUp(self):
        self.name_id = saml.NameID()

    def testEmptyExtensionsList(self):
        """Test if NameID has empty extensions list"""
        self.assert_(isinstance(self.name_id.extension_elements, list))
        self.assert_(len(self.name_id.extension_elements) == 0)

    def testFormatAttribute(self):
        """Test for Format attribute accessors"""
        self.name_id.format = saml.NAMEID_FORMAT_EMAILADDRESS
        self.assert_(self.name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS)
        self.assert_(len(self.name_id.extension_elements) == 0)
        new_name_id = saml.NameIDFromString(self.name_id.ToString())
        self.assert_(len(new_name_id.extension_elements) == 0)

        self.name_id.extension_elements.append(saml2.ExtensionElement(
            'foo', text='bar'))
        self.assert_(len(self.name_id.extension_elements) == 1)
        self.assert_(self.name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS)

    def testNameIDText(self):
        """Test text value of NameID element"""
        self.name_id.text = "tmatsuo@sios.com"
        self.assert_(self.name_id.text == "tmatsuo@sios.com")
        
    def testSPProvidedID(self):
        """Test for SPProvidedID attribute accessors"""
        self.name_id.sp_provided_id = "provided id"
        self.assert_(self.name_id.sp_provided_id == "provided id")

    def testEmptyNameIDToAndFromStringMatch(self):
        """Test NameIDFromString() with empty NameID"""
        string_from_name_id = self.name_id.ToString()
        new_name_id = saml.NameIDFromString(string_from_name_id)
        string_from_new_name_id = new_name_id.ToString()
        self.assert_(string_from_name_id == string_from_new_name_id)

    def testNameIDToAndFromStringMatch(self):
        """Test NameIDFromString() with data"""
        self.name_id.format = saml.NAMEID_FORMAT_EMAILADDRESS
        self.name_id.text = "tmatsuo@sios.com"
        self.name_id.name_qualifier = "name_qualifier"
        self.name_id.sp_name_qualifier = "sp_name_qualifier"
        string_from_name_id = self.name_id.ToString()
        new_name_id = saml.NameIDFromString(string_from_name_id)
        self.assert_(new_name_id.name_qualifier == "name_qualifier")
        self.assert_(new_name_id.sp_name_qualifier == "sp_name_qualifier")
        string_from_new_name_id = new_name_id.ToString()
        self.assert_(string_from_name_id == string_from_new_name_id)

    def testExtensionAttributes(self):
        """Test extension attributes"""
        self.name_id.extension_attributes['hoge'] = 'fuga'
        self.name_id.extension_attributes['moge'] = 'muga'
        self.assert_(self.name_id.extension_attributes['hoge'] == 'fuga')
        self.assert_(self.name_id.extension_attributes['moge'] == 'muga')
        new_name_id = saml.NameIDFromString(self.name_id.ToString())
        self.assert_(new_name_id.extension_attributes['hoge'] == 'fuga')
        self.assert_(new_name_id.extension_attributes['moge'] == 'muga')

    def testNameIDFromString(self):
        """Test NameIDFromString() using test data"""
        name_id = saml.NameIDFromString(test_data.TEST_NAME_ID)
        self.assert_(name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS)
        self.assert_(name_id.text.strip() == "tmatsuo@sios.com")
        self.assert_(name_id.sp_provided_id == "sp provided id")


class IssuerTest(unittest.TestCase):

    def setUp(self):
        self.issuer = saml.Issuer()

    def testIssuerToAndFromString(self):
        """Test IssuerFromString()"""
        self.issuer.text = "http://www.sios.com/test"
        self.issuer.name_qualifier = "name_qualifier"
        self.issuer.sp_name_qualifier = "sp_name_qualifier"
        new_issuer = saml.IssuerFromString(self.issuer.ToString())
        self.assert_(self.issuer.text == new_issuer.text)
        self.assert_(self.issuer.name_qualifier == new_issuer.name_qualifier)
        self.assert_(self.issuer.sp_name_qualifier == new_issuer.sp_name_qualifier)
        self.assert_(self.issuer.extension_elements ==
                                 new_issuer.extension_elements)

    def testUsingTestData(self):
        """Test IssuerFromString() using test data"""
        issuer = saml.IssuerFromString(test_data.TEST_ISSUER)
        self.assert_(issuer.text.strip() == "http://www.sios.com/test")
        new_issuer = saml.IssuerFromString(issuer.ToString())
        self.assert_(issuer.text == new_issuer.text)
        self.assert_(issuer.extension_elements ==
                                 new_issuer.extension_elements)


class SubjectLocalityTest(unittest.TestCase):

    def setUp(self):
        self.subject_locality = saml.SubjectLocality()

    def testAccessors(self):
        """Test for SubjectLocality accessors"""
        self.subject_locality.address = "127.0.0.1"
        self.subject_locality.dns_name = "localhost"
        self.assert_(self.subject_locality.address == "127.0.0.1")
        self.assert_(self.subject_locality.dns_name == "localhost")
        new_subject_locality = saml.SubjectLocalityFromString(
            self.subject_locality.ToString())
        self.assert_(new_subject_locality.address == "127.0.0.1")
        self.assert_(new_subject_locality.dns_name == "localhost")

    def testUsingTestData(self):
        """Test SubjectLocalityFromString() using test data"""

        subject_locality = saml.SubjectLocalityFromString(
            test_data.TEST_SUBJECT_LOCALITY)
        self.assert_(subject_locality.address == "127.0.0.1")
        self.assert_(subject_locality.dns_name == "localhost")
        
        new_subject_locality = saml.SubjectLocalityFromString(
            subject_locality.ToString())
        self.assert_(new_subject_locality.address == "127.0.0.1")
        self.assert_(new_subject_locality.dns_name == "localhost")
        self.assert_(subject_locality.ToString() ==
                                 new_subject_locality.ToString())


class AuthnContextClassRefTest(unittest.TestCase):

    def setUp(self):
        self.authn_context_class_ref = saml.AuthnContextClassRef()

    def testAccessors(self):
        """Test for AuthnContextClassRef accessors"""
        self.authn_context_class_ref.text = (
            "http://www.sios.com/authnContextClassRef")
        self.assert_(self.authn_context_class_ref.text ==
                                 "http://www.sios.com/authnContextClassRef")
        new_authn_context_class_ref = saml.AuthnContextClassRefFromString(
            self.authn_context_class_ref.ToString())
        self.assert_(new_authn_context_class_ref.text ==
                                 "http://www.sios.com/authnContextClassRef")

        self.assert_(self.authn_context_class_ref.ToString() ==
                                 new_authn_context_class_ref.ToString())

    def testUsingTestData(self):
        """Test AuthnContextClassRefFromString() using test data"""
        authn_context_class_ref = saml.AuthnContextClassRefFromString(
            test_data.TEST_AUTHN_CONTEXT_CLASS_REF)
        self.assert_(authn_context_class_ref.text.strip() ==
                                 "http://www.sios.com/authnContextClassRef")


class AuthnContextDeclRefTest(unittest.TestCase):

    def setUp(self):
        self.authn_context_decl_ref = saml.AuthnContextDeclRef()

    def testAccessors(self):
        """Test for AuthnContextDeclRef accessors"""
        self.authn_context_decl_ref.text = (
            "http://www.sios.com/authnContextDeclRef")
        self.assert_(self.authn_context_decl_ref.text ==
                                 "http://www.sios.com/authnContextDeclRef")
        new_authn_context_decl_ref = saml.AuthnContextDeclRefFromString(
            self.authn_context_decl_ref.ToString())
        self.assert_(new_authn_context_decl_ref.text ==
                                 "http://www.sios.com/authnContextDeclRef")

        self.assert_(self.authn_context_decl_ref.ToString() ==
                                 new_authn_context_decl_ref.ToString())

    def testUsingTestData(self):
        """Test AuthnContextDeclRefFromString() using test data"""
        authn_context_decl_ref = saml.AuthnContextDeclRefFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL_REF)
        self.assert_(authn_context_decl_ref.text.strip() ==
                                 "http://www.sios.com/authnContextDeclRef")


class AuthnContextDeclTest(unittest.TestCase):

    def setUp(self):
        self.authn_context_decl = saml.AuthnContextDecl()

    def testAccessors(self):
        """Test for AuthnContextDecl accessors"""
        self.authn_context_decl.text = (
            "http://www.sios.com/authnContextDecl")
        self.assert_(self.authn_context_decl.text ==
                                 "http://www.sios.com/authnContextDecl")
        new_authn_context_decl = saml.AuthnContextDeclFromString(
            self.authn_context_decl.ToString())
        self.assert_(new_authn_context_decl.text ==
                                 "http://www.sios.com/authnContextDecl")

        self.assert_(self.authn_context_decl.ToString() ==
                                 new_authn_context_decl.ToString())

    def testUsingTestData(self):
        """Test AuthnContextDeclFromString() using test data"""
        authn_context_decl = saml.AuthnContextDeclFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL)
        self.assert_(authn_context_decl.text.strip() ==
                                 "http://www.sios.com/authnContextDecl")


class AuthenticatingAuthorityTest(unittest.TestCase):

    def setUp(self):
        self.authenticating_authority = saml.AuthenticatingAuthority()

    def testAccessors(self):
        """Test for AuthenticatingAuthority accessors"""
        self.authenticating_authority.text = (
            "http://www.sios.com/authenticatingAuthority")
        self.assert_(self.authenticating_authority.text ==
                                 "http://www.sios.com/authenticatingAuthority")
        new_authenticating_authority = saml.AuthenticatingAuthorityFromString(
            self.authenticating_authority.ToString())
        self.assert_(new_authenticating_authority.text ==
                                 "http://www.sios.com/authenticatingAuthority")

        self.assert_(self.authenticating_authority.ToString() ==
                                 new_authenticating_authority.ToString())

    def testUsingTestData(self):
        """Test AuthenticatingAuthorityFromString() using test data"""
        authenticating_authority = saml.AuthenticatingAuthorityFromString(
            test_data.TEST_AUTHENTICATING_AUTHORITY)
        self.assert_(authenticating_authority.text.strip() ==
                                 "http://www.sios.com/authenticatingAuthority")


class AuthnContextTest(unittest.TestCase):

    def setUp(self):
        self.authn_context = saml.AuthnContext()

    def testAccessors(self):
        """Test for AuthnContext accessors"""
        self.authn_context.authn_context_class_ref = \
            saml.AuthnContextClassRefFromString(
            test_data.TEST_AUTHN_CONTEXT_CLASS_REF)
        self.authn_context.authn_context_decl_ref = \
            saml.AuthnContextDeclRefFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL_REF)
        self.authn_context.authn_context_decl = \
            saml.AuthnContextDeclFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL)
        self.authn_context.authenticating_authority.append(
            saml.AuthenticatingAuthorityFromString(
            test_data.TEST_AUTHENTICATING_AUTHORITY))
        self.assert_(self.authn_context.authn_context_class_ref.text.strip() ==
                                 "http://www.sios.com/authnContextClassRef")
        self.assert_(self.authn_context.authn_context_decl_ref.text.strip() ==
                                 "http://www.sios.com/authnContextDeclRef")
        self.assert_(self.authn_context.authn_context_decl.text.strip() ==
                                 "http://www.sios.com/authnContextDecl")
        self.assert_(self.authn_context.authenticating_authority[0].text.strip() ==
                                 "http://www.sios.com/authenticatingAuthority")
        new_authn_context = saml.AuthnContextFromString(
            self.authn_context.ToString())
        self.assert_(self.authn_context.ToString() == new_authn_context.ToString())

    def testUsingTestData(self):
        """Test AuthnContextFromString() using test data"""
        authn_context = saml.AuthnContextFromString(test_data.TEST_AUTHN_CONTEXT)
        self.assert_(authn_context.authn_context_class_ref.text.strip() ==
                                 saml.URN_PASSWORD)


class AuthnStatementTest(unittest.TestCase):

    def setUp(self):
        self.as = saml.AuthnStatement()

    def testAccessors(self):
        """Test for AuthnStatement accessors"""
        self.as.authn_instant = "2007-08-31T01:05:02Z"
        self.as.session_not_on_or_after = "2007-09-14T01:05:02Z"
        self.as.session_index = "sessionindex"
        self.as.authn_context = saml.AuthnContext()
        self.as.authn_context.authn_context_class_ref = \
            saml.AuthnContextClassRefFromString(
            test_data.TEST_AUTHN_CONTEXT_CLASS_REF)
        self.as.authn_context.authn_context_decl_ref = \
            saml.AuthnContextDeclRefFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL_REF)
        self.as.authn_context.authn_context_decl = \
            saml.AuthnContextDeclFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL)
        self.as.authn_context.authenticating_authority.append(
            saml.AuthenticatingAuthorityFromString(
            test_data.TEST_AUTHENTICATING_AUTHORITY))

        new_as = saml.AuthnStatementFromString(self.as.ToString())
        self.assert_(new_as.authn_instant == "2007-08-31T01:05:02Z")
        self.assert_(new_as.session_index == "sessionindex")
        self.assert_(new_as.session_not_on_or_after == "2007-09-14T01:05:02Z")
        self.assert_(new_as.authn_context.authn_context_class_ref.text.strip() ==
                                 "http://www.sios.com/authnContextClassRef")
        self.assert_(new_as.authn_context.authn_context_decl_ref.text.strip() ==
                                 "http://www.sios.com/authnContextDeclRef")
        self.assert_(new_as.authn_context.authn_context_decl.text.strip() ==
                                 "http://www.sios.com/authnContextDecl")
        self.assert_(new_as.authn_context.authenticating_authority[0].text.strip()
                                 == "http://www.sios.com/authenticatingAuthority")
        self.assert_(self.as.ToString() == new_as.ToString())

    def testUsingTestData(self):
        """Test AuthnStatementFromString() using test data"""
        as = saml.AuthnStatementFromString(test_data.TEST_AUTHN_STATEMENT)
        self.assert_(as.authn_instant == "2007-08-31T01:05:02Z")
        self.assert_(as.session_not_on_or_after == "2007-09-14T01:05:02Z")
        self.assert_(as.authn_context.authn_context_class_ref.text.strip() ==
                                 saml.URN_PASSWORD)


class AttributeValueTest(unittest.TestCase):

    def setUp(self):
        self.attribute_value = saml.AttributeValue()

    def testAccessors(self):
        """Test for AttributeValue accessors"""

        self.attribute_value.text = "value for test attribute"
        new_attribute_value = saml.AttributeValueFromString(
            self.attribute_value.ToString())
        self.assert_(new_attribute_value.text.strip() ==
                                 "value for test attribute")

    def testUsingTestData(self):
        """Test AttributeValueFromString() using test data"""

        attribute_value = saml.AttributeValueFromString(
            test_data.TEST_ATTRIBUTE_VALUE)
        self.assert_(attribute_value.text.strip() == "value for test attribute")


class AttributeTest(unittest.TestCase):

    def setUp(self):
        self.attribute = saml.Attribute()

    def testAccessors(self):
        """Test for Attribute accessors"""
        self.attribute.name = "testAttribute"
        self.attribute.name_format = saml.NAME_FORMAT_URI
        self.attribute.friendly_name = "test attribute"
        self.attribute.attribute_value.append(saml.AttributeValue())
        self.attribute.attribute_value[0].text = "value of test attribute"

        new_attribute = saml.AttributeFromString(self.attribute.ToString())
        self.assert_(new_attribute.name == "testAttribute")
        self.assert_(new_attribute.name_format == saml.NAME_FORMAT_URI)
        self.assert_(new_attribute.friendly_name == "test attribute")
        self.assert_(new_attribute.attribute_value[0].text.strip() ==
                                 "value of test attribute")

    def testUsingTestData(self):
        """Test AttributeFromString() using test data"""
        attribute = saml.AttributeFromString(test_data.TEST_ATTRIBUTE)
        self.assert_(attribute.name == "testAttribute")
        self.assert_(attribute.name_format == saml.NAME_FORMAT_UNSPECIFIED)
        self.assert_(attribute.friendly_name == "test attribute")
        self.assert_(attribute.attribute_value[0].text.strip() ==
                                 "value1 of test attribute")
        self.assert_(attribute.attribute_value[1].text.strip() ==
                                 "value2 of test attribute")
        # test again
        attribute = saml.AttributeFromString(attribute.ToString())
        self.assert_(attribute.name == "testAttribute")
        self.assert_(attribute.name_format == saml.NAME_FORMAT_UNSPECIFIED)
        self.assert_(attribute.friendly_name == "test attribute")
        self.assert_(attribute.attribute_value[0].text.strip() ==
                                 "value1 of test attribute")
        self.assert_(attribute.attribute_value[1].text.strip() ==
                                 "value2 of test attribute")


class AttributeStatementTest(unittest.TestCase):

    def setUp(self):
        self.as = saml.AttributeStatement()

    def testAccessors(self):
        """Test for Attribute accessors"""
        self.as.attribute.append(saml.Attribute())
        self.as.attribute.append(saml.Attribute())
        self.as.attribute[0].name = "testAttribute"
        self.as.attribute[0].name_format = saml.NAME_FORMAT_URI
        self.as.attribute[0].friendly_name = "test attribute"
        self.as.attribute[0].attribute_value.append(saml.AttributeValue())
        self.as.attribute[0].attribute_value[0].text = "value of test attribute"

        self.as.attribute[1].name = "testAttribute2"
        self.as.attribute[1].name_format = saml.NAME_FORMAT_UNSPECIFIED
        self.as.attribute[1].friendly_name = "test attribute2"
        self.as.attribute[1].attribute_value.append(saml.AttributeValue())
        self.as.attribute[1].attribute_value[0].text = "value2 of test attribute"

        new_as = saml.AttributeStatementFromString(self.as.ToString())
        self.assert_(new_as.attribute[0].name == "testAttribute")
        self.assert_(new_as.attribute[0].name_format == saml.NAME_FORMAT_URI)
        self.assert_(new_as.attribute[0].friendly_name == "test attribute")
        self.assert_(new_as.attribute[0].attribute_value[0].text.strip() ==
                                 "value of test attribute")
        self.assert_(new_as.attribute[1].name == "testAttribute2")
        self.assert_(new_as.attribute[1].name_format ==
                                 saml.NAME_FORMAT_UNSPECIFIED)
        self.assert_(new_as.attribute[1].friendly_name == "test attribute2")
        self.assert_(new_as.attribute[1].attribute_value[0].text.strip() ==
                                 "value2 of test attribute")

    def testUsingTestData(self):
        """Test AttributeStatementFromString() using test data"""
        as = saml.AttributeStatementFromString(test_data.TEST_ATTRIBUTE_STATEMENT)
        self.assert_(as.attribute[0].name == "testAttribute")
        self.assert_(as.attribute[0].name_format == saml.NAME_FORMAT_UNSPECIFIED)
        self.assert_(as.attribute[0].friendly_name == "test attribute")
        self.assert_(as.attribute[0].attribute_value[0].text.strip() ==
                                 "value1 of test attribute")
        self.assert_(as.attribute[0].attribute_value[1].text.strip() ==
                                 "value2 of test attribute")
        self.assert_(as.attribute[1].name == "http://www.sios.com/testAttribute2")
        self.assert_(as.attribute[1].name_format == saml.NAME_FORMAT_URI)
        self.assert_(as.attribute[1].friendly_name == "test attribute2")
        self.assert_(as.attribute[1].attribute_value[0].text.strip() ==
                                 "value1 of test attribute2")
        self.assert_(as.attribute[1].attribute_value[1].text.strip() ==
                                 "value2 of test attribute2")

        # test again
        as = saml.AttributeStatementFromString(as.ToString())
        self.assert_(as.attribute[0].name == "testAttribute")
        self.assert_(as.attribute[0].name_format == saml.NAME_FORMAT_UNSPECIFIED)
        self.assert_(as.attribute[0].friendly_name == "test attribute")
        self.assert_(as.attribute[0].attribute_value[0].text.strip() ==
                                 "value1 of test attribute")
        self.assert_(as.attribute[0].attribute_value[1].text.strip() ==
                                 "value2 of test attribute")
        self.assert_(as.attribute[1].name == "http://www.sios.com/testAttribute2")
        self.assert_(as.attribute[1].name_format == saml.NAME_FORMAT_URI)
        self.assert_(as.attribute[1].friendly_name == "test attribute2")
        self.assert_(as.attribute[1].attribute_value[0].text.strip() ==
                                 "value1 of test attribute2")
        self.assert_(as.attribute[1].attribute_value[1].text.strip() ==
                                 "value2 of test attribute2")


class SubjectConfirmationDataTest(unittest.TestCase):

    def setUp(self):
        self.scd = saml.SubjectConfirmationData()

    def testAccessors(self):
        """Test for SubjectConfirmationData accessors"""

        self.scd.not_before = "2007-08-31T01:05:02Z"
        self.scd.not_on_or_after = "2007-09-14T01:05:02Z"
        self.scd.recipient = "recipient"
        self.scd.in_response_to = "responseID"
        self.scd.address = "127.0.0.1"
        new_scd = saml.SubjectConfirmationDataFromString(self.scd.ToString())
        self.assert_(new_scd.not_before == "2007-08-31T01:05:02Z")
        self.assert_(new_scd.not_on_or_after == "2007-09-14T01:05:02Z")
        self.assert_(new_scd.recipient == "recipient")
        self.assert_(new_scd.in_response_to == "responseID")
        self.assert_(new_scd.address == "127.0.0.1")

    def testUsingTestData(self):
        """Test SubjectConfirmationDataFromString() using test data"""

        scd = saml.SubjectConfirmationDataFromString(
            test_data.TEST_SUBJECT_CONFIRMATION_DATA)
        self.assert_(scd.not_before == "2007-08-31T01:05:02Z")
        self.assert_(scd.not_on_or_after == "2007-09-14T01:05:02Z")
        self.assert_(scd.recipient == "recipient")
        self.assert_(scd.in_response_to == "responseID")
        self.assert_(scd.address == "127.0.0.1")


class SubjectConfirmationTest(unittest.TestCase):

    def setUp(self):
        self.sc = saml.SubjectConfirmation()

    def testAccessors(self):
        """Test for SubjectConfirmation accessors"""
        self.sc.name_id = saml.NameIDFromString(test_data.TEST_NAME_ID)
        self.sc.method = saml.SUBJECT_CONFIRMATION_METHOD_BEARER
        self.sc.subject_confirmation_data = saml.SubjectConfirmationDataFromString(
            test_data.TEST_SUBJECT_CONFIRMATION_DATA)
        new_sc = saml.SubjectConfirmationFromString(self.sc.ToString())
        self.assert_(new_sc.name_id.sp_provided_id == "sp provided id")
        self.assert_(new_sc.method == saml.SUBJECT_CONFIRMATION_METHOD_BEARER)
        self.assert_(new_sc.subject_confirmation_data.not_before ==
                                 "2007-08-31T01:05:02Z")
        self.assert_(new_sc.subject_confirmation_data.not_on_or_after ==
                                 "2007-09-14T01:05:02Z")
        self.assert_(new_sc.subject_confirmation_data.recipient == "recipient")
        self.assert_(new_sc.subject_confirmation_data.in_response_to ==
                                 "responseID")
        self.assert_(new_sc.subject_confirmation_data.address == "127.0.0.1")

    def testUsingTestData(self):
        """Test SubjectConfirmationFromString() using test data"""

        sc = saml.SubjectConfirmationFromString(
            test_data.TEST_SUBJECT_CONFIRMATION)
        self.assert_(sc.name_id.sp_provided_id == "sp provided id")
        self.assert_(sc.method == saml.SUBJECT_CONFIRMATION_METHOD_BEARER)
        self.assert_(sc.subject_confirmation_data.not_before ==
                                 "2007-08-31T01:05:02Z")
        self.assert_(sc.subject_confirmation_data.not_on_or_after ==
                                 "2007-09-14T01:05:02Z")
        self.assert_(sc.subject_confirmation_data.recipient == "recipient")
        self.assert_(sc.subject_confirmation_data.in_response_to ==
                                 "responseID")
        self.assert_(sc.subject_confirmation_data.address == "127.0.0.1")


class SubjectTest(unittest.TestCase):

    def setUp(self):
        self.subject = saml.Subject()

    def testAccessors(self):
        """Test for Subject accessors"""
        self.subject.name_id = saml.NameIDFromString(test_data.TEST_NAME_ID)
        self.subject.subject_confirmation.append(
            saml.SubjectConfirmationFromString(
            test_data.TEST_SUBJECT_CONFIRMATION))
        new_subject = saml.SubjectFromString(self.subject.ToString())
        self.assert_(new_subject.name_id.sp_provided_id == "sp provided id")
        self.assert_(new_subject.name_id.text.strip() == "tmatsuo@sios.com")
        self.assert_(new_subject.name_id.format ==
                                 saml.NAMEID_FORMAT_EMAILADDRESS)
        self.assert_(isinstance(new_subject.subject_confirmation[0],
                                                        saml.SubjectConfirmation))

    def testUsingTestData(self):
        """Test for SubjectFromString() using test data."""

        subject = saml.SubjectFromString(test_data.TEST_SUBJECT)
        self.assert_(subject.name_id.sp_provided_id == "sp provided id")
        self.assert_(subject.name_id.text.strip() == "tmatsuo@sios.com")
        self.assert_(subject.name_id.format ==
                                 saml.NAMEID_FORMAT_EMAILADDRESS)
        self.assert_(isinstance(subject.subject_confirmation[0],
                                                        saml.SubjectConfirmation))


class ConditionTest(unittest.TestCase):

    def setUp(self):
        self.condition = saml.Condition()

    def testAccessors(self):
        """Test for Condition accessors."""
        self.condition.extension_attributes["{%s}type" % saml.XSI_NAMESPACE] = \
                                                                                                     "test"
        self.condition.extension_attributes['ExtendedAttribute'] = "value"
        new_condition = saml.ConditionFromString(self.condition.ToString())
        self.assert_(
            new_condition.extension_attributes["{%s}type" % saml.XSI_NAMESPACE] ==
            "test")
        self.assert_(new_condition.extension_attributes["ExtendedAttribute"] ==
                                 "value")

    def testUsingTestData(self):
        """Test for ConditionFromString() using test data."""

        condition = saml.ConditionFromString(test_data.TEST_CONDITION)
        self.assert_(
            condition.extension_attributes["{%s}type" % saml.XSI_NAMESPACE] ==
            "test")
        self.assert_(condition.extension_attributes["ExtendedAttribute"] ==
                                 "value")


class AudienceTest(unittest.TestCase):

    def setUp(self):
        self.audience = saml.Audience()

    def testAccessors(self):
        """Test for Audience accessors"""

        self.audience.text = "http://www.sios.com/Audience"
        new_audience = saml.AudienceFromString(self.audience.ToString())
        self.assert_(new_audience.text.strip() == "http://www.sios.com/Audience")

    def testUsingTestData(self):
        """Test AudienceFromString using test data"""

        audience = saml.AudienceFromString(test_data.TEST_AUDIENCE)
        self.assert_(audience.text.strip() == "http://www.sios.com/Audience")


class AudienceRestrictionTest(unittest.TestCase):
    def setUp(self):
        self.audience_restriction = saml.AudienceRestriction()

    def testAccessors(self):
        """Test for AudienceRestriction accessors"""

        self.audience_restriction.audience = saml.AudienceFromString(
            test_data.TEST_AUDIENCE)
        new_audience = saml.AudienceRestrictionFromString(
            self.audience_restriction.ToString())
        self.assert_(self.audience_restriction.audience.text.strip() ==
                                 "http://www.sios.com/Audience")

    def testUsingTestData(self):
        """Test AudienceRestrictionFromString using test data"""

        audience_restriction = saml.AudienceRestrictionFromString(
            test_data.TEST_AUDIENCE_RESTRICTION)
        self.assert_(audience_restriction.audience.text.strip() ==
                                 "http://www.sios.com/Audience")


class OneTimeUseTest(unittest.TestCase):

    def setUp(self):
        self.one_time_use = saml.OneTimeUse()

    def testAccessors(self):
        """Test for OneTimeUse accessors"""
        self.assert_(isinstance(self.one_time_use, saml.OneTimeUse))
        self.assert_(isinstance(self.one_time_use, saml.Condition))

    def testUsingTestData(self):
        """Test OneTimeUseFromString() using test data"""
        one_time_use = saml.OneTimeUseFromString(test_data.TEST_ONE_TIME_USE)
        self.assert_(isinstance(one_time_use, saml.OneTimeUse))
        self.assert_(isinstance(one_time_use, saml.Condition))


class ProxyRestrictionTest(unittest.TestCase):

    def setUp(self):
        self.proxy_restriction = saml.ProxyRestriction()

    def testAccessors(self):
        """Test for ProxyRestriction accessors"""

        self.assert_(isinstance(self.proxy_restriction, saml.Condition))
        self.proxy_restriction.count = "2"
        self.proxy_restriction.audience.append(saml.AudienceFromString(
            test_data.TEST_AUDIENCE))
        new_proxy_restriction = saml.ProxyRestrictionFromString(
            self.proxy_restriction.ToString())
        self.assert_(new_proxy_restriction.count == "2")
        self.assert_(new_proxy_restriction.audience[0].text.strip() ==
                                 "http://www.sios.com/Audience")

    def testUsingTestData(self):
        """Test ProxyRestrictionFromString() using test data"""

        proxy_restriction = saml.ProxyRestrictionFromString(
            test_data.TEST_PROXY_RESTRICTION)
        self.assert_(proxy_restriction.count == "2")
        self.assert_(proxy_restriction.audience[0].text.strip() ==
                                 "http://www.sios.com/Audience")

class ConditionsTest(unittest.TestCase):

    def setUp(self):
        self.conditions = saml.Conditions()

    def testAccessors(self):
        """Test for Conditions accessors"""
        self.conditions.not_before = "2007-08-31T01:05:02Z"
        self.conditions.not_on_or_after = "2007-09-14T01:05:02Z"
        self.conditions.condition.append(saml.Condition())
        self.conditions.audience_restriction.append(saml.AudienceRestriction())
        self.conditions.one_time_use.append(saml.OneTimeUse())
        self.conditions.proxy_restriction.append(saml.ProxyRestriction())
        new_conditions = saml.ConditionsFromString(self.conditions.ToString())
        self.assert_(new_conditions.not_before == "2007-08-31T01:05:02Z")
        self.assert_(new_conditions.not_on_or_after == "2007-09-14T01:05:02Z")
        self.assert_(isinstance(new_conditions.condition[0], saml.Condition))
        self.assert_(isinstance(new_conditions.audience_restriction[0],
                                                        saml.AudienceRestriction))
        self.assert_(isinstance(new_conditions.one_time_use[0],
                                                        saml.OneTimeUse))
        self.assert_(isinstance(new_conditions.proxy_restriction[0],
                                                        saml.ProxyRestriction))

    def testUsingTestData(self):
        """Test ConditionsFromString() using test data"""
        new_conditions = saml.ConditionsFromString(test_data.TEST_CONDITIONS)
        self.assert_(new_conditions.not_before == "2007-08-31T01:05:02Z")
        self.assert_(new_conditions.not_on_or_after == "2007-09-14T01:05:02Z")
        self.assert_(isinstance(new_conditions.condition[0], saml.Condition))
        self.assert_(isinstance(new_conditions.audience_restriction[0],
                                                        saml.AudienceRestriction))
        self.assert_(isinstance(new_conditions.one_time_use[0],
                                                        saml.OneTimeUse))
        self.assert_(isinstance(new_conditions.proxy_restriction[0],
                                                        saml.ProxyRestriction))

class AssertionIDRefTest(unittest.TestCase):

    def setUp(self):
        self.assertion_id_ref = saml.AssertionIDRef()

    def testAccessors(self):
        """Test for AssertionIDRef accessors"""
        self.assertion_id_ref.text = "zzlieajngjbkjggjldmgindkckkolcblndbghlhm"
        new_assertion_id_ref = saml.AssertionIDRefFromString(
            self.assertion_id_ref.ToString())
        self.assert_(new_assertion_id_ref.text ==
                                 "zzlieajngjbkjggjldmgindkckkolcblndbghlhm")

    def testUsingTestData(self):
        """Test AssertionIDRefFromString() using test data"""
        new_assertion_id_ref = saml.AssertionIDRefFromString(
            test_data.TEST_ASSERTION_ID_REF)
        self.assert_(new_assertion_id_ref.text.strip() ==
                                 "zzlieajngjbkjggjldmgindkckkolcblndbghlhm")


class AssertionURIRefTest(unittest.TestCase):

    def setUp(self):
        self.assertion_uri_ref = saml.AssertionURIRef()

    def testAccessors(self):
        """Test for AssertionURIRef accessors"""
        self.assertion_uri_ref.text = "http://www.sios.com/AssertionURIRef"
        new_assertion_uri_ref = saml.AssertionURIRefFromString(
            self.assertion_uri_ref.ToString())
        self.assert_(new_assertion_uri_ref.text ==
                                 "http://www.sios.com/AssertionURIRef")

    def testUsingTestData(self):
        """Test AssertionURIRefFromString() using test data"""
        new_assertion_uri_ref = saml.AssertionURIRefFromString(
            test_data.TEST_ASSERTION_URI_REF)
        self.assert_(new_assertion_uri_ref.text.strip() ==
                                 "http://www.sios.com/AssertionURIRef")


class ActionTest(unittest.TestCase):

    def setUp(self):
        self.action = saml.Action()

    def testAccessors(self):
        """Test for Action accessors"""
        self.action.namespace = "http://www.sios.com/Namespace"
        new_action = saml.ActionFromString(self.action.ToString())
        self.assert_(new_action.namespace == "http://www.sios.com/Namespace")

    def testUsingTestData(self):
        """Test ActionFromString() using test data"""
        new_action = saml.ActionFromString(test_data.TEST_ACTION)
        self.assert_(new_action.namespace == "http://www.sios.com/Namespace")


class EvidenceTest(unittest.TestCase):

    def setUp(self):
        self.evidence = saml.Evidence()

    def testAccessors(self):
        """Test for Evidence accessors"""
        self.evidence.assertion_id_ref.append(saml.AssertionIDRef())
        self.evidence.assertion_uri_ref.append(saml.AssertionURIRef())
        self.evidence.assertion.append(saml.Assertion())
        self.evidence.encrypted_assertion.append(saml.EncryptedAssertion())
        new_evidence = saml.EvidenceFromString(self.evidence.ToString())
        self.assert_(self.evidence.ToString() == new_evidence.ToString())
        self.assert_(isinstance(new_evidence.assertion_id_ref[0],
                                                        saml.AssertionIDRef))
        self.assert_(isinstance(new_evidence.assertion_uri_ref[0],
                                                        saml.AssertionURIRef))
        self.assert_(isinstance(new_evidence.assertion[0], saml.Assertion))
        self.assert_(isinstance(new_evidence.encrypted_assertion[0],
                                                        saml.EncryptedAssertion))

    def testUsingTestData(self):
        """Test EvidenceFromString() using test data"""
        # TODO:
        pass


class AuthzDecisionStatementTest(unittest.TestCase):

    def setUp(self):
        self.authz_decision_statement = saml.AuthzDecisionStatement()

    def testAccessors(self):
        """Test for AuthzDecisionStatement accessors"""
        self.authz_decision_statement.resource = "http://www.sios.com/Resource"
        self.authz_decision_statement.decision = saml.DECISION_TYPE_PERMIT
        self.authz_decision_statement.action.append(saml.Action())
        self.authz_decision_statement.evidence.append(saml.Evidence())
        new_authz_decision_statement = saml.AuthzDecisionStatementFromString(
            self.authz_decision_statement.ToString())
        self.assert_(self.authz_decision_statement.ToString() ==
                                 new_authz_decision_statement.ToString())
        self.assert_(new_authz_decision_statement.resource ==
                                 "http://www.sios.com/Resource")
        self.assert_(new_authz_decision_statement.decision ==
                                 saml.DECISION_TYPE_PERMIT)
        self.assert_(isinstance(new_authz_decision_statement.action[0],
                                                        saml.Action))
        self.assert_(isinstance(new_authz_decision_statement.evidence[0],
                                                        saml.Evidence))


    def testUsingTestData(self):
        """Test AuthzDecisionStatementFromString() using test data"""
        # TODO:
        pass

class AdviceTest(unittest.TestCase):

    def setUp(self):
        self.advice = saml.Advice()

    def testAccessors(self):
        """Test for Advice accessors"""
        self.advice.assertion_id_ref.append(saml.AssertionIDRef())
        self.advice.assertion_uri_ref.append(saml.AssertionURIRef())
        self.advice.assertion.append(saml.Assertion())
        self.advice.encrypted_assertion.append(saml.EncryptedAssertion())
        new_advice = saml.AdviceFromString(self.advice.ToString())
        self.assert_(self.advice.ToString() == new_advice.ToString())
        self.assert_(isinstance(new_advice.assertion_id_ref[0],
                                                        saml.AssertionIDRef))
        self.assert_(isinstance(new_advice.assertion_uri_ref[0],
                                                        saml.AssertionURIRef))
        self.assert_(isinstance(new_advice.assertion[0], saml.Assertion))
        self.assert_(isinstance(new_advice.encrypted_assertion[0],
                                                        saml.EncryptedAssertion))

    def testUsingTestData(self):
        """Test AdviceFromString() using test data"""
        # TODO:
        pass


class AssertionTest(unittest.TestCase):

    def setUp(self):
        self.assertion = saml.Assertion()

    def testAccessors(self):
        """Test for Assertion accessors"""
        self.assertion.id = "assertion id"
        self.assertion.version = saml.V2
        self.assertion.issue_instant = "2007-08-31T01:05:02Z"
        self.assertion.issuer = saml.IssuerFromString(test_data.TEST_ISSUER)
        self.assertion.signature = ds.SignatureFromString(
            ds_test_data.TEST_SIGNATURE)
        self.assertion.subject = saml.SubjectFromString(test_data.TEST_SUBJECT)
        self.assertion.conditions = saml.ConditionsFromString(
            test_data.TEST_CONDITIONS)
        self.assertion.advice = saml.Advice()
        self.assertion.statement.append(saml.Statement())
        self.assertion.authn_statement.append(saml.AuthnStatementFromString(
            test_data.TEST_AUTHN_STATEMENT))
        self.assertion.authz_decision_statement.append(
            saml.AuthzDecisionStatement())
        self.assertion.attribute_statement.append(
            saml.AttributeStatementFromString(
            test_data.TEST_ATTRIBUTE_STATEMENT))

        new_assertion = saml.AssertionFromString(self.assertion.ToString())
        self.assert_(new_assertion.id == "assertion id")
        self.assert_(new_assertion.version == saml.V2)
        self.assert_(new_assertion.issue_instant == "2007-08-31T01:05:02Z")
        self.assert_(isinstance(new_assertion.issuer, saml.Issuer))
        self.assert_(isinstance(new_assertion.signature, ds.Signature))
        self.assert_(isinstance(new_assertion.subject, saml.Subject))
        self.assert_(isinstance(new_assertion.conditions, saml.Conditions))
        self.assert_(isinstance(new_assertion.advice, saml.Advice))
        self.assert_(isinstance(new_assertion.statement[0], saml.Statement))
        self.assert_(isinstance(new_assertion.authn_statement[0],
                                                saml.AuthnStatement))
        self.assert_(isinstance(new_assertion.authz_decision_statement[0],
                                                saml.AuthzDecisionStatement))
        self.assert_(isinstance(new_assertion.attribute_statement[0],
                                                saml.AttributeStatement))


    def testUsingTestData(self):
        """Test AssertionFromString() using test data"""
        # TODO
        pass
        
if __name__ == '__main__':
    unittest.main()
