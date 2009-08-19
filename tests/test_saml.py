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

try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree
import saml2
from saml2 import saml, test_data, ds_test_data
import xmldsig as ds

class TestNameID:

    def setup_class(self):
        self.name_id = saml.NameID()

    def testEmptyExtensionsList(self):
        """Test if NameID has empty extensions list"""
        assert isinstance(self.name_id.extension_elements, list)
        assert len(self.name_id.extension_elements) == 0

    def testFormatAttribute(self):
        """Test for Format attribute accessors"""
        self.name_id.format = saml.NAMEID_FORMAT_EMAILADDRESS
        assert self.name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS
        assert len(self.name_id.extension_elements) == 0
        new_name_id = saml.NameIDFromString(self.name_id.to_string())
        assert len(new_name_id.extension_elements) == 0

        self.name_id.extension_elements.append(saml2.ExtensionElement(
            'foo', text='bar'))
        assert len(self.name_id.extension_elements) == 1
        assert self.name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS

    def testNameIDText(self):
        """Test text value of NameID element"""
        self.name_id.text = "tmatsuo@sios.com"
        assert self.name_id.text == "tmatsuo@sios.com"
        
    def testSPProvidedID(self):
        """Test for SPProvidedID attribute accessors"""
        self.name_id.sp_provided_id = "provided id"
        assert self.name_id.sp_provided_id == "provided id"

    def testEmptyNameIDToAndFromStringMatch(self):
        """Test NameIDFromString() with empty NameID"""
        string_from_name_id = self.name_id.to_string()
        new_name_id = saml.NameIDFromString(string_from_name_id)
        string_from_new_name_id = new_name_id.to_string()
        assert string_from_name_id == string_from_new_name_id

    def testNameIDToAndFromStringMatch(self):
        """Test NameIDFromString() with data"""
        self.name_id.format = saml.NAMEID_FORMAT_EMAILADDRESS
        self.name_id.text = "tmatsuo@sios.com"
        self.name_id.name_qualifier = "name_qualifier"
        self.name_id.sp_name_qualifier = "sp_name_qualifier"
        string_from_name_id = self.name_id.to_string()
        new_name_id = saml.NameIDFromString(string_from_name_id)
        assert new_name_id.name_qualifier == "name_qualifier"
        assert new_name_id.sp_name_qualifier == "sp_name_qualifier"
        string_from_new_name_id = new_name_id.to_string()
        assert string_from_name_id == string_from_new_name_id

    def testExtensionAttributes(self):
        """Test extension attributes"""
        self.name_id.extension_attributes['hoge'] = 'fuga'
        self.name_id.extension_attributes['moge'] = 'muga'
        assert self.name_id.extension_attributes['hoge'] == 'fuga'
        assert self.name_id.extension_attributes['moge'] == 'muga'
        new_name_id = saml.NameIDFromString(self.name_id.to_string())
        assert new_name_id.extension_attributes['hoge'] == 'fuga'
        assert new_name_id.extension_attributes['moge'] == 'muga'

    def testNameIDFromString(self):
        """Test NameIDFromString() using test data"""
        name_id = saml.NameIDFromString(test_data.TEST_NAME_ID)
        assert name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS
        assert name_id.text.strip() == "tmatsuo@sios.com"
        assert name_id.sp_provided_id == "sp provided id"


class TestIssuer:

    def setup_class(self):
        self.issuer = saml.Issuer()

    def testIssuerToAndFromString(self):
        """Test IssuerFromString()"""
        self.issuer.text = "http://www.sios.com/test"
        self.issuer.name_qualifier = "name_qualifier"
        self.issuer.sp_name_qualifier = "sp_name_qualifier"
        new_issuer = saml.IssuerFromString(self.issuer.to_string())
        assert self.issuer.text == new_issuer.text
        assert self.issuer.name_qualifier == new_issuer.name_qualifier
        assert self.issuer.sp_name_qualifier == new_issuer.sp_name_qualifier
        assert self.issuer.extension_elements == new_issuer.extension_elements

    def testUsingTestData(self):
        """Test IssuerFromString() using test data"""
        issuer = saml.IssuerFromString(test_data.TEST_ISSUER)
        assert issuer.text.strip() == "http://www.sios.com/test"
        new_issuer = saml.IssuerFromString(issuer.to_string())
        assert issuer.text == new_issuer.text
        assert issuer.extension_elements == new_issuer.extension_elements


class TestSubjectLocality:

    def setup_class(self):
        self.subject_locality = saml.SubjectLocality()

    def testAccessors(self):
        """Test for SubjectLocality accessors"""
        self.subject_locality.address = "127.0.0.1"
        self.subject_locality.dns_name = "localhost"
        assert self.subject_locality.address == "127.0.0.1"
        assert self.subject_locality.dns_name == "localhost"
        new_subject_locality = saml.SubjectLocalityFromString(
            self.subject_locality.to_string())
        assert new_subject_locality.address == "127.0.0.1"
        assert new_subject_locality.dns_name == "localhost"

    def testUsingTestData(self):
        """Test SubjectLocalityFromString() using test data"""

        subject_locality = saml.SubjectLocalityFromString(
            test_data.TEST_SUBJECT_LOCALITY)
        assert subject_locality.address == "127.0.0.1"
        assert subject_locality.dns_name == "localhost"
        
        new_subject_locality = saml.SubjectLocalityFromString(
            subject_locality.to_string())
        assert new_subject_locality.address == "127.0.0.1"
        assert new_subject_locality.dns_name == "localhost"
        assert subject_locality.to_string() == new_subject_locality.to_string()


class TestAuthnContextClassRef:

    def setup_class(self):
        self.authn_context_class_ref = saml.AuthnContextClassRef()
        text = "http://www.sios.com/authnContextClassRef"

    def testAccessors(self):
        """Test for AuthnContextClassRef accessors"""
        self.authn_context_class_ref.text = self.text
        assert self.authn_context_class_ref.text == self.text
        new_authn_context_class_ref = saml.AuthnContextClassRefFromString(
            self.authn_context_class_ref.to_string())
        assert new_authn_context_class_ref.text == self.text
        assert self.authn_context_class_ref.to_string() == \
                    new_authn_context_class_ref.to_string()

    def testUsingTestData(self):
        """Test AuthnContextClassRefFromString() using test data"""
        authn_context_class_ref = saml.AuthnContextClassRefFromString(
            test_data.TEST_AUTHN_CONTEXT_CLASS_REF)
        assert authn_context_class_ref.text.strip() == self.text


class TestAuthnContextDeclRef:

    def setup_class(self):
        self.authn_context_decl_ref = saml.AuthnContextDeclRef()
        ref = "http://www.sios.com/authnContextDeclRef"

    def testAccessors(self):
        """Test for AuthnContextDeclRef accessors"""
        self.authn_context_decl_ref.text = self.ref
        assert self.authn_context_decl_ref.text == self.ref
        new_authn_context_decl_ref = saml.AuthnContextDeclRefFromString(
            self.authn_context_decl_ref.to_string())
        assert new_authn_context_decl_ref.text == self.ref
        assert self.authn_context_decl_ref.to_string() == \
                                 new_authn_context_decl_ref.to_string()

    def testUsingTestData(self):
        """Test AuthnContextDeclRefFromString() using test data"""
        authn_context_decl_ref = saml.AuthnContextDeclRefFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL_REF)
        assert authn_context_decl_ref.text.strip() == self.ref


class TestAuthnContextDecl:

    def setup_class(self):
        self.authn_context_decl = saml.AuthnContextDecl()
        self.text = "http://www.sios.com/authnContextDecl"
        
    def testAccessors(self):
        """Test for AuthnContextDecl accessors"""
        self.authn_context_decl.text = self.text
        assert self.authn_context_decl.text == self.text
        new_authn_context_decl = saml.AuthnContextDeclFromString(
            self.authn_context_decl.to_string())
        assert new_authn_context_decl.text == self.text
        assert self.authn_context_decl.to_string() == \
                                 new_authn_context_decl.to_string()

    def testUsingTestData(self):
        """Test AuthnContextDeclFromString() using test data"""
        authn_context_decl = saml.AuthnContextDeclFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL)
        assert authn_context_decl.text.strip() == self.text


class TestAuthenticatingAuthority:

    def setup_class(self):
        self.authenticating_authority = saml.AuthenticatingAuthority()
        self.text = "http://www.sios.com/authenticatingAuthority"
        
    def testAccessors(self):
        """Test for AuthenticatingAuthority accessors"""
        self.authenticating_authority.text = self.text
        assert self.authenticating_authority.text == self.text
        new_authenticating_authority = saml.AuthenticatingAuthorityFromString(
            self.authenticating_authority.to_string())
        assert new_authenticating_authority.text == self.text
        assert self.authenticating_authority.to_string() == \
                                 new_authenticating_authority.to_string()

    def testUsingTestData(self):
        """Test AuthenticatingAuthorityFromString() using test data"""
        authenticating_authority = saml.AuthenticatingAuthorityFromString(
            test_data.TEST_AUTHENTICATING_AUTHORITY)
        assert authenticating_authority.text.strip() == self.text

class TestAuthnContext:

    def setup_class(self):
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
        assert self.authn_context.authn_context_class_ref.text.strip() == \
                                 "http://www.sios.com/authnContextClassRef"
        assert self.authn_context.authn_context_decl_ref.text.strip() == \
                                 "http://www.sios.com/authnContextDeclRef"
        assert self.authn_context.authn_context_decl.text.strip() == \
                                 "http://www.sios.com/authnContextDecl"
        assert self.authn_context.authenticating_authority[0].text.strip() == \
                                 "http://www.sios.com/authenticatingAuthority"
        new_authn_context = saml.AuthnContextFromString(
            self.authn_context.to_string())
        assert self.authn_context.to_string() == new_authn_context.to_string()

    def testUsingTestData(self):
        """Test AuthnContextFromString() using test data"""
        authn_context = saml.AuthnContextFromString(test_data.TEST_AUTHN_CONTEXT)
        assert authn_context.authn_context_class_ref.text.strip() == \
                                 saml.URN_PASSWORD


class TestAuthnStatement:

    def setup_class(self):
        self.authn_statem = saml.AuthnStatement()

    def testAccessors(self):
        """Test for AuthnStatement accessors"""
        self.authn_statem.authn_instant = "2007-08-31T01:05:02Z"
        self.authn_statem.session_not_on_or_after = "2007-09-14T01:05:02Z"
        self.authn_statem.session_index = "sessionindex"
        self.authn_statem.authn_context = saml.AuthnContext()
        self.authn_statem.authn_context.authn_context_class_ref = \
            saml.AuthnContextClassRefFromString(
            test_data.TEST_AUTHN_CONTEXT_CLASS_REF)
        self.authn_statem.authn_context.authn_context_decl_ref = \
            saml.AuthnContextDeclRefFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL_REF)
        self.authn_statem.authn_context.authn_context_decl = \
            saml.AuthnContextDeclFromString(
            test_data.TEST_AUTHN_CONTEXT_DECL)
        self.authn_statem.authn_context.authenticating_authority.append(
            saml.AuthenticatingAuthorityFromString(
            test_data.TEST_AUTHENTICATING_AUTHORITY))

        new_as = saml.AuthnStatementFromString(self.authn_statem.to_string())
        assert new_as.authn_instant == "2007-08-31T01:05:02Z"
        assert new_as.session_index == "sessionindex"
        assert new_as.session_not_on_or_after == "2007-09-14T01:05:02Z"
        assert new_as.authn_context.authn_context_class_ref.text.strip() == \
                                 "http://www.sios.com/authnContextClassRef"
        assert new_as.authn_context.authn_context_decl_ref.text.strip() == \
                                 "http://www.sios.com/authnContextDeclRef"
        assert new_as.authn_context.authn_context_decl.text.strip() == \
                                 "http://www.sios.com/authnContextDecl"
        assert new_as.authn_context.authenticating_authority[0].text.strip() \
                                 == "http://www.sios.com/authenticatingAuthority"
        assert self.authn_statem.to_string() == new_as.to_string()

    def testUsingTestData(self):
        """Test AuthnStatementFromString() using test data"""
        authn_statem = saml.AuthnStatementFromString(test_data.TEST_AUTHN_STATEMENT)
        assert authn_statem.authn_instant == "2007-08-31T01:05:02Z"
        assert authn_statem.session_not_on_or_after == "2007-09-14T01:05:02Z"
        assert authn_statem.authn_context.authn_context_class_ref.text.strip() == \
                                 saml.URN_PASSWORD


class TestAttributeValue:

    def setup_class(self):
        self.attribute_value = saml.AttributeValue()
        self.text = "value for test attribute"
        
    def testAccessors(self):
        """Test for AttributeValue accessors"""

        self.attribute_value.text = self.text
        new_attribute_value = saml.AttributeValueFromString(
            self.attribute_value.to_string())
        assert new_attribute_value.text.strip() == self.text

    def testUsingTestData(self):
        """Test AttributeValueFromString() using test data"""

        attribute_value = saml.AttributeValueFromString(
            test_data.TEST_ATTRIBUTE_VALUE)
        assert attribute_value.text.strip() == self.text


class TestAttribute:

    def setup_class(self):
        self.attribute = saml.Attribute()
        self.text = ["value of test attribute",
            "value1 of test attribute",
            "value2 of test attribute"]
        
    def testAccessors(self):
        """Test for Attribute accessors"""
        self.attribute.name = "testAttribute"
        self.attribute.name_format = saml.NAME_FORMAT_URI
        self.attribute.friendly_name = "test attribute"
        self.attribute.attribute_value.append(saml.AttributeValue())
        self.attribute.attribute_value[0].text = self.text[0]

        new_attribute = saml.AttributeFromString(self.attribute.to_string())
        assert new_attribute.name == "testAttribute"
        assert new_attribute.name_format == saml.NAME_FORMAT_URI
        assert new_attribute.friendly_name == "test attribute"
        assert new_attribute.attribute_value[0].text.strip() == self.text[0]

    def testUsingTestData(self):
        """Test AttributeFromString() using test data"""
        attribute = saml.AttributeFromString(test_data.TEST_ATTRIBUTE)
        assert attribute.name == "testAttribute"
        assert attribute.name_format == saml.NAME_FORMAT_UNSPECIFIED
        assert attribute.friendly_name == "test attribute"
        assert attribute.attribute_value[0].text.strip() == self.text[1]
        assert attribute.attribute_value[1].text.strip() == self.text[2]
        # test again
        attribute = saml.AttributeFromString(attribute.to_string())
        assert attribute.name == "testAttribute"
        assert attribute.name_format == saml.NAME_FORMAT_UNSPECIFIED
        assert attribute.friendly_name == "test attribute"
        assert attribute.attribute_value[0].text.strip() == self.text[1]
        assert attribute.attribute_value[1].text.strip() == self.text[2]


class TestAttributeStatement:

    def setup_class(self):
        self.attr_statem = saml.AttributeStatement()
        self.text = ["value of test attribute",
            "value1 of test attribute",
            "value2 of test attribute"]

    def testAccessors(self):
        """Test for Attribute accessors"""
        self.attr_statem.attribute.append(saml.Attribute())
        self.attr_statem.attribute.append(saml.Attribute())
        self.attr_statem.attribute[0].name = "testAttribute"
        self.attr_statem.attribute[0].name_format = saml.NAME_FORMAT_URI
        self.attr_statem.attribute[0].friendly_name = "test attribute"
        self.attr_statem.attribute[0].attribute_value.append(saml.AttributeValue())
        self.attr_statem.attribute[0].attribute_value[0].text = self.text[0]

        self.attr_statem.attribute[1].name = "testAttribute2"
        self.attr_statem.attribute[1].name_format = saml.NAME_FORMAT_UNSPECIFIED
        self.attr_statem.attribute[1].friendly_name = self.text[2]
        self.attr_statem.attribute[1].attribute_value.append(saml.AttributeValue())
        self.attr_statem.attribute[1].attribute_value[0].text = self.text[2]

        new_as = saml.AttributeStatementFromString(self.attr_statem.to_string())
        assert new_as.attribute[0].name == "testAttribute"
        assert new_as.attribute[0].name_format == saml.NAME_FORMAT_URI
        assert new_as.attribute[0].friendly_name == "test attribute"
        assert new_as.attribute[0].attribute_value[0].text.strip() == self.text[0]
        assert new_as.attribute[1].name == "testAttribute2"
        assert new_as.attribute[1].name_format == saml.NAME_FORMAT_UNSPECIFIED
        assert new_as.attribute[1].friendly_name == "test attribute2"
        assert new_as.attribute[1].attribute_value[0].text.strip() == self.text[2]

    def testUsingTestData(self):
        """Test AttributeStatementFromString() using test data"""
        attr_statem = saml.AttributeStatementFromString(test_data.TEST_ATTRIBUTE_STATEMENT)
        assert attr_statem.attribute[0].name == "testAttribute"
        assert attr_statem.attribute[0].name_format == saml.NAME_FORMAT_UNSPECIFIED
        assert attr_statem.attribute[0].friendly_name == "test attribute"
        assert attr_statem.attribute[0].attribute_value[0].text.strip() == self.text[1]
        assert attr_statem.attribute[0].attribute_value[1].text.strip() == self.text[2]
        assert attr_statem.attribute[1].name == "http://www.sios.com/testAttribute2"
        assert attr_statem.attribute[1].name_format == saml.NAME_FORMAT_URI
        assert attr_statem.attribute[1].friendly_name == "test attribute2"
        assert attr_statem.attribute[1].attribute_value[0].text.strip() == self.text[1]
        assert attr_statem.attribute[1].attribute_value[1].text.strip() == self.text[2]

        # test again
        attr_statem2 = saml.AttributeStatementFromString(attr_statem.to_string())
        assert attr_statem2.attribute[0].name == "testAttribute"
        assert attr_statem2.attribute[0].name_format == saml.NAME_FORMAT_UNSPECIFIED
        assert attr_statem2.attribute[0].friendly_name == "test attribute"
        assert attr_statem2.attribute[0].attribute_value[0].text.strip() == self.text[1]
        assert attr_statem2.attribute[0].attribute_value[1].text.strip() == self.text[2]
        assert attr_statem2.attribute[1].name == "http://www.sios.com/testAttribute2"
        assert attr_statem2.attribute[1].name_format == saml.NAME_FORMAT_URI
        assert attr_statem2.attribute[1].friendly_name == "test attribute2"
        assert attr_statem2.attribute[1].attribute_value[0].text.strip() == self.text[1]
        assert attr_statem2.attribute[1].attribute_value[1].text.strip() == self.text[2]


class TestSubjectConfirmationData:

    def setup_class(self):
        self.scd = saml.SubjectConfirmationData()

    def testAccessors(self):
        """Test for SubjectConfirmationData accessors"""

        self.scd.not_before = "2007-08-31T01:05:02Z"
        self.scd.not_on_or_after = "2007-09-14T01:05:02Z"
        self.scd.recipient = "recipient"
        self.scd.in_response_to = "responseID"
        self.scd.address = "127.0.0.1"
        new_scd = saml.SubjectConfirmationDataFromString(self.scd.to_string())
        assert new_scd.not_before == "2007-08-31T01:05:02Z"
        assert new_scd.not_on_or_after == "2007-09-14T01:05:02Z"
        assert new_scd.recipient == "recipient"
        assert new_scd.in_response_to == "responseID"
        assert new_scd.address == "127.0.0.1"

    def testUsingTestData(self):
        """Test SubjectConfirmationDataFromString() using test data"""

        scd = saml.SubjectConfirmationDataFromString(
            test_data.TEST_SUBJECT_CONFIRMATION_DATA)
        assert scd.not_before == "2007-08-31T01:05:02Z"
        assert scd.not_on_or_after == "2007-09-14T01:05:02Z"
        assert scd.recipient == "recipient"
        assert scd.in_response_to == "responseID"
        assert scd.address == "127.0.0.1"


class TestSubjectConfirmation:

    def setup_class(self):
        self.sc = saml.SubjectConfirmation()

    def testAccessors(self):
        """Test for SubjectConfirmation accessors"""
        self.sc.name_id = saml.NameIDFromString(test_data.TEST_NAME_ID)
        self.sc.method = saml.SUBJECT_CONFIRMATION_METHOD_BEARER
        self.sc.subject_confirmation_data = saml.SubjectConfirmationDataFromString(
            test_data.TEST_SUBJECT_CONFIRMATION_DATA)
        new_sc = saml.SubjectConfirmationFromString(self.sc.to_string())
        assert new_sc.name_id.sp_provided_id == "sp provided id"
        assert new_sc.method == saml.SUBJECT_CONFIRMATION_METHOD_BEARER
        assert new_sc.subject_confirmation_data.not_before == \
                                 "2007-08-31T01:05:02Z"
        assert new_sc.subject_confirmation_data.not_on_or_after == \
                                 "2007-09-14T01:05:02Z"
        assert new_sc.subject_confirmation_data.recipient == "recipient"
        assert new_sc.subject_confirmation_data.in_response_to == "responseID"
        assert new_sc.subject_confirmation_data.address == "127.0.0.1"

    def testUsingTestData(self):
        """Test SubjectConfirmationFromString() using test data"""

        sc = saml.SubjectConfirmationFromString(
            test_data.TEST_SUBJECT_CONFIRMATION)
        assert sc.name_id.sp_provided_id == "sp provided id"
        assert sc.method == saml.SUBJECT_CONFIRMATION_METHOD_BEARER
        assert sc.subject_confirmation_data.not_before == "2007-08-31T01:05:02Z"
        assert sc.subject_confirmation_data.not_on_or_after == "2007-09-14T01:05:02Z"
        assert sc.subject_confirmation_data.recipient == "recipient"
        assert sc.subject_confirmation_data.in_response_to == "responseID"
        assert sc.subject_confirmation_data.address == "127.0.0.1"


class TestSubject:

    def setup_class(self):
        self.subject = saml.Subject()

    def testAccessors(self):
        """Test for Subject accessors"""
        self.subject.name_id = saml.NameIDFromString(test_data.TEST_NAME_ID)
        self.subject.subject_confirmation.append(
            saml.SubjectConfirmationFromString(
            test_data.TEST_SUBJECT_CONFIRMATION))
        new_subject = saml.SubjectFromString(self.subject.to_string())
        assert new_subject.name_id.sp_provided_id == "sp provided id"
        assert new_subject.name_id.text.strip() == "tmatsuo@sios.com"
        assert new_subject.name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS
        assert isinstance(new_subject.subject_confirmation[0],
                            saml.SubjectConfirmation)

    def testUsingTestData(self):
        """Test for SubjectFromString() using test data."""

        subject = saml.SubjectFromString(test_data.TEST_SUBJECT)
        assert subject.name_id.sp_provided_id == "sp provided id"
        assert subject.name_id.text.strip() == "tmatsuo@sios.com"
        assert subject.name_id.format == saml.NAMEID_FORMAT_EMAILADDRESS
        assert isinstance(subject.subject_confirmation[0],
                            saml.SubjectConfirmation)


class TestCondition:

    def setup_class(self):
        self.condition = saml.Condition()
        self.name = "{%s}type" % saml.XSI_NAMESPACE
        
    def testAccessors(self):
        """Test for Condition accessors."""
        self.condition.extension_attributes[self.name] = "test"
        self.condition.extension_attributes['ExtendedAttribute'] = "value"
        new_condition = saml.ConditionFromString(self.condition.to_string())
        assert new_condition.extension_attributes[self.name] == "test"
        assert new_condition.extension_attributes["ExtendedAttribute"] == "value"

    def testUsingTestData(self):
        """Test for ConditionFromString() using test data."""
        condition = saml.ConditionFromString(test_data.TEST_CONDITION)
        assert condition.extension_attributes[self.name] == "test"
        assert condition.extension_attributes["ExtendedAttribute"] == "value"


class TestAudience:

    def setup_class(self):
        self.audience = saml.Audience()

    def testAccessors(self):
        """Test for Audience accessors"""

        self.audience.text = "http://www.sios.com/Audience"
        new_audience = saml.AudienceFromString(self.audience.to_string())
        assert new_audience.text.strip() == "http://www.sios.com/Audience"

    def testUsingTestData(self):
        """Test AudienceFromString using test data"""

        audience = saml.AudienceFromString(test_data.TEST_AUDIENCE)
        assert audience.text.strip() == "http://www.sios.com/Audience"


class TestAudienceRestriction:
    def setup_class(self):
        self.audience_restriction = saml.AudienceRestriction()

    def testAccessors(self):
        """Test for AudienceRestriction accessors"""

        self.audience_restriction.audience = \
            saml.AudienceFromString(test_data.TEST_AUDIENCE)
        new_audience = saml.AudienceRestrictionFromString(
                        self.audience_restriction.to_string())
        assert self.audience_restriction.audience.text.strip() == \
                                 "http://www.sios.com/Audience"

    def testUsingTestData(self):
        """Test AudienceRestrictionFromString using test data"""

        audience_restriction = saml.AudienceRestrictionFromString(
            test_data.TEST_AUDIENCE_RESTRICTION)
        assert audience_restriction.audience.text.strip() == \
                                 "http://www.sios.com/Audience"


class TestOneTimeUse:

    def setup_class(self):
        self.one_time_use = saml.OneTimeUse()

    def testAccessors(self):
        """Test for OneTimeUse accessors"""
        assert isinstance(self.one_time_use, saml.OneTimeUse)
        assert isinstance(self.one_time_use, saml.Condition)

    def testUsingTestData(self):
        """Test OneTimeUseFromString() using test data"""
        one_time_use = saml.OneTimeUseFromString(test_data.TEST_ONE_TIME_USE)
        assert isinstance(one_time_use, saml.OneTimeUse)
        assert isinstance(one_time_use, saml.Condition)


class TestProxyRestriction:

    def setup_class(self):
        self.proxy_restriction = saml.ProxyRestriction()

    def testAccessors(self):
        """Test for ProxyRestriction accessors"""

        assert isinstance(self.proxy_restriction, saml.Condition)
        self.proxy_restriction.count = "2"
        self.proxy_restriction.audience.append(saml.AudienceFromString(
            test_data.TEST_AUDIENCE))
        new_proxy_restriction = saml.ProxyRestrictionFromString(
            self.proxy_restriction.to_string())
        assert new_proxy_restriction.count == "2"
        assert new_proxy_restriction.audience[0].text.strip() == \
                    "http://www.sios.com/Audience"

    def testUsingTestData(self):
        """Test ProxyRestrictionFromString() using test data"""

        proxy_restriction = saml.ProxyRestrictionFromString(
            test_data.TEST_PROXY_RESTRICTION)
        assert proxy_restriction.count == "2"
        assert proxy_restriction.audience[0].text.strip() == \
                                 "http://www.sios.com/Audience"

class TestConditions:

    def setup_class(self):
        self.conditions = saml.Conditions()

    def testAccessors(self):
        """Test for Conditions accessors"""
        self.conditions.not_before = "2007-08-31T01:05:02Z"
        self.conditions.not_on_or_after = "2007-09-14T01:05:02Z"
        self.conditions.condition.append(saml.Condition())
        self.conditions.audience_restriction.append(saml.AudienceRestriction())
        self.conditions.one_time_use.append(saml.OneTimeUse())
        self.conditions.proxy_restriction.append(saml.ProxyRestriction())
        new_conditions = saml.ConditionsFromString(self.conditions.to_string())
        assert new_conditions.not_before == "2007-08-31T01:05:02Z"
        assert new_conditions.not_on_or_after == "2007-09-14T01:05:02Z"
        assert isinstance(new_conditions.condition[0], saml.Condition)
        assert isinstance(new_conditions.audience_restriction[0],
                                                        saml.AudienceRestriction)
        assert isinstance(new_conditions.one_time_use[0],
                                                        saml.OneTimeUse)
        assert isinstance(new_conditions.proxy_restriction[0],
                                                        saml.ProxyRestriction)

    def testUsingTestData(self):
        """Test ConditionsFromString() using test data"""
        new_conditions = saml.ConditionsFromString(test_data.TEST_CONDITIONS)
        assert new_conditions.not_before == "2007-08-31T01:05:02Z"
        assert new_conditions.not_on_or_after == "2007-09-14T01:05:02Z"
        assert isinstance(new_conditions.condition[0], saml.Condition)
        assert isinstance(new_conditions.audience_restriction[0],
                                                        saml.AudienceRestriction)
        assert isinstance(new_conditions.one_time_use[0],
                                                        saml.OneTimeUse)
        assert isinstance(new_conditions.proxy_restriction[0],
                                                        saml.ProxyRestriction)

class TestAssertionIDRef:

    def setup_class(self):
        self.assertion_id_ref = saml.AssertionIDRef()

    def testAccessors(self):
        """Test for AssertionIDRef accessors"""
        self.assertion_id_ref.text = "zzlieajngjbkjggjldmgindkckkolcblndbghlhm"
        new_assertion_id_ref = saml.AssertionIDRefFromString(
            self.assertion_id_ref.to_string())
        assert new_assertion_id_ref.text == \
                                "zzlieajngjbkjggjldmgindkckkolcblndbghlhm"

    def testUsingTestData(self):
        """Test AssertionIDRefFromString() using test data"""
        new_assertion_id_ref = saml.AssertionIDRefFromString(
            test_data.TEST_ASSERTION_ID_REF)
        assert new_assertion_id_ref.text.strip() == \
                                "zzlieajngjbkjggjldmgindkckkolcblndbghlhm"


class TestAssertionURIRef:

    def setup_class(self):
        self.assertion_uri_ref = saml.AssertionURIRef()

    def testAccessors(self):
        """Test for AssertionURIRef accessors"""
        self.assertion_uri_ref.text = "http://www.sios.com/AssertionURIRef"
        new_assertion_uri_ref = saml.AssertionURIRefFromString(
            self.assertion_uri_ref.to_string())
        assert new_assertion_uri_ref.text == \
                                 "http://www.sios.com/AssertionURIRef"

    def testUsingTestData(self):
        """Test AssertionURIRefFromString() using test data"""
        new_assertion_uri_ref = saml.AssertionURIRefFromString(
            test_data.TEST_ASSERTION_URI_REF)
        assert new_assertion_uri_ref.text.strip() == \
                                 "http://www.sios.com/AssertionURIRef"


class TestAction:

    def setup_class(self):
        self.action = saml.Action()

    def testAccessors(self):
        """Test for Action accessors"""
        self.action.namespace = "http://www.sios.com/Namespace"
        new_action = saml.ActionFromString(self.action.to_string())
        assert new_action.namespace == "http://www.sios.com/Namespace"

    def testUsingTestData(self):
        """Test ActionFromString() using test data"""
        new_action = saml.ActionFromString(test_data.TEST_ACTION)
        assert new_action.namespace == "http://www.sios.com/Namespace"


class TestEvidence:

    def setup_class(self):
        self.evidence = saml.Evidence()

    def testAccessors(self):
        """Test for Evidence accessors"""
        self.evidence.assertion_id_ref.append(saml.AssertionIDRef())
        self.evidence.assertion_uri_ref.append(saml.AssertionURIRef())
        self.evidence.assertion.append(saml.Assertion())
        self.evidence.encrypted_assertion.append(saml.EncryptedAssertion())
        new_evidence = saml.EvidenceFromString(self.evidence.to_string())
        assert self.evidence.to_string() == new_evidence.to_string()
        assert isinstance(new_evidence.assertion_id_ref[0],
                                                        saml.AssertionIDRef)
        assert isinstance(new_evidence.assertion_uri_ref[0],
                                                        saml.AssertionURIRef)
        assert isinstance(new_evidence.assertion[0], saml.Assertion)
        assert isinstance(new_evidence.encrypted_assertion[0],
                                                        saml.EncryptedAssertion)

    def testUsingTestData(self):
        """Test EvidenceFromString() using test data"""
        # TODO:
        pass


class TestAuthzDecisionStatement:

    def setup_class(self):
        self.authz_decision_statement = saml.AuthzDecisionStatement()

    def testAccessors(self):
        """Test for AuthzDecisionStatement accessors"""
        self.authz_decision_statement.resource = "http://www.sios.com/Resource"
        self.authz_decision_statement.decision = saml.DECISION_TYPE_PERMIT
        self.authz_decision_statement.action.append(saml.Action())
        self.authz_decision_statement.evidence.append(saml.Evidence())
        new_authz_decision_statement = saml.AuthzDecisionStatementFromString(
            self.authz_decision_statement.to_string())
        assert self.authz_decision_statement.to_string() == \
                                 new_authz_decision_statement.to_string()
        assert new_authz_decision_statement.resource == \
                                 "http://www.sios.com/Resource"
        assert new_authz_decision_statement.decision == \
                                 saml.DECISION_TYPE_PERMIT
        assert isinstance(new_authz_decision_statement.action[0],
                                                        saml.Action)
        assert isinstance(new_authz_decision_statement.evidence[0],
                                                        saml.Evidence)


    def testUsingTestData(self):
        """Test AuthzDecisionStatementFromString() using test data"""
        # TODO:
        pass

class TestAdvice:

    def setup_class(self):
        self.advice = saml.Advice()

    def testAccessors(self):
        """Test for Advice accessors"""
        self.advice.assertion_id_ref.append(saml.AssertionIDRef())
        self.advice.assertion_uri_ref.append(saml.AssertionURIRef())
        self.advice.assertion.append(saml.Assertion())
        self.advice.encrypted_assertion.append(saml.EncryptedAssertion())
        new_advice = saml.AdviceFromString(self.advice.to_string())
        assert self.advice.to_string() == new_advice.to_string()
        assert isinstance(new_advice.assertion_id_ref[0],
                                                        saml.AssertionIDRef)
        assert isinstance(new_advice.assertion_uri_ref[0],
                                                        saml.AssertionURIRef)
        assert isinstance(new_advice.assertion[0], saml.Assertion)
        assert isinstance(new_advice.encrypted_assertion[0],
                                                        saml.EncryptedAssertion)

    def testUsingTestData(self):
        """Test AdviceFromString() using test data"""
        # TODO:
        pass


class TestAssertion:

    def setup_class(self):
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

        new_assertion = saml.AssertionFromString(self.assertion.to_string())
        assert new_assertion.id == "assertion id"
        assert new_assertion.version == saml.V2
        assert new_assertion.issue_instant == "2007-08-31T01:05:02Z"
        assert isinstance(new_assertion.issuer, saml.Issuer)
        assert isinstance(new_assertion.signature, ds.Signature)
        assert isinstance(new_assertion.subject, saml.Subject)
        assert isinstance(new_assertion.conditions, saml.Conditions)
        assert isinstance(new_assertion.advice, saml.Advice)
        assert isinstance(new_assertion.statement[0], saml.Statement)
        assert isinstance(new_assertion.authn_statement[0],
                                                saml.AuthnStatement)
        assert isinstance(new_assertion.authz_decision_statement[0],
                                                saml.AuthzDecisionStatement)
        assert isinstance(new_assertion.attribute_statement[0],
                                                saml.AttributeStatement)


    def testUsingTestData(self):
        """Test AssertionFromString() using test data"""
        # TODO
        pass
