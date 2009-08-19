#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for saml2.md"""

__author__ = 'tmatsuo@sios.com (Takashi MATSUO)'

import unittest
try:
  from xml.etree import ElementTree
except ImportError:
  from elementtree import ElementTree
import saml2
from saml2 import saml, samlp, md, md_test_data, ds_test_data
import xmldsig as ds

class EndpointTest(unittest.TestCase):

  def setUp(self):
    self.endpoint = md.Endpoint()

  def testAccessors(self):
    """Test for Endpoint accessors"""
    self.endpoint.binding = saml2.BINDING_HTTP_POST
    self.endpoint.location = "http://www.example.com/endpoint"
    self.endpoint.response_location = "http://www.example.com/response"
    new_endpoint = md.EndpointFromString(self.endpoint.ToString())
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

  def testUsingTestData(self):
    """Test for EndpointFromString() using test data."""
    new_endpoint = md.EndpointFromString(md_test_data.TEST_ENDPOINT)
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")
    

class IndexedEndpointTest(unittest.TestCase):

  def setUp(self):
    self.i_e = md.IndexedEndpoint()

  def testAccessors(self):
    """Test for IndexedEndpoint accessors"""
    self.i_e.binding = saml2.BINDING_HTTP_POST
    self.i_e.location = "http://www.example.com/endpoint"
    self.i_e.response_location = "http://www.example.com/response"
    self.i_e.index = "1"
    self.i_e.is_default = "false"
    new_i_e = md.IndexedEndpointFromString(self.i_e.ToString())
    self.assert_(new_i_e.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_i_e.location == "http://www.example.com/endpoint")
    self.assert_(new_i_e.response_location ==
                 "http://www.example.com/response")
    self.assert_(new_i_e.index == "1")
    self.assert_(new_i_e.is_default == "false")

  def testUsingTestData(self):
    """Test for IndexedEndpointFromString() using test data."""
    new_i_e = md.IndexedEndpointFromString(md_test_data.TEST_INDEXED_ENDPOINT)
    self.assert_(new_i_e.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_i_e.location == "http://www.example.com/endpoint")
    self.assert_(new_i_e.response_location ==
                 "http://www.example.com/response")
    self.assert_(new_i_e.index == "1")
    self.assert_(new_i_e.is_default == "false")


class ExtensionsTest(unittest.TestCase):

  def setUp(self):
    self.extensions = md.Extensions()

  def testAccessors(self):
    """Test for Extensions accessors"""
    self.extensions.extension_elements.append(
      saml2.ExtensionElementFromString(
      """<?xml version='1.0' encoding='UTF-8'?>
      <hoge>fuga</hoge>
      """))
    new_extensions = md.ExtensionsFromString(self.extensions.ToString())
    self.assert_(new_extensions.extension_elements[0].tag == "hoge")
    self.assert_(new_extensions.extension_elements[0].text.strip() ==
                 "fuga")


class OrganizationNameTest(unittest.TestCase):

  def setUp(self):
    self.organization_name = md.OrganizationName()

  def testAccessors(self):
    """Test for OrganizationName accessors"""
    self.organization_name.lang = "en"
    self.organization_name.text = "SIOS Technology, Inc."
    new_organization_name = md.OrganizationNameFromString(
      self.organization_name.ToString())
    self.assert_(new_organization_name.lang == "en")
    self.assert_(new_organization_name.text.strip() ==
                 "SIOS Technology, Inc.")

  def testUsingTestData(self):
    """Test for OrganizationNameFromString() using test data."""
    new_organization_name = md.OrganizationNameFromString(
      md_test_data.TEST_ORGANIZATION_NAME)
    self.assert_(new_organization_name.lang == "en")
    self.assert_(new_organization_name.text.strip() ==
                 "SIOS Technology, Inc.")


class OrganizationDisplayNameTest(unittest.TestCase):

  def setUp(self):
    self.od_name = md.OrganizationDisplayName()

  def testAccessors(self):
    """Test for OrganizationDisplayName accessors"""
    self.od_name.lang = "en"
    self.od_name.text = "SIOS"
    new_od_name = md.OrganizationDisplayNameFromString(
      self.od_name.ToString())
    self.assert_(new_od_name.lang == "en")
    self.assert_(new_od_name.text.strip() == "SIOS")

  def testUsingTestData(self):
    """Test for OrganizationDisplayNameFromString() using test data."""
    new_od_name = md.OrganizationDisplayNameFromString(
      md_test_data.TEST_ORGANIZATION_DISPLAY_NAME)
    self.assert_(new_od_name.lang == "en")
    self.assert_(new_od_name.text.strip() == "SIOS")


class OrganizationURLTest(unittest.TestCase):

  def setUp(self):
    self.organization_url = md.OrganizationURL()

  def testAccessors(self):
    """Test for OrganizationURL accessors"""
    self.organization_url.lang = "ja"
    self.organization_url.text = "http://www.sios.com/"
    new_organization_url = md.OrganizationURLFromString(
      self.organization_url.ToString())
    self.assert_(new_organization_url.lang == "ja")
    self.assert_(new_organization_url.text.strip() == "http://www.sios.com/")

  def testUsingTestData(self):
    """Test for OrganizationURLFromString() using test data."""
    new_organization_url = md.OrganizationURLFromString(
      md_test_data.TEST_ORGANIZATION_URL)
    self.assert_(new_organization_url.lang == "ja")
    self.assert_(new_organization_url.text.strip() == "http://www.sios.com/")


class OrganizationTest(unittest.TestCase):

  def setUp(self):
    self.organization = md.Organization()

  def testAccessors(self):
    """Test for Organization accessors"""
    self.organization.extensions = md.Extensions()
    self.organization.organization_name.append(
      md.OrganizationNameFromString(md_test_data.TEST_ORGANIZATION_NAME))
    self.organization.organization_display_name.append(
      md.OrganizationDisplayNameFromString(
      md_test_data.TEST_ORGANIZATION_DISPLAY_NAME))
    self.organization.organization_url.append(
      md.OrganizationURLFromString(md_test_data.TEST_ORGANIZATION_URL))
    new_organization = md.OrganizationFromString(self.organization.ToString())
    self.assert_(isinstance(new_organization.extensions, md.Extensions))
    self.assert_(isinstance(new_organization.organization_name[0],
                            md.OrganizationName))
    self.assert_(isinstance(new_organization.organization_display_name[0],
                            md.OrganizationDisplayName))
    self.assert_(isinstance(new_organization.organization_url[0],
                            md.OrganizationURL))
    self.assert_(new_organization.organization_name[0].text.strip() ==
                 "SIOS Technology, Inc.")
    self.assert_(new_organization.organization_name[0].lang == "en")
    self.assert_(new_organization.organization_display_name[0].text.strip() ==
                 "SIOS")
    self.assert_(new_organization.organization_display_name[0].lang == "en")
    self.assert_(new_organization.organization_url[0].text.strip() ==
                 "http://www.sios.com/")
    self.assert_(new_organization.organization_url[0].lang == "ja")
    

  def testUsingTestData(self):
    """Test for OrganizationFromString() using test data."""
    new_organization = md.OrganizationFromString(
      md_test_data.TEST_ORGANIZATION)
    self.assert_(isinstance(new_organization.extensions, md.Extensions))
    self.assert_(isinstance(new_organization.organization_name[0],
                            md.OrganizationName))
    self.assert_(isinstance(new_organization.organization_display_name[0],
                            md.OrganizationDisplayName))
    self.assert_(isinstance(new_organization.organization_url[0],
                            md.OrganizationURL))
    self.assert_(new_organization.organization_name[0].text.strip() ==
                 "SIOS Technology, Inc.")
    self.assert_(new_organization.organization_name[0].lang == "en")
    self.assert_(new_organization.organization_display_name[0].text.strip() ==
                 "SIOS")
    self.assert_(new_organization.organization_display_name[0].lang == "en")
    self.assert_(new_organization.organization_url[0].text.strip() ==
                 "http://www.sios.com/")
    self.assert_(new_organization.organization_url[0].lang == "ja")


class ContactPersonTest(unittest.TestCase):

  def setUp(self):
    self.contact_person = md.ContactPerson()

  def testAccessors(self):
    """Test for ContactPerson accessors"""
    self.contact_person.contact_type = "technical"
    self.contact_person.extensions = md.Extensions()
    self.contact_person.company = md.Company(text="SIOS Technology, Inc.")
    self.contact_person.given_name = md.GivenName(text="Takashi")
    self.contact_person.sur_name = md.SurName(text="Matsuo")
    self.contact_person.email_address.append(
      md.EmailAddress(text="tmatsuo@sios.com"))
    self.contact_person.email_address.append(
      md.EmailAddress(text="tmatsuo@shehas.net"))
    self.contact_person.telephone_number.append(
      md.TelephoneNumber(text="00-0000-0000"))
    new_contact_person = md.ContactPersonFromString(
      self.contact_person.ToString())
    self.assert_(new_contact_person.contact_type == "technical")
    self.assert_(isinstance(new_contact_person.extensions, md.Extensions))
    self.assert_(new_contact_person.company.text.strip() ==
                 "SIOS Technology, Inc.")
    self.assert_(new_contact_person.given_name.text.strip() == "Takashi")
    self.assert_(new_contact_person.sur_name.text.strip() == "Matsuo")
    self.assert_(new_contact_person.email_address[0].text.strip() ==
                 "tmatsuo@sios.com")
    self.assert_(new_contact_person.email_address[1].text.strip() ==
                 "tmatsuo@shehas.net")
    self.assert_(new_contact_person.telephone_number[0].text.strip() ==
                 "00-0000-0000")

  def testUsingTestData(self):
    """Test for ContactPersonFromString() using test data."""
    new_contact_person = md.ContactPersonFromString(
      md_test_data.TEST_CONTACT_PERSON)
    self.assert_(new_contact_person.contact_type == "technical")
    self.assert_(isinstance(new_contact_person.extensions, md.Extensions))
    self.assert_(new_contact_person.company.text.strip() ==
                 "SIOS Technology, Inc.")
    self.assert_(new_contact_person.given_name.text.strip() == "Takashi")
    self.assert_(new_contact_person.sur_name.text.strip() == "Matsuo")
    self.assert_(new_contact_person.email_address[0].text.strip() ==
                 "tmatsuo@sios.com")
    self.assert_(new_contact_person.email_address[1].text.strip() ==
                 "tmatsuo@shehas.net")
    self.assert_(new_contact_person.telephone_number[0].text.strip() ==
                 "00-0000-0000")

class AdditionalMetadataLocationTest(unittest.TestCase):

  def setUp(self):
    self.additional_metadata_location = md.AdditionalMetadataLocation()

  def testAccessors(self):
    """Test for AdditionalMetadataLocation accessors"""
    self.additional_metadata_location.namespace = (
      "http://www.sios.com/namespace")
    self.additional_metadata_location.text = (
      "http://www.sios.com/AdditionalMetadataLocation")
    new_additional_metadata_location = md.AdditionalMetadataLocationFromString(
      self.additional_metadata_location.ToString())
    self.assert_(new_additional_metadata_location.namespace ==
                 "http://www.sios.com/namespace")
    self.assert_(new_additional_metadata_location.text.strip() ==
                 "http://www.sios.com/AdditionalMetadataLocation")

  def testUsingTestData(self):
    """Test for AdditionalMetadataLocationFromString() using test data."""
    new_additional_metadata_location = md.AdditionalMetadataLocationFromString(
      md_test_data.TEST_ADDITIONAL_METADATA_LOCATION)
    self.assert_(new_additional_metadata_location.namespace ==
                 "http://www.sios.com/namespace")
    self.assert_(new_additional_metadata_location.text.strip() ==
                 "http://www.sios.com/AdditionalMetadataLocation")

class KeySizeTest(unittest.TestCase):

  def setUp(self):
    self.key_size = md.KeySize()

  def testAccessors(self):
    """Test for KeySize accessors"""
    self.key_size.text = "128"
    new_key_size = md.KeySizeFromString(self.key_size.ToString())
    self.assert_(new_key_size.text.strip() == "128")

  def testUsingTestData(self):
    """Test for KeySizeFromString() using test data."""
    new_key_size = md.KeySizeFromString(md_test_data.TEST_KEY_SIZE)
    self.assert_(new_key_size.text.strip() == "128")
    

class OAEPparamsTest(unittest.TestCase):

  def setUp(self):
    self.oaep_params = md.OAEPparams()

  def testAccessors(self):
    """Test for OAEPparams accessors"""
    self.oaep_params.text = "9lWu3Q=="
    new_oaep_params = md.OAEPparamsFromString(self.oaep_params.ToString())
    self.assert_(new_oaep_params.text.strip() == "9lWu3Q==")

  def testUsingTestData(self):
    """Test for OAEPparamsFromString() using test data."""
    new_oaep_params = md.OAEPparamsFromString(md_test_data.TEST_OAEP_PARAMS)
    self.assert_(new_oaep_params.text.strip() == "9lWu3Q==")


class EncryptionMethodTest(unittest.TestCase):

  def setUp(self):
    self.encryption_method = md.EncryptionMethod()

  def testAccessors(self):
    """Test for EncryptionMethod accessors"""
    self.encryption_method.algorithm = (
      "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
    self.encryption_method.oaep_params = md.OAEPparams(text="9lWu3Q==")
    self.encryption_method.digest_method = ds.DigestMethod(
      algorithm="http://www.w3.org/2000/09/xmldsig#sha1")
    new_encryption_method = md.EncryptionMethodFromString(
      self.encryption_method.ToString())
    self.assert_(new_encryption_method.algorithm ==
                 "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
    self.assert_(new_encryption_method.oaep_params.text.strip() == "9lWu3Q==")
    self.assert_(new_encryption_method.digest_method.algorithm ==
                 "http://www.w3.org/2000/09/xmldsig#sha1")

  def testUsingTestData(self):
    """Test for EncryptionMethodFromString() using test data."""
    new_encryption_method = md.EncryptionMethodFromString(
      md_test_data.TEST_ENCRYPTION_METHOD)
    self.assert_(new_encryption_method.algorithm ==
                 "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
    self.assert_(new_encryption_method.oaep_params.text.strip() == "9lWu3Q==")
    self.assert_(new_encryption_method.digest_method.algorithm ==
                 "http://www.w3.org/2000/09/xmldsig#sha1")


class KeyDescriptorTest(unittest.TestCase):

  def setUp(self):
    self.key_descriptor = md.KeyDescriptor()

  def testAccessors(self):
    """Test for KeyDescriptor accessors"""

    self.key_descriptor.use = "signing"
    self.key_descriptor.key_info = ds.KeyInfoFromString(
      ds_test_data.TEST_KEY_INFO)
    self.key_descriptor.encryption_method.append(md.EncryptionMethodFromString(
      md_test_data.TEST_ENCRYPTION_METHOD))
    new_key_descriptor = md.KeyDescriptorFromString(
      self.key_descriptor.ToString())
    self.assert_(new_key_descriptor.use == "signing")
    self.assert_(isinstance(new_key_descriptor.key_info, ds.KeyInfo))
    self.assert_(isinstance(new_key_descriptor.encryption_method[0],
                            md.EncryptionMethod))

  def testUsingTestData(self):
    """Test for KeyDescriptorFromString() using test data."""
    new_key_descriptor = md.KeyDescriptorFromString(
      md_test_data.TEST_KEY_DESCRIPTOR)
    self.assert_(new_key_descriptor.use == "signing")
    self.assert_(isinstance(new_key_descriptor.key_info, ds.KeyInfo))
    self.assert_(isinstance(new_key_descriptor.encryption_method[0],
                            md.EncryptionMethod))


class RoleDescriptorTest(unittest.TestCase):
  def setUp(self):
    self.role_descriptor = md.RoleDescriptor()

  def testAccessors(self):
    """Test for RoleDescriptor accessors"""
    self.role_descriptor.id = "ID"
    self.role_descriptor.valid_until = "2008-09-14T01:05:02Z"
    self.role_descriptor.cache_duration = "10:00:00:00"
    self.role_descriptor.protocol_support_enumeration = samlp.SAMLP_NAMESPACE
    self.role_descriptor.error_url = "http://www.sios.com/errorURL"
    self.role_descriptor.signature = ds.GetEmptySignature()
    self.role_descriptor.extensions = md.Extensions()
    self.role_descriptor.key_descriptor.append(md.KeyDescriptorFromString(
      md_test_data.TEST_KEY_DESCRIPTOR))
    self.role_descriptor.organization = md.Organization()
    self.role_descriptor.contact_person.append(md.ContactPerson())

    new_role_descriptor = md.RoleDescriptorFromString(
      self.role_descriptor.ToString())
    self.assert_(new_role_descriptor.id == "ID")
    self.assert_(new_role_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_role_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_role_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_role_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_role_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_role_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_role_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_role_descriptor.organization, md.Organization))
    self.assert_(isinstance(new_role_descriptor.contact_person[0],
                            md.ContactPerson))

  def testUsingTestData(self):
    """Test for RoleDescriptorFromString() using test data."""
    new_role_descriptor = md.RoleDescriptorFromString(
      md_test_data.TEST_ROLE_DESCRIPTOR)
    self.assert_(new_role_descriptor.id == "ID")
    self.assert_(new_role_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_role_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_role_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_role_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_role_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_role_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_role_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_role_descriptor.organization, md.Organization))
    self.assert_(isinstance(new_role_descriptor.contact_person[0],
                            md.ContactPerson))

class SSODescriptorTest(unittest.TestCase):
  def setUp(self):
    self.sso_descriptor = md.SSODescriptor()

  def testAccessors(self):
    """Test for SSODescriptor accessors"""
    self.sso_descriptor.id = "ID"
    self.sso_descriptor.valid_until = "2008-09-14T01:05:02Z"
    self.sso_descriptor.cache_duration = "10:00:00:00"
    self.sso_descriptor.protocol_support_enumeration = samlp.SAMLP_NAMESPACE
    self.sso_descriptor.error_url = "http://www.sios.com/errorURL"
    self.sso_descriptor.signature = ds.GetEmptySignature()
    self.sso_descriptor.extensions = md.Extensions()
    self.sso_descriptor.key_descriptor.append(md.KeyDescriptorFromString(
      md_test_data.TEST_KEY_DESCRIPTOR))
    self.sso_descriptor.organization = md.Organization()
    self.sso_descriptor.contact_person.append(md.ContactPerson())
    self.sso_descriptor.artifact_resolution_service.append(
      md.ArtifactResolutionService())
    self.sso_descriptor.single_logout_service.append(
      md.SingleLogoutService())
    self.sso_descriptor.manage_name_id_service.append(
      md.ManageNameIDService())
    self.sso_descriptor.name_id_format.append(
      md.NameIDFormat())

    new_sso_descriptor = md.SSODescriptorFromString(
      self.sso_descriptor.ToString())
    self.assert_(new_sso_descriptor.id == "ID")
    self.assert_(new_sso_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_sso_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_sso_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_sso_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_sso_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_sso_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_sso_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_sso_descriptor.organization, md.Organization))
    self.assert_(isinstance(new_sso_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(new_sso_descriptor.artifact_resolution_service[0],
                            md.ArtifactResolutionService))
    self.assert_(isinstance(new_sso_descriptor.single_logout_service[0],
                            md.SingleLogoutService))
    self.assert_(isinstance(new_sso_descriptor.manage_name_id_service[0],
                            md.ManageNameIDService))
    self.assert_(isinstance(new_sso_descriptor.name_id_format[0],
                            md.NameIDFormat))

  def testUsingTestData(self):
    """Test for SSODescriptorFromString() using test data."""
    new_sso_descriptor = md.SSODescriptorFromString(
      md_test_data.TEST_SSO_DESCRIPTOR)
    self.assert_(new_sso_descriptor.id == "ID")
    self.assert_(new_sso_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_sso_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_sso_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_sso_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_sso_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_sso_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_sso_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_sso_descriptor.organization, md.Organization))
    self.assert_(isinstance(new_sso_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(new_sso_descriptor.artifact_resolution_service[0],
                            md.ArtifactResolutionService))
    self.assert_(isinstance(new_sso_descriptor.single_logout_service[0],
                            md.SingleLogoutService))
    self.assert_(isinstance(new_sso_descriptor.manage_name_id_service[0],
                            md.ManageNameIDService))
    self.assert_(isinstance(new_sso_descriptor.name_id_format[0],
                            md.NameIDFormat))


class ArtifactResolutionServiceTest(unittest.TestCase):

  def setUp(self):
    self.i_e = md.ArtifactResolutionService()

  def testAccessors(self):
    """Test for ArtifactResolutionService accessors"""
    self.i_e.binding = saml2.BINDING_HTTP_POST
    self.i_e.location = "http://www.example.com/endpoint"
    self.i_e.response_location = "http://www.example.com/response"
    self.i_e.index = "1"
    self.i_e.is_default = "false"
    new_i_e = md.ArtifactResolutionServiceFromString(self.i_e.ToString())
    self.assert_(new_i_e.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_i_e.location == "http://www.example.com/endpoint")
    self.assert_(new_i_e.response_location ==
                 "http://www.example.com/response")
    self.assert_(new_i_e.index == "1")
    self.assert_(new_i_e.is_default == "false")

  def testUsingTestData(self):
    """Test for ArtifactResolutionServiceFromString() using test data."""
    new_i_e = md.ArtifactResolutionServiceFromString(
      md_test_data.TEST_ARTIFACT_RESOLUTION_SERVICE)
    self.assert_(new_i_e.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_i_e.location == "http://www.example.com/endpoint")
    self.assert_(new_i_e.response_location ==
                 "http://www.example.com/response")
    self.assert_(new_i_e.index == "1")
    self.assert_(new_i_e.is_default == "false")


class SingleLogoutService(unittest.TestCase):

  def setUp(self):
    self.endpoint = md.SingleLogoutService()

  def testAccessors(self):
    """Test for SingleLogoutService accessors"""
    self.endpoint.binding = saml2.BINDING_HTTP_POST
    self.endpoint.location = "http://www.example.com/endpoint"
    self.endpoint.response_location = "http://www.example.com/response"
    new_endpoint = md.SingleLogoutServiceFromString(self.endpoint.ToString())
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

  def testUsingTestData(self):
    """Test for SingleLogoutServiceFromString() using test data."""
    new_endpoint = md.SingleLogoutServiceFromString(
      md_test_data.TEST_SINGLE_LOGOUT_SERVICE)
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")
    

class ManageNameIDServiceTest(unittest.TestCase):

  def setUp(self):
    self.endpoint = md.ManageNameIDService()

  def testAccessors(self):
    """Test for ManageNameIDService accessors"""
    self.endpoint.binding = saml2.BINDING_HTTP_POST
    self.endpoint.location = "http://www.example.com/endpoint"
    self.endpoint.response_location = "http://www.example.com/response"
    new_endpoint = md.ManageNameIDServiceFromString(self.endpoint.ToString())
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

  def testUsingTestData(self):
    """Test for ManageNameIDServiceFromString() using test data."""
    new_endpoint = md.ManageNameIDServiceFromString(
      md_test_data.TEST_MANAGE_NAMEID_SERVICE)
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")
    

class NameIDFormatTest(unittest.TestCase):

  def setUp(self):
    self.name_id_format = md.NameIDFormat()

  def testAccessors(self):
    """Test for NameIDFormat accessors"""
    self.name_id_format.text = saml.NAMEID_FORMAT_EMAILADDRESS
    new_name_id_format = md.NameIDFormatFromString(
      self.name_id_format.ToString())
    self.assert_(new_name_id_format.text.strip() ==
                 saml.NAMEID_FORMAT_EMAILADDRESS)

  def testUsingTestData(self):
    """Test for NameIDFormatFromString() using test data."""
    new_name_id_format = md.NameIDFormatFromString(
      md_test_data.TEST_NAME_ID_FORMAT)
    self.assert_(new_name_id_format.text.strip() ==
                 saml.NAMEID_FORMAT_EMAILADDRESS)
  

class SingleSignOnServiceTest(unittest.TestCase):

  def setUp(self):
    self.endpoint = md.SingleSignOnService()

  def testAccessors(self):
    """Test for SingelSignOnService accessors"""
    self.endpoint.binding = saml2.BINDING_HTTP_POST
    self.endpoint.location = "http://www.example.com/endpoint"
    self.endpoint.response_location = "http://www.example.com/response"
    new_endpoint = md.SingleSignOnServiceFromString(self.endpoint.ToString())
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

  def testUsingTestData(self):
    """Test for SingelSignOnServiceFromString() using test data."""
    new_endpoint = md.SingleSignOnServiceFromString(
      md_test_data.TEST_SINGLE_SIGN_ON_SERVICE)
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

class NameIDMappingServiceTest(unittest.TestCase):

  def setUp(self):
    self.endpoint = md.NameIDMappingService()

  def testAccessors(self):
    """Test for NameIDMappingService accessors"""
    self.endpoint.binding = saml2.BINDING_HTTP_POST
    self.endpoint.location = "http://www.example.com/endpoint"
    self.endpoint.response_location = "http://www.example.com/response"
    new_endpoint = md.NameIDMappingServiceFromString(self.endpoint.ToString())
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

  def testUsingTestData(self):
    """Test for NameIDMappingServiceFromString() using test data."""
    new_endpoint = md.NameIDMappingServiceFromString(
      md_test_data.TEST_NAME_ID_MAPPING_SERVICE)
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

class AssertionIDRequestServiceTest(unittest.TestCase):

  def setUp(self):
    self.endpoint = md.AssertionIDRequestService()

  def testAccessors(self):
    """Test for AssertionIDRequestService accessors"""
    self.endpoint.binding = saml2.BINDING_HTTP_POST
    self.endpoint.location = "http://www.example.com/endpoint"
    self.endpoint.response_location = "http://www.example.com/response"
    new_endpoint = md.AssertionIDRequestServiceFromString(
      self.endpoint.ToString())
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

  def testUsingTestData(self):
    """Test for AssertionIDRequestServiceFromString() using test data."""
    new_endpoint = md.AssertionIDRequestServiceFromString(
      md_test_data.TEST_ASSERTION_ID_REQUEST_SERVICE)
    self.assert_(new_endpoint.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_endpoint.location == "http://www.example.com/endpoint")
    self.assert_(new_endpoint.response_location ==
                 "http://www.example.com/response")

class AttributeProfileTest(unittest.TestCase):

  def setUp(self):
    self.attribute_profile = md.AttributeProfile()

  def testAccessors(self):
    """Test for AttributeProfile accessors"""
    self.attribute_profile.text = saml.PROFILE_ATTRIBUTE_BASIC
    new_attribute_profile = md.AttributeProfileFromString(
      self.attribute_profile.ToString())
    self.assert_(new_attribute_profile.text.strip() ==
                 saml.PROFILE_ATTRIBUTE_BASIC)

  def testUsingTestData(self):
    """Test for NameIDFormatFromString() using test data."""
    new_attribute_profile = md.AttributeProfileFromString(
      md_test_data.TEST_ATTRIBUTE_PROFILE)
    self.assert_(new_attribute_profile.text.strip() ==
                 saml.PROFILE_ATTRIBUTE_BASIC)
  

class IDPSSODescriptorTest(unittest.TestCase):
  def setUp(self):
    self.idp_sso_descriptor = md.IDPSSODescriptor()

  def testAccessors(self):
    """Test for IDPSSODescriptor accessors"""
    self.idp_sso_descriptor.id = "ID"
    self.idp_sso_descriptor.valid_until = "2008-09-14T01:05:02Z"
    self.idp_sso_descriptor.cache_duration = "10:00:00:00"
    self.idp_sso_descriptor.protocol_support_enumeration = \
                                                         samlp.SAMLP_NAMESPACE
    self.idp_sso_descriptor.error_url = "http://www.sios.com/errorURL"
    self.idp_sso_descriptor.signature = ds.GetEmptySignature()
    self.idp_sso_descriptor.extensions = md.Extensions()
    self.idp_sso_descriptor.key_descriptor.append(md.KeyDescriptorFromString(
      md_test_data.TEST_KEY_DESCRIPTOR))
    self.idp_sso_descriptor.organization = md.Organization()
    self.idp_sso_descriptor.contact_person.append(md.ContactPerson())
    self.idp_sso_descriptor.artifact_resolution_service.append(
      md.ArtifactResolutionService())
    self.idp_sso_descriptor.single_logout_service.append(
      md.SingleLogoutService())
    self.idp_sso_descriptor.manage_name_id_service.append(
      md.ManageNameIDService())
    self.idp_sso_descriptor.name_id_format.append(
      md.NameIDFormat())
    self.idp_sso_descriptor.want_authn_requests_signed = 'true'
    self.idp_sso_descriptor.single_sign_on_service.append(
      md.SingleSignOnService())
    self.idp_sso_descriptor.name_id_mapping_service.append(
      md.NameIDMappingService())
    self.idp_sso_descriptor.assertion_id_request_service.append(
      md.AssertionIDRequestService())
    self.idp_sso_descriptor.attribute_profile.append(
      md.AttributeProfile())
    self.idp_sso_descriptor.attribute.append(saml.Attribute())

    new_idp_sso_descriptor = md.IDPSSODescriptorFromString(
      self.idp_sso_descriptor.ToString())
    self.assert_(new_idp_sso_descriptor.id == "ID")
    self.assert_(new_idp_sso_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_idp_sso_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_idp_sso_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_idp_sso_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_idp_sso_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_idp_sso_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_idp_sso_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_idp_sso_descriptor.organization,
                            md.Organization))
    self.assert_(isinstance(new_idp_sso_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(
      new_idp_sso_descriptor.artifact_resolution_service[0],
      md.ArtifactResolutionService))
    self.assert_(isinstance(new_idp_sso_descriptor.single_logout_service[0],
                            md.SingleLogoutService))
    self.assert_(isinstance(new_idp_sso_descriptor.manage_name_id_service[0],
                            md.ManageNameIDService))
    self.assert_(isinstance(new_idp_sso_descriptor.name_id_format[0],
                            md.NameIDFormat))
    self.assert_(new_idp_sso_descriptor.want_authn_requests_signed == "true")
    self.assert_(isinstance(new_idp_sso_descriptor.single_sign_on_service[0],
                            md.SingleSignOnService))
    self.assert_(isinstance(new_idp_sso_descriptor.name_id_mapping_service[0],
                            md.NameIDMappingService))
    self.assert_(isinstance(
      new_idp_sso_descriptor.assertion_id_request_service[0],
      md.AssertionIDRequestService))
    self.assert_(isinstance(new_idp_sso_descriptor.attribute_profile[0],
                            md.AttributeProfile))
    self.assert_(isinstance(new_idp_sso_descriptor.attribute[0],
                            saml.Attribute))

  def testUsingTestData(self):
    """Test for IDPSSODescriptorFromString() using test data."""
    new_idp_sso_descriptor = md.IDPSSODescriptorFromString(
      md_test_data.TEST_IDP_SSO_DESCRIPTOR)
    self.assert_(new_idp_sso_descriptor.id == "ID")
    self.assert_(new_idp_sso_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_idp_sso_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_idp_sso_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_idp_sso_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_idp_sso_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_idp_sso_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_idp_sso_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_idp_sso_descriptor.organization,
                            md.Organization))
    self.assert_(isinstance(new_idp_sso_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(
      new_idp_sso_descriptor.artifact_resolution_service[0],
      md.ArtifactResolutionService))
    self.assert_(isinstance(new_idp_sso_descriptor.single_logout_service[0],
                            md.SingleLogoutService))
    self.assert_(isinstance(new_idp_sso_descriptor.manage_name_id_service[0],
                            md.ManageNameIDService))
    self.assert_(isinstance(new_idp_sso_descriptor.name_id_format[0],
                            md.NameIDFormat))
    self.assert_(new_idp_sso_descriptor.want_authn_requests_signed == "true")
    self.assert_(isinstance(new_idp_sso_descriptor.single_sign_on_service[0],
                            md.SingleSignOnService))
    self.assert_(isinstance(new_idp_sso_descriptor.name_id_mapping_service[0],
                            md.NameIDMappingService))
    self.assert_(isinstance(
      new_idp_sso_descriptor.assertion_id_request_service[0],
      md.AssertionIDRequestService))
    self.assert_(isinstance(new_idp_sso_descriptor.attribute_profile[0],
                            md.AttributeProfile))
    self.assert_(isinstance(new_idp_sso_descriptor.attribute[0],
                            saml.Attribute))


class AssertionConsumerServiceTest(unittest.TestCase):

  def setUp(self):
    self.i_e = md.AssertionConsumerService()

  def testAccessors(self):
    """Test for AssertionConsumerService accessors"""
    self.i_e.binding = saml2.BINDING_HTTP_POST
    self.i_e.location = "http://www.example.com/endpoint"
    self.i_e.response_location = "http://www.example.com/response"
    self.i_e.index = "1"
    self.i_e.is_default = "false"
    new_i_e = md.AssertionConsumerServiceFromString(self.i_e.ToString())
    self.assert_(new_i_e.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_i_e.location == "http://www.example.com/endpoint")
    self.assert_(new_i_e.response_location ==
                 "http://www.example.com/response")
    self.assert_(new_i_e.index == "1")
    self.assert_(new_i_e.is_default == "false")

  def testUsingTestData(self):
    """Test for AssertionConsumerServiceFromString() using test data."""
    new_i_e = md.AssertionConsumerServiceFromString(
      md_test_data.TEST_ASSERTION_CONSUMER_SERVICE)
    self.assert_(new_i_e.binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_i_e.location == "http://www.example.com/endpoint")
    self.assert_(new_i_e.response_location ==
                 "http://www.example.com/response")
    self.assert_(new_i_e.index == "1")
    self.assert_(new_i_e.is_default == "false")


class RequestedAttributeTest(unittest.TestCase):

  def setUp(self):
    self.requested_attribute = md.RequestedAttribute()

  def testAccessors(self):
    """Test for RequestedAttribute accessors"""
    self.assert_(isinstance(self.requested_attribute, saml.Attribute))
    self.assert_(isinstance(self.requested_attribute, md.RequestedAttribute))
    self.assert_(self.requested_attribute.is_required is None)
    self.requested_attribute.is_required = "true"
    new_requested_attribute = md.RequestedAttributeFromString(
      self.requested_attribute.ToString())
    self.assert_(new_requested_attribute.is_required == "true")
    self.assert_(isinstance(new_requested_attribute, saml.Attribute))
    self.assert_(isinstance(new_requested_attribute, md.RequestedAttribute))

  def testUsingTestData(self):
    """Test for RequestedAttributeFromString() using test data."""
    new_requested_attribute = md.RequestedAttributeFromString(
      md_test_data.TEST_REQUESTED_ATTRIBUTE)
    self.assert_(new_requested_attribute.is_required == "true")
    self.assert_(isinstance(new_requested_attribute, saml.Attribute))
    self.assert_(isinstance(new_requested_attribute, md.RequestedAttribute))


class ServiceNameTest(unittest.TestCase):

  def setUp(self):
    self.service_name = md.ServiceName()

  def testAccessors(self):
    """Test for ServiceName accessors"""
    self.service_name.lang = "en"
    self.service_name.text = "SIOS mail"
    new_service_name = md.ServiceNameFromString(self.service_name.ToString())
    self.assert_(new_service_name.lang == "en")
    self.assert_(new_service_name.text.strip() == "SIOS mail")

  def testUsingTestData(self):
    """Test for OrganizationNameFromString() using test data."""
    new_service_name = md.ServiceNameFromString(md_test_data.TEST_SERVICE_NAME)
    self.assert_(new_service_name.lang == "en")
    self.assert_(new_service_name.text.strip() == "SIOS mail")


class ServiceDescriptionTest(unittest.TestCase):

  def setUp(self):
    self.service_description = md.ServiceDescription()

  def testAccessors(self):
    """Test for ServiceDescription accessors"""
    self.service_description.lang = "en"
    self.service_description.text = "SIOS mail service"
    new_service_description = md.ServiceDescriptionFromString(
      self.service_description.ToString())
    self.assert_(new_service_description.lang == "en")
    self.assert_(new_service_description.text.strip() ==
                 "SIOS mail service")

  def testUsingTestData(self):
    """Test for OrganizationNameFromString() using test data."""
    new_service_description = md.ServiceDescriptionFromString(
      md_test_data.TEST_SERVICE_DESCRIPTION)
    self.assert_(new_service_description.lang == "en")
    self.assert_(new_service_description.text.strip() ==
                 "SIOS mail service")


class AttributeConsumingServiceTest(unittest.TestCase):

  def setUp(self):
    self.attribute_consuming_service = md.AttributeConsumingService()

  def testAccessors(self):
    """Test for AttributeConsumingService accessors"""
    self.attribute_consuming_service.service_name.append(md.ServiceName())
    self.attribute_consuming_service.service_description.append(
      md.ServiceDescription())
    self.attribute_consuming_service.requested_attribute.append(
      md.RequestedAttribute())
    self.attribute_consuming_service.index = "1"
    self.attribute_consuming_service.is_default = "true"

    new_attribute_consuming_service = md.AttributeConsumingServiceFromString(
      self.attribute_consuming_service.ToString())
    self.assert_(new_attribute_consuming_service.index == "1")
    self.assert_(new_attribute_consuming_service.is_default == "true")
    self.assert_(isinstance(new_attribute_consuming_service.service_name[0],
                 md.ServiceName))
    self.assert_(isinstance(
      new_attribute_consuming_service.service_description[0],
      md.ServiceDescription))
    self.assert_(isinstance(
      new_attribute_consuming_service.requested_attribute[0],
      md.RequestedAttribute))

  def testUsingTestData(self):
    """Test for AttributeConsumingServiceFromString() using test data."""
    new_attribute_consuming_service = md.AttributeConsumingServiceFromString(
      md_test_data.TEST_ATTRIBUTE_CONSUMING_SERVICE)
    self.assert_(new_attribute_consuming_service.index == "1")
    self.assert_(new_attribute_consuming_service.is_default == "true")
    self.assert_(isinstance(new_attribute_consuming_service.service_name[0],
                 md.ServiceName))
    self.assert_(isinstance(
      new_attribute_consuming_service.service_description[0],
      md.ServiceDescription))
    self.assert_(isinstance(
      new_attribute_consuming_service.requested_attribute[0],
      md.RequestedAttribute))


class SPSSODescriptorTest(unittest.TestCase):
  def setUp(self):
    self.sp_sso_descriptor = md.SPSSODescriptor()

  def testAccessors(self):
    """Test for SPSSODescriptor accessors"""
    self.sp_sso_descriptor.id = "ID"
    self.sp_sso_descriptor.valid_until = "2008-09-14T01:05:02Z"
    self.sp_sso_descriptor.cache_duration = "10:00:00:00"
    self.sp_sso_descriptor.protocol_support_enumeration = \
                                                         samlp.SAMLP_NAMESPACE
    self.sp_sso_descriptor.error_url = "http://www.sios.com/errorURL"
    self.sp_sso_descriptor.signature = ds.GetEmptySignature()
    self.sp_sso_descriptor.extensions = md.Extensions()
    self.sp_sso_descriptor.key_descriptor.append(md.KeyDescriptorFromString(
      md_test_data.TEST_KEY_DESCRIPTOR))
    self.sp_sso_descriptor.organization = md.Organization()
    self.sp_sso_descriptor.contact_person.append(md.ContactPerson())
    self.sp_sso_descriptor.artifact_resolution_service.append(
      md.ArtifactResolutionService())
    self.sp_sso_descriptor.single_logout_service.append(
      md.SingleLogoutService())
    self.sp_sso_descriptor.manage_name_id_service.append(
      md.ManageNameIDService())
    self.sp_sso_descriptor.name_id_format.append(
      md.NameIDFormat())
    self.sp_sso_descriptor.authn_requests_signed = "true"
    self.sp_sso_descriptor.want_assertions_signed = "true"
    self.sp_sso_descriptor.assertion_consumer_service.append(
      md.AssertionConsumerService())
    self.sp_sso_descriptor.attribute_consuming_service.append(
      md.AttributeConsumingService())

    new_sp_sso_descriptor = md.SPSSODescriptorFromString(
      self.sp_sso_descriptor.ToString())
    self.assert_(new_sp_sso_descriptor.id == "ID")
    self.assert_(new_sp_sso_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_sp_sso_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_sp_sso_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_sp_sso_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_sp_sso_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_sp_sso_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_sp_sso_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_sp_sso_descriptor.organization,
                            md.Organization))
    self.assert_(isinstance(new_sp_sso_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(
      new_sp_sso_descriptor.artifact_resolution_service[0],
      md.ArtifactResolutionService))
    self.assert_(isinstance(new_sp_sso_descriptor.single_logout_service[0],
                            md.SingleLogoutService))
    self.assert_(isinstance(new_sp_sso_descriptor.manage_name_id_service[0],
                            md.ManageNameIDService))
    self.assert_(isinstance(new_sp_sso_descriptor.name_id_format[0],
                            md.NameIDFormat))
    self.assert_(new_sp_sso_descriptor.authn_requests_signed == "true")
    self.assert_(new_sp_sso_descriptor.want_assertions_signed == "true")
    self.assert_(isinstance(
      new_sp_sso_descriptor.assertion_consumer_service[0],
      md.AssertionConsumerService))
    self.assert_(isinstance(
      new_sp_sso_descriptor.attribute_consuming_service[0],
      md.AttributeConsumingService))

  def testUsingTestData(self):
    """Test for SPSSODescriptorFromString() using test data."""
    new_sp_sso_descriptor = md.SPSSODescriptorFromString(
      md_test_data.TEST_SP_SSO_DESCRIPTOR)
    self.assert_(new_sp_sso_descriptor.id == "ID")
    self.assert_(new_sp_sso_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_sp_sso_descriptor.cache_duration == "10:00:00:00")
    self.assert_(new_sp_sso_descriptor.protocol_support_enumeration ==
                 samlp.SAMLP_NAMESPACE)
    self.assert_(new_sp_sso_descriptor.error_url ==
                 "http://www.sios.com/errorURL")
    self.assert_(isinstance(new_sp_sso_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_sp_sso_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_sp_sso_descriptor.key_descriptor[0],
                            md.KeyDescriptor))
    self.assert_(isinstance(new_sp_sso_descriptor.organization,
                            md.Organization))
    self.assert_(isinstance(new_sp_sso_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(
      new_sp_sso_descriptor.artifact_resolution_service[0],
      md.ArtifactResolutionService))
    self.assert_(isinstance(new_sp_sso_descriptor.single_logout_service[0],
                            md.SingleLogoutService))
    self.assert_(isinstance(new_sp_sso_descriptor.manage_name_id_service[0],
                            md.ManageNameIDService))
    self.assert_(isinstance(new_sp_sso_descriptor.name_id_format[0],
                            md.NameIDFormat))
    self.assert_(new_sp_sso_descriptor.authn_requests_signed == "true")
    self.assert_(new_sp_sso_descriptor.want_assertions_signed == "true")
    self.assert_(isinstance(
      new_sp_sso_descriptor.assertion_consumer_service[0],
      md.AssertionConsumerService))
    self.assert_(isinstance(
      new_sp_sso_descriptor.attribute_consuming_service[0],
      md.AttributeConsumingService))


class EntityDescriptorTest(unittest.TestCase):
  def setUp(self):
    self.entity_descriptor = md.EntityDescriptor()

  def testAccessors(self):
    """Test for RoleDescriptor accessors"""
    self.entity_descriptor.id = "ID"
    self.entity_descriptor.entity_id = "entityID"
    self.entity_descriptor.valid_until = "2008-09-14T01:05:02Z"
    self.entity_descriptor.cache_duration = "10:00:00:00"

    self.entity_descriptor.signature = ds.GetEmptySignature()
    self.entity_descriptor.extensions = md.Extensions()
    self.entity_descriptor.role_descriptor.append(md.RoleDescriptor())
    self.entity_descriptor.idp_sso_descriptor.append(md.IDPSSODescriptor())
    self.entity_descriptor.sp_sso_descriptor.append(md.SPSSODescriptor())
    self.entity_descriptor.organization = md.Organization()
    self.entity_descriptor.contact_person.append(md.ContactPerson())
    self.entity_descriptor.additional_metadata_location.append(
      md.AdditionalMetadataLocation())

    new_entity_descriptor = md.EntityDescriptorFromString(
      self.entity_descriptor.ToString())
    self.assert_(new_entity_descriptor.id == "ID")
    self.assert_(new_entity_descriptor.entity_id == "entityID")
    self.assert_(new_entity_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_entity_descriptor.cache_duration == "10:00:00:00")
    self.assert_(isinstance(new_entity_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_entity_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_entity_descriptor.role_descriptor[0],
                            md.RoleDescriptor))
    self.assert_(isinstance(new_entity_descriptor.idp_sso_descriptor[0],
                            md.IDPSSODescriptor))
    self.assert_(isinstance(new_entity_descriptor.sp_sso_descriptor[0],
                            md.SPSSODescriptor))
    self.assert_(isinstance(new_entity_descriptor.organization,
                            md.Organization))
    self.assert_(isinstance(new_entity_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(
      new_entity_descriptor.additional_metadata_location[0],
      md.AdditionalMetadataLocation))

  def testUsingTestData(self):
    """Test for EntityDescriptorFromString() using test data."""
    new_entity_descriptor = md.EntityDescriptorFromString(
      md_test_data.TEST_ENTITY_DESCRIPTOR)
    self.assert_(new_entity_descriptor.id == "ID")
    self.assert_(new_entity_descriptor.entity_id == "entityID")
    self.assert_(new_entity_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_entity_descriptor.cache_duration == "10:00:00:00")
    self.assert_(isinstance(new_entity_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_entity_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_entity_descriptor.role_descriptor[0],
                            md.RoleDescriptor))
    self.assert_(isinstance(new_entity_descriptor.idp_sso_descriptor[0],
                            md.IDPSSODescriptor))
    self.assert_(isinstance(new_entity_descriptor.sp_sso_descriptor[0],
                            md.SPSSODescriptor))
    self.assert_(isinstance(new_entity_descriptor.organization,
                            md.Organization))
    self.assert_(isinstance(new_entity_descriptor.contact_person[0],
                            md.ContactPerson))
    self.assert_(isinstance(
      new_entity_descriptor.additional_metadata_location[0],
      md.AdditionalMetadataLocation))


class EntitiesDescriptorTest(unittest.TestCase):
  def setUp(self):
    self.entities_descriptor = md.EntitiesDescriptor()

  def testAccessors(self):
    """Test for EntitiesDescriptor accessors"""
    self.entities_descriptor.id = "ID"
    self.entities_descriptor.name = "name"
    self.entities_descriptor.valid_until = "2008-09-14T01:05:02Z"
    self.entities_descriptor.cache_duration = "10:00:00:00"

    self.entities_descriptor.signature = ds.GetEmptySignature()
    self.entities_descriptor.extensions = md.Extensions()
    self.entities_descriptor.entity_descriptor.append(md.EntityDescriptor())
    self.entities_descriptor.entities_descriptor.append(
      md.EntitiesDescriptor())

    new_entities_descriptor = md.EntitiesDescriptorFromString(
      self.entities_descriptor.ToString())
    self.assert_(new_entities_descriptor.id == "ID")
    self.assert_(new_entities_descriptor.name == "name")
    self.assert_(new_entities_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_entities_descriptor.cache_duration == "10:00:00:00")
    self.assert_(isinstance(new_entities_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_entities_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_entities_descriptor.entity_descriptor[0],
                            md.EntityDescriptor))
    self.assert_(isinstance(new_entities_descriptor.entities_descriptor[0],
                            md.EntitiesDescriptor))

  def testUsingTestData(self):
    """Test for EntitiesDescriptorFromString() using test data."""
    new_entities_descriptor = md.EntitiesDescriptorFromString(
      md_test_data.TEST_ENTITIES_DESCRIPTOR)
    self.assert_(new_entities_descriptor.id == "ID")
    self.assert_(new_entities_descriptor.name == "name")
    self.assert_(new_entities_descriptor.valid_until == "2008-09-14T01:05:02Z")
    self.assert_(new_entities_descriptor.cache_duration == "10:00:00:00")
    self.assert_(isinstance(new_entities_descriptor.signature, ds.Signature))
    self.assert_(isinstance(new_entities_descriptor.extensions, md.Extensions))
    self.assert_(isinstance(new_entities_descriptor.entity_descriptor[0],
                            md.EntityDescriptor))
    self.assert_(isinstance(new_entities_descriptor.entities_descriptor[0],
                            md.EntitiesDescriptor))


if __name__ == '__main__':
  unittest.main()

