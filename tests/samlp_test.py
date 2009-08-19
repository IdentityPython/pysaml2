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

"""Tests for saml2.samlp"""

__author__ = 'tmatsuo@sios.com (Takashi MATSUO)'

import unittest
try:
  from xml.etree import ElementTree
except ImportError:
  from elementtree import ElementTree
import saml2
from saml2 import saml, samlp, test_data, ds_test_data, samlp_test_data
import xmldsig as ds


class AbstractRequestTest(unittest.TestCase):

  def setUp(self):
    self.ar = samlp.AbstractRequest()

  def testAccessors(self):
    """Test for AbstractRequest accessors"""
    self.ar.id = "request id"
    self.ar.version = saml.V2
    self.ar.issue_instant = "2007-09-14T01:05:02Z"
    self.ar.destination = "http://www.sios.com/Destination"
    self.ar.consent = saml.CONSENT_UNSPECIFIED
    self.ar.issuer = saml.Issuer()
    self.ar.signature = ds.GetEmptySignature()
    self.ar.extensions = samlp.Extensions()

    new_ar = samlp.AbstractRequestFromString(self.ar.ToString())
    self.assert_(new_ar.id == "request id")
    self.assert_(new_ar.version == saml.V2)
    self.assert_(new_ar.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_ar.destination == "http://www.sios.com/Destination")
    self.assert_(new_ar.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_ar.issuer, saml.Issuer))
    self.assert_(isinstance(new_ar.signature, ds.Signature))
    self.assert_(isinstance(new_ar.extensions, samlp.Extensions))
    
  def testUsingTestData(self):
    """Test for AbstractRequestFromString() using test data"""
    # TODO:
    pass

class StatusDetailTest(unittest.TestCase):

  def setUp(self):
    self.status_detail = samlp.StatusDetail()

  def testAccessors(self):
    """Test for StatusDetail accessors"""
    # TODO:
    pass
  

class StatusMessageTest(unittest.TestCase):

  def setUp(self):
    self.status_message = samlp.StatusMessage()

  def testAccessors(self):
    """Test for StatusMessage accessors"""
    # TODO:
    pass
  

class StatusCodeTest(unittest.TestCase):

  def setUp(self):
    self.status_code = samlp.StatusCode()

  def testAccessors(self):
    """Test for StatusCode accessors"""
    self.status_code.value = samlp.STATUS_RESPONDER
    self.status_code.status_code = samlp.StatusCode(
      value=samlp.STATUS_REQUEST_DENIED)
    new_status_code = samlp.StatusCodeFromString(self.status_code.ToString())
    self.assert_(new_status_code.value == samlp.STATUS_RESPONDER)
    self.assert_(new_status_code.status_code.value ==
                 samlp.STATUS_REQUEST_DENIED)

  def testUsingTestData(self):
    """Test for StatusCodeFromString() using test data"""
    new_status_code = samlp.StatusCodeFromString(
      samlp_test_data.TEST_STATUS_CODE)
    self.assert_(new_status_code.value == samlp.STATUS_RESPONDER)
    self.assert_(new_status_code.status_code.value ==
                 samlp.STATUS_REQUEST_DENIED)


class StatusTest(unittest.TestCase):

  def setUp(self):
    self.status = samlp.Status()

  def testAccessors(self):
    """Test for Status accessors"""
    self.status.status_code = samlp.StatusCode()
    self.status.status_message = samlp.StatusMessage()
    self.status.status_detail = samlp.StatusDetail()
    new_status = samlp.StatusFromString(self.status.ToString())
    self.assert_(isinstance(new_status.status_code, samlp.StatusCode))
    self.assert_(isinstance(new_status.status_message, samlp.StatusMessage))
    self.assert_(isinstance(new_status.status_detail, samlp.StatusDetail))

  def testUsingTestData(self):
    """Test for StatusFromString using test data"""
    new_status = samlp.StatusFromString(samlp_test_data.TEST_STATUS)
    self.assert_(isinstance(new_status.status_code, samlp.StatusCode))
    self.assert_(isinstance(new_status.status_code.status_code,
                            samlp.StatusCode))
    self.assert_(isinstance(new_status.status_message, samlp.StatusMessage))
    self.assert_(isinstance(new_status.status_detail, samlp.StatusDetail))

class StatusResponseTest(unittest.TestCase):

  def setUp(self):
    self.sr = samlp.StatusResponse()

  def testAccessors(self):
    """Test for StatusResponse accessors"""
    self.sr.id = "response id"
    self.sr.in_response_to = "request id"
    self.sr.version = saml.V2
    self.sr.issue_instant = "2007-09-14T01:05:02Z"
    self.sr.destination = "http://www.sios.com/Destination"
    self.sr.consent = saml.CONSENT_UNSPECIFIED
    self.sr.issuer = saml.Issuer()
    self.sr.signature = ds.GetEmptySignature()
    self.sr.extensions = samlp.Extensions()
    self.sr.status = samlp.Status()

    new_sr = samlp.StatusResponseFromString(self.sr.ToString())
    self.assert_(new_sr.id == "response id")
    self.assert_(new_sr.in_response_to == "request id")
    self.assert_(new_sr.version == saml.V2)
    self.assert_(new_sr.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_sr.destination == "http://www.sios.com/Destination")
    self.assert_(new_sr.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_sr.issuer, saml.Issuer))
    self.assert_(isinstance(new_sr.signature, ds.Signature))
    self.assert_(isinstance(new_sr.extensions, samlp.Extensions))
    self.assert_(isinstance(new_sr.status, samlp.Status))
    
  def testUsingTestData(self):
    """Test for StatusResponseFromString() using test data"""
    # TODO:
    pass


class ResponseTest(unittest.TestCase):

  def setUp(self):
    self.response = samlp.Response()

  def testAccessors(self):
    """Test for Response accessors"""
    self.response.id = "response id"
    self.response.in_response_to = "request id"
    self.response.version = saml.V2
    self.response.issue_instant = "2007-09-14T01:05:02Z"
    self.response.destination = "http://www.sios.com/Destination"
    self.response.consent = saml.CONSENT_UNSPECIFIED
    self.response.issuer = saml.Issuer()
    self.response.signature = ds.GetEmptySignature()
    self.response.extensions = samlp.Extensions()
    self.response.status = samlp.Status()
    self.response.assertion.append(saml.Assertion())
    self.response.encrypted_assertion.append(saml.EncryptedAssertion())

    new_response = samlp.ResponseFromString(self.response.ToString())
    self.assert_(new_response.id == "response id")
    self.assert_(new_response.in_response_to == "request id")
    self.assert_(new_response.version == saml.V2)
    self.assert_(new_response.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_response.destination == "http://www.sios.com/Destination")
    self.assert_(new_response.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_response.issuer, saml.Issuer))
    self.assert_(isinstance(new_response.signature, ds.Signature))
    self.assert_(isinstance(new_response.extensions, samlp.Extensions))
    self.assert_(isinstance(new_response.status, samlp.Status))

    self.assert_(isinstance(new_response.assertion[0], saml.Assertion))
    self.assert_(isinstance(new_response.encrypted_assertion[0],
                            saml.EncryptedAssertion))

  def testUsingTestData(self):
    """Test for ResponseFromString() using test data"""
    # TODO:
    pass

class NameIDPolicyTest(unittest.TestCase):

  def setUp(self):
    self.name_id_policy = samlp.NameIDPolicy()

  def testAccessors(self):
    """Test for NameIDPolicy accessors"""
    self.name_id_policy.format = saml.NAMEID_FORMAT_EMAILADDRESS
    self.name_id_policy.sp_name_qualifier = saml.NAMEID_FORMAT_PERSISTENT
    self.name_id_policy.allow_create = 'false'

    new_name_id_policy = samlp.NameIDPolicyFromString(
      self.name_id_policy.ToString())

    self.assert_(new_name_id_policy.format == saml.NAMEID_FORMAT_EMAILADDRESS)
    self.assert_(new_name_id_policy.sp_name_qualifier ==
                 saml.NAMEID_FORMAT_PERSISTENT)
    self.assert_(new_name_id_policy.allow_create == 'false')

  def testUsingTestData(self):
    """Test for NameIDPolicyFromString() using test data"""
    new_name_id_policy = samlp.NameIDPolicyFromString(
      samlp_test_data.TEST_NAME_ID_POLICY)

    self.assert_(new_name_id_policy.format == saml.NAMEID_FORMAT_EMAILADDRESS)
    self.assert_(new_name_id_policy.sp_name_qualifier ==
                 saml.NAMEID_FORMAT_PERSISTENT)
    self.assert_(new_name_id_policy.allow_create == 'false')


class IDPEntryTest(unittest.TestCase):

  def setUp(self):
    self.idp_entry = samlp.IDPEntry()

  def testAccessors(self):
    """Test for IDPEntry accessors"""
    self.idp_entry.provider_id = "http://www.sios.com/provider"
    self.idp_entry.name = "the provider"
    self.idp_entry.loc = "http://www.sios.com/Loc"

    new_idp_entry = samlp.IDPEntryFromString(self.idp_entry.ToString())
    self.assert_(new_idp_entry.provider_id == "http://www.sios.com/provider")
    self.assert_(new_idp_entry.name == "the provider")
    self.assert_(new_idp_entry.loc == "http://www.sios.com/Loc")

  def testUsingTestData(self):
    """Test for IDPEntryFromString() using test data"""
    new_idp_entry = samlp.IDPEntryFromString(samlp_test_data.TEST_IDP_ENTRY)
    self.assert_(new_idp_entry.provider_id == "http://www.sios.com/provider")
    self.assert_(new_idp_entry.name == "the provider")
    self.assert_(new_idp_entry.loc == "http://www.sios.com/Loc")


class IDPListTest(unittest.TestCase):

  def setUp(self):
    self.idp_list = samlp.IDPList()

  def testAccessors(self):
    """Test for IDPList accessors"""
    self.idp_list.idp_entry.append(samlp.IDPEntryFromString(
      samlp_test_data.TEST_IDP_ENTRY))
    self.idp_list.get_complete = samlp.GetComplete(
      text="http://www.sios.com/GetComplete")
    new_idp_list = samlp.IDPListFromString(self.idp_list.ToString())
    self.assert_(isinstance(new_idp_list.idp_entry[0], samlp.IDPEntry))
    self.assert_(new_idp_list.get_complete.text.strip() ==
                 "http://www.sios.com/GetComplete")

  def testUsingTestData(self):
    """Test for IDPListFromString() using test data"""
    new_idp_list = samlp.IDPListFromString(samlp_test_data.TEST_IDP_LIST)
    self.assert_(isinstance(new_idp_list.idp_entry[0], samlp.IDPEntry))
    self.assert_(new_idp_list.get_complete.text.strip() ==
                 "http://www.sios.com/GetComplete")


class ScopingTest(unittest.TestCase):

  def setUp(self):
    self.scoping = samlp.Scoping()

  def testAccessors(self):
    """Test for Scoping accessors"""

    self.scoping.proxy_count = "1"
    self.scoping.idp_list = samlp.IDPList()
    self.scoping.requester_id.append(samlp.RequesterID())

    new_scoping = samlp.ScopingFromString(self.scoping.ToString())

    self.assert_(new_scoping.proxy_count == "1")
    self.assert_(isinstance(new_scoping.idp_list, samlp.IDPList))
    self.assert_(isinstance(new_scoping.requester_id[0], samlp.RequesterID))

  def testUsingTestData(self):
    """Test for ScopingFromString() using test data"""
    new_scoping = samlp.ScopingFromString(samlp_test_data.TEST_SCOPING)

    self.assert_(new_scoping.proxy_count == "1")
    self.assert_(isinstance(new_scoping.idp_list, samlp.IDPList))
    self.assert_(isinstance(new_scoping.requester_id[0], samlp.RequesterID))


class RequestedAuthnContextTest(unittest.TestCase):

  def setUp(self):
    self.context = samlp.RequestedAuthnContext()

  def testAccessors(self):
    """Test for RequestedAuthnContext accessors"""

    self.context.authn_context_class_ref.append(saml.AuthnContextClassRef())
    self.context.authn_context_decl_ref.append(saml.AuthnContextDeclRef())
    self.context.comparison = "exact"

    new_context = samlp.RequestedAuthnContextFromString(
      self.context.ToString())

    self.assert_(isinstance(new_context.authn_context_class_ref[0],
                            saml.AuthnContextClassRef))
    self.assert_(isinstance(new_context.authn_context_decl_ref[0],
                            saml.AuthnContextDeclRef))
    self.assert_(new_context.comparison == "exact")

  def testUsingTestData(self):
    """Test for RequestedAuthnContextFromString() using test data"""
    new_context = samlp.RequestedAuthnContextFromString(
      samlp_test_data.TEST_REQUESTED_AUTHN_CONTEXT)

    self.assert_(isinstance(new_context.authn_context_class_ref[0],
                            saml.AuthnContextClassRef))
    self.assert_(isinstance(new_context.authn_context_decl_ref[0],
                            saml.AuthnContextDeclRef))
    self.assert_(new_context.comparison == "exact")


class AuthnRequestTest(unittest.TestCase):

  def setUp(self):
    self.ar = samlp.AuthnRequest()

  def testAccessors(self):
    """Test for AuthnRequest accessors"""
    self.ar.id = "request id"
    self.ar.version = saml.V2
    self.ar.issue_instant = "2007-09-14T01:05:02Z"
    self.ar.destination = "http://www.sios.com/Destination"
    self.ar.consent = saml.CONSENT_UNSPECIFIED
    self.ar.issuer = saml.Issuer()
    self.ar.signature = ds.GetEmptySignature()
    self.ar.extensions = samlp.Extensions()

    self.ar.subject = saml.Subject()
    self.ar.name_id_policy = samlp.NameIDPolicy()
    self.ar.conditions = saml.Conditions()
    self.ar.requested_authn_context = samlp.RequestedAuthnContext()
    self.ar.scoping = samlp.Scoping()
    self.ar.force_authn = 'true'
    self.ar.is_passive = 'true'
    self.ar.assertion_consumer_service_index = "1"
    self.ar.assertion_consumer_service_url = "http://www.sios.com/acs"
    self.ar.protocol_binding = saml2.BINDING_HTTP_POST
    self.ar.assertion_consuming_service_index = "2"
    self.ar.provider_name = "provider name"

    new_ar = samlp.AuthnRequestFromString(self.ar.ToString())
    self.assert_(new_ar.id == "request id")
    self.assert_(new_ar.version == saml.V2)
    self.assert_(new_ar.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_ar.destination == "http://www.sios.com/Destination")
    self.assert_(new_ar.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_ar.issuer, saml.Issuer))
    self.assert_(isinstance(new_ar.signature, ds.Signature))
    self.assert_(isinstance(new_ar.extensions, samlp.Extensions))

    self.assert_(isinstance(new_ar.subject, saml.Subject))
    self.assert_(isinstance(new_ar.name_id_policy, samlp.NameIDPolicy))
    self.assert_(isinstance(new_ar.conditions, saml.Conditions))
    self.assert_(isinstance(new_ar.requested_authn_context,
                            samlp.RequestedAuthnContext))
    self.assert_(isinstance(new_ar.scoping, samlp.Scoping))
    self.assert_(new_ar.force_authn == 'true')
    self.assert_(new_ar.is_passive == 'true')
    self.assert_(new_ar.assertion_consumer_service_index == '1')
    self.assert_(new_ar.assertion_consumer_service_url ==
                 'http://www.sios.com/acs')
    self.assert_(new_ar.protocol_binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_ar.assertion_consuming_service_index == '2')
    self.assert_(new_ar.provider_name == "provider name")

  def testUsingTestData(self):
    """Test for AuthnRequestFromString() using test data"""
    new_ar = samlp.AuthnRequestFromString(samlp_test_data.TEST_AUTHN_REQUEST)
    self.assert_(new_ar.id == "request id")
    self.assert_(new_ar.version == saml.V2)
    self.assert_(new_ar.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_ar.destination == "http://www.sios.com/Destination")
    self.assert_(new_ar.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_ar.issuer, saml.Issuer))
    self.assert_(isinstance(new_ar.signature, ds.Signature))
    self.assert_(isinstance(new_ar.extensions, samlp.Extensions))

    self.assert_(isinstance(new_ar.subject, saml.Subject))
    self.assert_(isinstance(new_ar.name_id_policy, samlp.NameIDPolicy))
    self.assert_(isinstance(new_ar.conditions, saml.Conditions))
    self.assert_(isinstance(new_ar.requested_authn_context,
                            samlp.RequestedAuthnContext))
    self.assert_(isinstance(new_ar.scoping, samlp.Scoping))
    self.assert_(new_ar.force_authn == 'true')
    self.assert_(new_ar.is_passive == 'true')
    self.assert_(new_ar.assertion_consumer_service_index == '1')
    self.assert_(new_ar.assertion_consumer_service_url ==
                 'http://www.sios.com/acs')
    self.assert_(new_ar.protocol_binding == saml2.BINDING_HTTP_POST)
    self.assert_(new_ar.assertion_consuming_service_index == '2')
    self.assert_(new_ar.provider_name == "provider name")


class LogoutRequestTest(unittest.TestCase):

  def setUp(self):
    self.lr = samlp.LogoutRequest()

  def testAccessors(self):
    """Test for LogoutRequest accessors"""
    self.lr.id = "request id"
    self.lr.version = saml.V2
    self.lr.issue_instant = "2007-09-14T01:05:02Z"
    self.lr.destination = "http://www.sios.com/Destination"
    self.lr.consent = saml.CONSENT_UNSPECIFIED
    self.lr.issuer = saml.Issuer()
    self.lr.signature = ds.GetEmptySignature()
    self.lr.extensions = samlp.Extensions()

    self.lr.not_on_or_after = "2007-10-14T01:05:02Z"
    self.lr.reason = "http://www.sios.com/Reason"
    self.lr.base_id = saml.BaseID()
    self.lr.name_id = saml.NameID()
    self.lr.encrypted_id = saml.EncryptedID()
    self.lr.session_index = samlp.SessionIndex()

    new_lr = samlp.LogoutRequestFromString(self.lr.ToString())
    self.assert_(new_lr.id == "request id")
    self.assert_(new_lr.version == saml.V2)
    self.assert_(new_lr.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_lr.destination == "http://www.sios.com/Destination")
    self.assert_(new_lr.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_lr.issuer, saml.Issuer))
    self.assert_(isinstance(new_lr.signature, ds.Signature))
    self.assert_(isinstance(new_lr.extensions, samlp.Extensions))
    self.assert_(new_lr.not_on_or_after == "2007-10-14T01:05:02Z")
    self.assert_(new_lr.reason == "http://www.sios.com/Reason")
    self.assert_(isinstance(new_lr.base_id, saml.BaseID))
    self.assert_(isinstance(new_lr.name_id, saml.NameID))
    self.assert_(isinstance(new_lr.encrypted_id, saml.EncryptedID))
    self.assert_(isinstance(new_lr.session_index, samlp.SessionIndex))

  def testUsingTestData(self):
    """Test for LogoutRequestFromString() using test data"""
    new_lr = samlp.LogoutRequestFromString(samlp_test_data.TEST_LOGOUT_REQUEST)
    self.assert_(new_lr.id == "request id")
    self.assert_(new_lr.version == saml.V2)
    self.assert_(new_lr.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_lr.destination == "http://www.sios.com/Destination")
    self.assert_(new_lr.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_lr.issuer, saml.Issuer))
    self.assert_(isinstance(new_lr.signature, ds.Signature))
    self.assert_(isinstance(new_lr.extensions, samlp.Extensions))
    self.assert_(new_lr.not_on_or_after == "2007-10-14T01:05:02Z")
    self.assert_(new_lr.reason == "http://www.sios.com/Reason")
    self.assert_(isinstance(new_lr.base_id, saml.BaseID))
    self.assert_(isinstance(new_lr.name_id, saml.NameID))
    self.assert_(isinstance(new_lr.encrypted_id, saml.EncryptedID))
    self.assert_(isinstance(new_lr.session_index, samlp.SessionIndex))
    self.assert_(new_lr.session_index.text.strip() == "session index")


class LogoutResponseTest(unittest.TestCase):
  
  def setUp(self):
    self.lr = samlp.LogoutResponse()

  def testAccessors(self):
    """Test for LogoutResponse accessors"""
    self.lr.id = "response id"
    self.lr.in_response_to = "request id"
    self.lr.version = saml.V2
    self.lr.issue_instant = "2007-09-14T01:05:02Z"
    self.lr.destination = "http://www.sios.com/Destination"
    self.lr.consent = saml.CONSENT_UNSPECIFIED
    self.lr.issuer = saml.Issuer()
    self.lr.signature = ds.GetEmptySignature()
    self.lr.extensions = samlp.Extensions()
    self.lr.status = samlp.Status()

    new_lr = samlp.LogoutResponseFromString(self.lr.ToString())
    self.assert_(new_lr.id == "response id")
    self.assert_(new_lr.in_response_to == "request id")
    self.assert_(new_lr.version == saml.V2)
    self.assert_(new_lr.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_lr.destination == "http://www.sios.com/Destination")
    self.assert_(new_lr.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_lr.issuer, saml.Issuer))
    self.assert_(isinstance(new_lr.signature, ds.Signature))
    self.assert_(isinstance(new_lr.extensions, samlp.Extensions))
    self.assert_(isinstance(new_lr.status, samlp.Status))
    
  def testUsingTestData(self):
    """Test for LogoutResponseFromString() using test data"""
    new_lr = samlp.LogoutResponseFromString(
      samlp_test_data.TEST_LOGOUT_RESPONSE)
    self.assert_(new_lr.id == "response id")
    self.assert_(new_lr.in_response_to == "request id")
    self.assert_(new_lr.version == saml.V2)
    self.assert_(new_lr.issue_instant == "2007-09-14T01:05:02Z")
    self.assert_(new_lr.destination == "http://www.sios.com/Destination")
    self.assert_(new_lr.consent == saml.CONSENT_UNSPECIFIED)
    self.assert_(isinstance(new_lr.issuer, saml.Issuer))
    self.assert_(isinstance(new_lr.signature, ds.Signature))
    self.assert_(isinstance(new_lr.extensions, samlp.Extensions))
    self.assert_(isinstance(new_lr.status, samlp.Status))


if __name__ == '__main__':
  unittest.main()
