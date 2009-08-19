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

"""Tests for saml2.saml"""

__author__ = 'tmatsuo@sios.com (Takashi MATSUO)'

import unittest
try:
  from xml.etree import ElementTree
except ImportError:
  from elementtree import ElementTree
from saml2 import ds_test_data
import xmldsig as ds

class ObjectTest(unittest.TestCase):

  def setUp(self):
    self.object = ds.Object()

  def testAccessors(self):
    """Test for Object accessors"""
    self.object.id = "object_id"
    self.object.mime_type = "test/plain; charset=UTF-8"
    self.object.encoding = ds.ENCODING_BASE64
    new_object = ds.ObjectFromString(self.object.ToString())
    self.assert_(new_object.id == "object_id")
    self.assert_(new_object.mime_type == "test/plain; charset=UTF-8")
    self.assert_(new_object.encoding == ds.ENCODING_BASE64)

  def testUsingTestData(self):
    """Test for ObjectFromString() using test data"""
    new_object = ds.ObjectFromString(ds_test_data.TEST_OBJECT)
    self.assert_(new_object.id == "object_id")
    self.assert_(new_object.encoding == ds.ENCODING_BASE64)
    self.assert_(new_object.text.strip() ==
                 "V2VkIEp1biAgNCAxMjoxMTowMyBFRFQgMjAwMwo")
    

class MgmtDataTest(unittest.TestCase):

  def setUp(self):
    self.mgmt_data = ds.MgmtData()

  def testAccessors(self):
    """Test for MgmtData accessors"""
    self.mgmt_data.text = "mgmt data"
    new_mgmt_data = ds.MgmtDataFromString(self.mgmt_data.ToString())
    self.assert_(new_mgmt_data.text.strip() == "mgmt data")

  def testUsingTestData(self):
    """Test for MgmtDataFromString() using test data"""
    new_mgmt_data = ds.MgmtDataFromString(ds_test_data.TEST_MGMT_DATA)
    self.assert_(new_mgmt_data.text.strip() == "mgmt data")


class SPKISexpTest(unittest.TestCase):

  def setUp(self):
    self.spki_sexp = ds.SPKISexp()

  def testAccessors(self):
    """Test for SPKISexp accessors"""
    self.spki_sexp.text = "spki sexp"
    new_spki_sexp = ds.SPKISexpFromString(self.spki_sexp.ToString())
    self.assert_(new_spki_sexp.text.strip() == "spki sexp")

  def testUsingTestData(self):
    """Test for SPKISexpFromString() using test data"""
    new_spki_sexp = ds.SPKISexpFromString(ds_test_data.TEST_SPKI_SEXP)
    self.assert_(new_spki_sexp.text.strip() == "spki sexp")


class SPKIDataTest(unittest.TestCase):

  def setUp(self):
    self.spki_data = ds.SPKIData()

  def testAccessors(self):
    """Test for SPKIData accessors"""
    self.spki_data.spki_sexp.append(
      ds.SPKISexpFromString(ds_test_data.TEST_SPKI_SEXP))
    new_spki_data = ds.SPKIDataFromString(self.spki_data.ToString())
    self.assert_(new_spki_data.spki_sexp[0].text.strip() == "spki sexp")

  def testUsingTestData(self):
    """Test for SPKIDataFromString() using test data"""
    new_spki_data = ds.SPKIDataFromString(ds_test_data.TEST_SPKI_DATA)
    self.assert_(new_spki_data.spki_sexp[0].text.strip() == "spki sexp")
    self.assert_(new_spki_data.spki_sexp[1].text.strip() == "spki sexp2")


class PGPDataTest(unittest.TestCase):

  def setUp(self):
    self.pgp_data = ds.PGPData()

  def testAccessors(self):
    """Test for PGPData accessors"""
    self.pgp_data.pgp_key_id = ds.PGPKeyID(text="pgp key id")
    self.pgp_data.pgp_key_packet = ds.PGPKeyPacket(text="pgp key packet")
    new_pgp_data = ds.PGPDataFromString(self.pgp_data.ToString())
    self.assert_(isinstance(new_pgp_data.pgp_key_id, ds.PGPKeyID))
    self.assert_(isinstance(new_pgp_data.pgp_key_packet, ds.PGPKeyPacket))
    self.assert_(new_pgp_data.pgp_key_id.text.strip() == "pgp key id")
    self.assert_(new_pgp_data.pgp_key_packet.text.strip() == "pgp key packet")

  def testUsingTestData(self):
    """Test for PGPDataFromString() using test data"""
    new_pgp_data = ds.PGPDataFromString(ds_test_data.TEST_PGP_DATA)
    self.assert_(isinstance(new_pgp_data.pgp_key_id, ds.PGPKeyID))
    self.assert_(isinstance(new_pgp_data.pgp_key_packet, ds.PGPKeyPacket))
    self.assert_(new_pgp_data.pgp_key_id.text.strip() == "pgp key id")
    self.assert_(new_pgp_data.pgp_key_packet.text.strip() == "pgp key packet")


class X509IssuerSerialTest(unittest.TestCase):

  def setUp(self):
    self.x509_issuer_serial = ds.X509IssuerSerial()

  def testAccessors(self):
    """Test for X509IssuerSerial accessors"""
    self.x509_issuer_serial.x509_issuer_name = ds.X509IssuerName(
      text="issuer name")
    self.x509_issuer_serial.x509_issuer_number = ds.X509IssuerNumber(text="1")
    new_x509_issuer_serial = ds.X509IssuerSerialFromString(
      self.x509_issuer_serial.ToString())
    self.assert_(new_x509_issuer_serial.x509_issuer_name.text.strip() ==
                 "issuer name")
    self.assert_(new_x509_issuer_serial.x509_issuer_number.text.strip() == "1")

  def testUsingTestData(self):
    """Test for X509IssuerSerialFromString() using test data"""
    new_x509_issuer_serial = ds.X509IssuerSerialFromString(
      ds_test_data.TEST_X509_ISSUER_SERIAL)
    self.assert_(new_x509_issuer_serial.x509_issuer_name.text.strip() ==
                 "issuer name")
    self.assert_(new_x509_issuer_serial.x509_issuer_number.text.strip() == "1")


class X509DataTest(unittest.TestCase):

  def setUp(self):
    self.x509_data = ds.X509Data()

  def testAccessors(self):
    """Test for X509Data accessors"""
    self.x509_data.x509_issuer_serial.append(ds.X509IssuerSerialFromString(
      ds_test_data.TEST_X509_ISSUER_SERIAL))
    self.x509_data.x509_ski.append(ds.X509SKI(text="x509 ski"))
    self.x509_data.x509_subject_name.append(ds.X509SubjectName(
      text="x509 subject name"))
    self.x509_data.x509_certificate.append(ds.X509Certificate(
      text="x509 certificate"))
    self.x509_data.x509_crl.append(ds.X509CRL(text="x509 crl"))
    new_x509_data = ds.X509DataFromString(self.x509_data.ToString())
    self.assert_(isinstance(new_x509_data.x509_issuer_serial[0],
                            ds.X509IssuerSerial))
    self.assert_(new_x509_data.x509_ski[0].text.strip() == "x509 ski")
    self.assert_(isinstance(new_x509_data.x509_ski[0], ds.X509SKI))
    self.assert_(new_x509_data.x509_subject_name[0].text.strip() ==
                 "x509 subject name")
    self.assert_(isinstance(new_x509_data.x509_subject_name[0],
                            ds.X509SubjectName))
    self.assert_(new_x509_data.x509_certificate[0].text.strip() ==
                 "x509 certificate")
    self.assert_(isinstance(new_x509_data.x509_certificate[0],
                            ds.X509Certificate))
    self.assert_(new_x509_data.x509_crl[0].text.strip() == "x509 crl")
    self.assert_(isinstance(new_x509_data.x509_crl[0],ds.X509CRL))

  def testUsingTestData(self):
    """Test for X509DataFromString() using test data"""
    new_x509_data = ds.X509DataFromString(ds_test_data.TEST_X509_DATA)
    self.assert_(isinstance(new_x509_data.x509_issuer_serial[0],
                            ds.X509IssuerSerial))
    self.assert_(new_x509_data.x509_ski[0].text.strip() == "x509 ski")
    self.assert_(isinstance(new_x509_data.x509_ski[0], ds.X509SKI))
    self.assert_(new_x509_data.x509_subject_name[0].text.strip() ==
                 "x509 subject name")
    self.assert_(isinstance(new_x509_data.x509_subject_name[0],
                            ds.X509SubjectName))
    self.assert_(new_x509_data.x509_certificate[0].text.strip() ==
                 "x509 certificate")
    self.assert_(isinstance(new_x509_data.x509_certificate[0],
                            ds.X509Certificate))
    self.assert_(new_x509_data.x509_crl[0].text.strip() == "x509 crl")
    self.assert_(isinstance(new_x509_data.x509_crl[0],ds.X509CRL))


class TransformTest(unittest.TestCase):

  def setUp(self):
    self.transform = ds.Transform()

  def testAccessors(self):
    """Test for Transform accessors"""
    self.transform.xpath.append(ds.XPath(text="xpath"))
    self.transform.algorithm = ds.TRANSFORM_ENVELOPED
    new_transform = ds.TransformFromString(self.transform.ToString())
    self.assert_(isinstance(new_transform.xpath[0], ds.XPath))
    self.assert_(new_transform.xpath[0].text.strip() == "xpath")
    self.assert_(new_transform.algorithm == ds.TRANSFORM_ENVELOPED)

  def testUsingTestData(self):
    """Test for TransformFromString() using test data"""
    new_transform = ds.TransformFromString(ds_test_data.TEST_TRANSFORM)
    self.assert_(isinstance(new_transform.xpath[0], ds.XPath))
    self.assert_(new_transform.xpath[0].text.strip() == "xpath")
    self.assert_(new_transform.algorithm == ds.TRANSFORM_ENVELOPED)


class TransformsTest(unittest.TestCase):

  def setUp(self):
    self.transforms = ds.Transforms()

  def testAccessors(self):
    """Test for Transforms accessors"""
    self.transforms.transform.append(
      ds.TransformFromString(ds_test_data.TEST_TRANSFORM))
    self.transforms.transform.append(
      ds.TransformFromString(ds_test_data.TEST_TRANSFORM))
    new_transforms = ds.TransformsFromString(self.transforms.ToString())
    self.assert_(isinstance(new_transforms.transform[0], ds.Transform))
    self.assert_(isinstance(new_transforms.transform[1], ds.Transform))
    self.assert_(new_transforms.transform[0].algorithm ==
                 ds.TRANSFORM_ENVELOPED)
    self.assert_(new_transforms.transform[1].algorithm ==
                 ds.TRANSFORM_ENVELOPED)
    self.assert_(new_transforms.transform[0].xpath[0].text.strip() == "xpath")
    self.assert_(new_transforms.transform[1].xpath[0].text.strip() == "xpath")
    
  def testUsingTestData(self):
    """Test for TransformFromString() using test data"""
    new_transforms = ds.TransformsFromString(ds_test_data.TEST_TRANSFORMS)
    self.assert_(isinstance(new_transforms.transform[0], ds.Transform))
    self.assert_(isinstance(new_transforms.transform[1], ds.Transform))
    self.assert_(new_transforms.transform[0].algorithm ==
                 ds.TRANSFORM_ENVELOPED)
    self.assert_(new_transforms.transform[1].algorithm ==
                 ds.TRANSFORM_ENVELOPED)
    self.assert_(new_transforms.transform[0].xpath[0].text.strip() == "xpath")
    self.assert_(new_transforms.transform[1].xpath[0].text.strip() == "xpath")


class RetrievalMethodTest(unittest.TestCase):

  def setUp(self):
    self.retrieval_method = ds.RetrievalMethod()

  def testAccessors(self):
    """Test for RetrievalMethod accessors"""
    self.retrieval_method.uri = "http://www.sios.com/URI"
    self.retrieval_method.type = "http://www.sios.com/Type"
    self.retrieval_method.transforms.append(ds.TransformsFromString(
      ds_test_data.TEST_TRANSFORMS))
    new_retrieval_method = ds.RetrievalMethodFromString(
      self.retrieval_method.ToString())
    self.assert_(new_retrieval_method.uri == "http://www.sios.com/URI")
    self.assert_(new_retrieval_method.type == "http://www.sios.com/Type")
    self.assert_(isinstance(new_retrieval_method.transforms[0], ds.Transforms))
    
  def testUsingTestData(self):
    """Test for RetrievalMethodFromString() using test data"""
    new_retrieval_method = ds.RetrievalMethodFromString(
      ds_test_data.TEST_RETRIEVAL_METHOD)
    self.assert_(new_retrieval_method.uri == "http://www.sios.com/URI")
    self.assert_(new_retrieval_method.type == "http://www.sios.com/Type")
    self.assert_(isinstance(new_retrieval_method.transforms[0], ds.Transforms))


class RSAKeyValueTest(unittest.TestCase):

  def setUp(self):
    self.rsa_key_value = ds.RSAKeyValue()

  def testAccessors(self):
    """Test for RSAKeyValue accessors"""
    self.rsa_key_value.modulus = ds.Modulus(text="modulus")
    self.rsa_key_value.exponent = ds.Exponent(text="exponent")
    new_rsa_key_value = ds.RSAKeyValueFromString(self.rsa_key_value.ToString())
    self.assert_(isinstance(new_rsa_key_value.modulus, ds.Modulus))
    self.assert_(isinstance(new_rsa_key_value.exponent, ds.Exponent))
    self.assert_(new_rsa_key_value.modulus.text.strip() == "modulus")
    self.assert_(new_rsa_key_value.exponent.text.strip() == "exponent")
    
  def testUsingTestData(self):
    """Test for RSAKeyValueFromString() using test data"""
    new_rsa_key_value = ds.RSAKeyValueFromString(
      ds_test_data.TEST_RSA_KEY_VALUE)
    self.assert_(isinstance(new_rsa_key_value.modulus, ds.Modulus))
    self.assert_(isinstance(new_rsa_key_value.exponent, ds.Exponent))
    self.assert_(new_rsa_key_value.modulus.text.strip() == "modulus")
    self.assert_(new_rsa_key_value.exponent.text.strip() == "exponent")


class DSAKeyValueTest(unittest.TestCase):

  def setUp(self):
    self.dsa_key_value = ds.DSAKeyValue()

  def testAccessors(self):
    """Test for DSAKeyValue accessors"""
    self.dsa_key_value.p = ds.P(text="p")
    self.dsa_key_value.q = ds.Q(text="q")
    self.dsa_key_value.g = ds.G(text="g")
    self.dsa_key_value.y = ds.Y(text="y")
    self.dsa_key_value.j = ds.J(text="j")
    self.dsa_key_value.seed = ds.Seed(text="seed")
    self.dsa_key_value.pgen_counter = ds.PgenCounter(text="pgen counter")
    new_dsa_key_value = ds.DSAKeyValueFromString(self.dsa_key_value.ToString())
    self.assert_(isinstance(new_dsa_key_value.p, ds.P))
    self.assert_(isinstance(new_dsa_key_value.q, ds.Q))
    self.assert_(isinstance(new_dsa_key_value.g, ds.G))
    self.assert_(isinstance(new_dsa_key_value.y, ds.Y))
    self.assert_(isinstance(new_dsa_key_value.j, ds.J))
    self.assert_(isinstance(new_dsa_key_value.seed, ds.Seed))
    self.assert_(isinstance(new_dsa_key_value.pgen_counter, ds.PgenCounter))
    self.assert_(new_dsa_key_value.p.text.strip() == "p")
    self.assert_(new_dsa_key_value.q.text.strip() == "q")
    self.assert_(new_dsa_key_value.g.text.strip() == "g")
    self.assert_(new_dsa_key_value.y.text.strip() == "y")
    self.assert_(new_dsa_key_value.j.text.strip() == "j")
    self.assert_(new_dsa_key_value.seed.text.strip() == "seed")
    self.assert_(new_dsa_key_value.pgen_counter.text.strip() == "pgen counter")
    
  def testUsingTestData(self):
    """Test for DSAKeyValueFromString() using test data"""
    new_dsa_key_value = ds.DSAKeyValueFromString(
      ds_test_data.TEST_DSA_KEY_VALUE)
    self.assert_(isinstance(new_dsa_key_value.p, ds.P))
    self.assert_(isinstance(new_dsa_key_value.q, ds.Q))
    self.assert_(isinstance(new_dsa_key_value.g, ds.G))
    self.assert_(isinstance(new_dsa_key_value.y, ds.Y))
    self.assert_(isinstance(new_dsa_key_value.j, ds.J))
    self.assert_(isinstance(new_dsa_key_value.seed, ds.Seed))
    self.assert_(isinstance(new_dsa_key_value.pgen_counter, ds.PgenCounter))
    self.assert_(new_dsa_key_value.p.text.strip() == "p")
    self.assert_(new_dsa_key_value.q.text.strip() == "q")
    self.assert_(new_dsa_key_value.g.text.strip() == "g")
    self.assert_(new_dsa_key_value.y.text.strip() == "y")
    self.assert_(new_dsa_key_value.j.text.strip() == "j")
    self.assert_(new_dsa_key_value.seed.text.strip() == "seed")
    self.assert_(new_dsa_key_value.pgen_counter.text.strip() == "pgen counter")


class KeyValueTest(unittest.TestCase):

  def setUp(self):
    self.key_value = ds.KeyValue()

  def testAccessors(self):
    """Test for KeyValue accessors"""
    self.key_value.dsa_key_value = ds.DSAKeyValueFromString(
      ds_test_data.TEST_DSA_KEY_VALUE)
    new_key_value = ds.KeyValueFromString(self.key_value.ToString())
    self.assert_(isinstance(new_key_value.dsa_key_value, ds.DSAKeyValue))
    self.key_value.dsa_key_value = None
    self.key_value.rsa_key_value = ds.RSAKeyValueFromString(
      ds_test_data.TEST_RSA_KEY_VALUE)
    new_key_value = ds.KeyValueFromString(self.key_value.ToString())
    self.assert_(isinstance(new_key_value.rsa_key_value, ds.RSAKeyValue))
    
  def testUsingTestData(self):
    """Test for KeyValueFromString() using test data"""
    new_key_value = ds.KeyValueFromString(ds_test_data.TEST_KEY_VALUE1)
    self.assert_(isinstance(new_key_value.dsa_key_value, ds.DSAKeyValue))
    self.key_value.dsa_key_value = None
    self.key_value.rsa_key_value = ds.RSAKeyValueFromString(
      ds_test_data.TEST_RSA_KEY_VALUE)
    new_key_value = ds.KeyValueFromString(ds_test_data.TEST_KEY_VALUE2)
    self.assert_(isinstance(new_key_value.rsa_key_value, ds.RSAKeyValue))


class KeyNameTest(unittest.TestCase):

  def setUp(self):
    self.key_name = ds.KeyName()

  def testAccessors(self):
    """Test for KeyName accessors"""
    self.key_name.text = "key name"
    new_key_name = ds.KeyNameFromString(self.key_name.ToString())
    self.assert_(new_key_name.text.strip() == "key name")
    
  def testUsingTestData(self):
    """Test for KeyNameFromString() using test data"""
    new_key_name = ds.KeyNameFromString(ds_test_data.TEST_KEY_NAME)
    self.assert_(new_key_name.text.strip() == "key name")


class KeyInfoTest(unittest.TestCase):
  def setUp(self):
    self.key_info = ds.KeyInfo()

  def testAccessors(self):
    """Test for KeyInfo accessors"""
    self.key_info.key_name.append(
      ds.KeyNameFromString(ds_test_data.TEST_KEY_NAME))
    self.key_info.key_value.append(
      ds.KeyValueFromString(ds_test_data.TEST_KEY_VALUE1))
    self.key_info.retrieval_method.append(
      ds.RetrievalMethodFromString(ds_test_data.TEST_RETRIEVAL_METHOD))
    self.key_info.x509_data.append(
      ds.X509DataFromString(ds_test_data.TEST_X509_DATA))
    self.key_info.pgp_data.append(
      ds.PGPDataFromString(ds_test_data.TEST_PGP_DATA))
    self.key_info.spki_data.append(
      ds.SPKIDataFromString(ds_test_data.TEST_SPKI_DATA))
    self.key_info.mgmt_data.append(
      ds.MgmtDataFromString(ds_test_data.TEST_MGMT_DATA))
    self.key_info.id = "id"
    new_key_info = ds.KeyInfoFromString(self.key_info.ToString())

    self.assert_(isinstance(new_key_info.key_name[0], ds.KeyName))
    self.assert_(isinstance(new_key_info.key_value[0], ds.KeyValue))
    self.assert_(isinstance(new_key_info.retrieval_method[0],
                            ds.RetrievalMethod))
    self.assert_(isinstance(new_key_info.x509_data[0], ds.X509Data))
    self.assert_(isinstance(new_key_info.pgp_data[0], ds.PGPData))
    self.assert_(isinstance(new_key_info.spki_data[0], ds.SPKIData))
    self.assert_(isinstance(new_key_info.mgmt_data[0], ds.MgmtData))
    self.assert_(new_key_info.id == "id")
    
  def testUsingTestData(self):
    """Test for KeyInfoFromString() using test data"""
    new_key_info = ds.KeyInfoFromString(ds_test_data.TEST_KEY_INFO)
    self.assert_(isinstance(new_key_info.key_name[0], ds.KeyName))
    self.assert_(isinstance(new_key_info.key_value[0], ds.KeyValue))
    self.assert_(isinstance(new_key_info.retrieval_method[0],
                            ds.RetrievalMethod))
    self.assert_(isinstance(new_key_info.x509_data[0], ds.X509Data))
    self.assert_(isinstance(new_key_info.pgp_data[0], ds.PGPData))
    self.assert_(isinstance(new_key_info.spki_data[0], ds.SPKIData))
    self.assert_(isinstance(new_key_info.mgmt_data[0], ds.MgmtData))
    self.assert_(new_key_info.id == "id")
  

class DigestValueTest(unittest.TestCase):

  def setUp(self):
    self.digest_value = ds.DigestValue()

  def testAccessors(self):
    """Test for DigestValue accessors"""
    self.digest_value.text = "digest value"
    new_digest_value = ds.DigestValueFromString(self.digest_value.ToString())
    self.assert_(new_digest_value.text.strip() == "digest value")
    
  def testUsingTestData(self):
    """Test for DigestValueFromString() using test data"""
    new_digest_value = ds.DigestValueFromString(ds_test_data.TEST_DIGEST_VALUE)
    self.assert_(new_digest_value.text.strip() == "digest value")


class DigestMethodTest(unittest.TestCase):

  def setUp(self):
    self.digest_method = ds.DigestMethod()

  def testAccessors(self):
    """Test for DigestMethod accessors"""
    self.digest_method.algorithm = ds.DIGEST_SHA1
    new_digest_method = ds.DigestMethodFromString(
      self.digest_method.ToString())
    self.assert_(new_digest_method.algorithm == ds.DIGEST_SHA1)
    
  def testUsingTestData(self):
    """Test for DigestMethodFromString() using test data"""
    new_digest_method = ds.DigestMethodFromString(
      ds_test_data.TEST_DIGEST_METHOD)
    self.assert_(new_digest_method.algorithm == ds.DIGEST_SHA1)


class ReferenceTest(unittest.TestCase):

  def setUp(self):
    self.reference = ds.Reference()

  def testAccessors(self):
    """Test for Reference accessors"""
    self.reference.transforms.append(ds.TransformsFromString(
      ds_test_data.TEST_TRANSFORMS))
    self.reference.digest_method.append(ds.DigestMethodFromString(
      ds_test_data.TEST_DIGEST_METHOD))
    self.reference.digest_value.append(ds.DigestValueFromString(
      ds_test_data.TEST_DIGEST_VALUE))
    self.reference.id = "id"
    self.reference.uri = "http://www.sios.com/URI"
    self.reference.type = "http://www.sios.com/Type"
    new_reference = ds.ReferenceFromString(self.reference.ToString())
    self.assert_(isinstance(new_reference.transforms[0], ds.Transforms))
    self.assert_(isinstance(new_reference.digest_method[0], ds.DigestMethod))
    self.assert_(isinstance(new_reference.digest_value[0], ds.DigestValue))
    self.assert_(new_reference.id == "id")
    self.assert_(new_reference.uri == "http://www.sios.com/URI")
    self.assert_(new_reference.type == "http://www.sios.com/Type")
    
  def testUsingTestData(self):
    """Test for ReferenceFromString() using test data"""
    new_reference = ds.ReferenceFromString(ds_test_data.TEST_REFERENCE)
    self.assert_(isinstance(new_reference.transforms[0], ds.Transforms))
    self.assert_(isinstance(new_reference.digest_method[0], ds.DigestMethod))
    self.assert_(isinstance(new_reference.digest_value[0], ds.DigestValue))
    self.assert_(new_reference.id == "id")
    self.assert_(new_reference.uri == "http://www.sios.com/URI")
    self.assert_(new_reference.type == "http://www.sios.com/Type")


class SignatureMethodTest(unittest.TestCase):

  def setUp(self):
    self.signature_method = ds.SignatureMethod()

  def testAccessors(self):
    """Test for SignatureMethod accessors"""
    self.signature_method.algorithm = ds.SIG_RSA_SHA1
    self.signature_method.hmac_output_length = ds.HMACOutputLength(text="8")
    new_signature_method = ds.SignatureMethodFromString(
      self.signature_method.ToString())
    self.assert_(isinstance(new_signature_method.hmac_output_length,
                            ds.HMACOutputLength))
    self.assert_(new_signature_method.hmac_output_length.text.strip() == "8")
    self.assert_(new_signature_method.algorithm == ds.SIG_RSA_SHA1)
    
  def testUsingTestData(self):
    """Test for SignatureMethodFromString() using test data"""
    new_signature_method = ds.SignatureMethodFromString(
      ds_test_data.TEST_SIGNATURE_METHOD)
    self.assert_(isinstance(new_signature_method.hmac_output_length,
                            ds.HMACOutputLength))
    self.assert_(new_signature_method.hmac_output_length.text.strip() == "8")
    self.assert_(new_signature_method.algorithm == ds.SIG_RSA_SHA1)


class CanonicalizationMethodTest(unittest.TestCase):

  def setUp(self):
    self.canonicalization_method = ds.CanonicalizationMethod()

  def testAccessors(self):
    """Test for CanonicalizationMethod accessors"""
    self.canonicalization_method.algorithm = ds.C14N_WITH_C
    new_canonicalization_method = ds.CanonicalizationMethodFromString(
      self.canonicalization_method.ToString())
    self.assert_(new_canonicalization_method.algorithm == ds.C14N_WITH_C)
    
  def testUsingTestData(self):
    """Test for CanonicalizationMethodFromString() using test data"""
    new_canonicalization_method = ds.CanonicalizationMethodFromString(
      ds_test_data.TEST_CANONICALIZATION_METHOD)
    self.assert_(new_canonicalization_method.algorithm == ds.C14N_WITH_C)


class SignedInfoTest(unittest.TestCase):

  def setUp(self):
    self.si = ds.SignedInfo()

  def testAccessors(self):
    """Test for SignedInfo accessors"""
    self.si.id = "id"
    self.si.canonicalization_method = ds.CanonicalizationMethodFromString(
      ds_test_data.TEST_CANONICALIZATION_METHOD)
    self.si.signature_method = ds.SignatureMethodFromString(
      ds_test_data.TEST_SIGNATURE_METHOD)
    self.si.reference.append(ds.ReferenceFromString(
      ds_test_data.TEST_REFERENCE))
    new_si = ds.SignedInfoFromString(self.si.ToString())
    self.assert_(new_si.id == "id")
    self.assert_(isinstance(new_si.canonicalization_method,
                            ds.CanonicalizationMethod))
    self.assert_(isinstance(new_si.signature_method, ds.SignatureMethod))
    self.assert_(isinstance(new_si.reference[0], ds.Reference))
    
  def testUsingTestData(self):
    """Test for SignedInfoFromString() using test data"""
    new_si = ds.SignedInfoFromString(ds_test_data.TEST_SIGNED_INFO)
    self.assert_(new_si.id == "id")
    self.assert_(isinstance(new_si.canonicalization_method,
                            ds.CanonicalizationMethod))
    self.assert_(isinstance(new_si.signature_method, ds.SignatureMethod))
    self.assert_(isinstance(new_si.reference[0], ds.Reference))

class SignatureValueTest(unittest.TestCase):

  def setUp(self):
    self.signature_value = ds.SignatureValue()

  def testAccessors(self):
    """Test for SignatureValue accessors"""
    self.signature_value.id = "id"
    self.signature_value.text = "signature value"
    new_signature_value = ds.SignatureValueFromString(
      self.signature_value.ToString())
    self.assert_(new_signature_value.id == "id")
    self.assert_(new_signature_value.text.strip() == "signature value")
    
  def testUsingTestData(self):
    """Test for SignatureValueFromString() using test data"""
    new_signature_value = ds.SignatureValueFromString(
      ds_test_data.TEST_SIGNATURE_VALUE)
    self.assert_(new_signature_value.id == "id")
    self.assert_(new_signature_value.text.strip() == "signature value")


class SignatureTest(unittest.TestCase):

  def setUp(self):
    self.signature = ds.Signature()

  def testAccessors(self):
    """Test for Signature accessors"""
    self.signature.id = "id"
    self.signature.signed_info = ds.SignedInfoFromString(
      ds_test_data.TEST_SIGNED_INFO)
    self.signature.signature_value = ds.SignatureValueFromString(
      ds_test_data.TEST_SIGNATURE_VALUE)
    self.signature.key_info = ds.KeyInfoFromString(ds_test_data.TEST_KEY_INFO)
    self.signature.object.append(ds.ObjectFromString(ds_test_data.TEST_OBJECT))

    new_signature = ds.SignatureFromString(self.signature.ToString())
    self.assert_(new_signature.id == "id")
    self.assert_(isinstance(new_signature.signed_info, ds.SignedInfo))
    self.assert_(isinstance(new_signature.signature_value, ds.SignatureValue))
    self.assert_(isinstance(new_signature.key_info, ds.KeyInfo))
    self.assert_(isinstance(new_signature.object[0], ds.Object))
    
  def testUsingTestData(self):
    """Test for SignatureValueFromString() using test data"""
    new_signature = ds.SignatureFromString(ds_test_data.TEST_SIGNATURE)
    self.assert_(new_signature.id == "id")
    self.assert_(isinstance(new_signature.signed_info, ds.SignedInfo))
    self.assert_(isinstance(new_signature.signature_value, ds.SignatureValue))
    self.assert_(isinstance(new_signature.key_info, ds.KeyInfo))
    self.assert_(isinstance(new_signature.object[0], ds.Object))


if __name__ == '__main__':
  unittest.main()
