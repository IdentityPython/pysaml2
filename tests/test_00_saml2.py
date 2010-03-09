#!/usr/bin/env python

from saml2 import create_class_from_xml_string, class_name
from saml2.saml import NameID, Issuer, SubjectLocality, AuthnContextClassRef
from saml2.saml import SubjectConfirmationData, SubjectConfirmation
import saml2

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        from elementtree import ElementTree

ITEMS = {
    NameID:["""<?xml version="1.0" encoding="utf-8"?>
<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
  Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  SPProvidedID="sp provided id">
  roland@example.com
</NameID>
""", """<?xml version="1.0" encoding="utf-8"?>
<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
  SPNameQualifier="https://foo.example.com/sp" 
  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_1632879f09d08ea5ede2dc667cbed7e429ebc4335c</NameID>
""", """<?xml version="1.0" encoding="utf-8"?>
<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NameQualifier="http://authentic.example.com/saml/metadata"
SPNameQualifier="http://auth.example.com/saml/metadata">test
</NameID>"""],
    Issuer:"""<?xml version="1.0" encoding="utf-8"?>
<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  http://www.example.com/test
</Issuer>
""",
    SubjectLocality: """<?xml version="1.0" encoding="utf-8"?>
<SubjectLocality xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
  Address="127.0.0.1" DNSName="localhost"/>
""",
    SubjectConfirmationData:
"""<?xml version="1.0" encoding="utf-8"?>
<SubjectConfirmationData xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
InResponseTo="_1683146e27983964fbe7bf8f08961108d166a652e5" 
NotOnOrAfter="2010-02-18T13:52:13.959Z" 
NotBefore="2010-01-16T12:00:00Z" 
Recipient="http://192.168.0.10/saml/sp" />""",
    SubjectConfirmation:
    """<?xml version="1.0" encoding="utf-8"?>
<SubjectConfirmation xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><NameID
Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NameQualifier="http://authentic.example.com/saml/metadata">test@example.com
</NameID>
<SubjectConfirmationData
NotOnOrAfter="2010-02-17T17:02:38Z"
Recipient="http://auth.example.com/saml/proxySingleSignOnRedirect"
InResponseTo="_59B3A01B03334032C31E434C63F89E3E"/></SubjectConfirmation>"""
}

#def pytest_generate_tests(metafunc):
#    if "target_class" in metafunc.funcargnames:
#        for tcl,xml in ITEMS.items():
#            metafunc.addcall(funcargs={"target_class":tcl,"xml_string":xml})
    
def _eq(l1,l2):
    return set(l1) == set(l2)
    
def test_create_class_from_xml_string_nameid():
    kl = create_class_from_xml_string(NameID, ITEMS[NameID][0])
    assert kl != None
    assert kl.format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert kl.sp_provided_id == "sp provided id"
    assert kl.text.strip() == "roland@example.com"
    assert _eq(kl.keyswv(), ['sp_provided_id', 'format', 'text'])
    assert class_name(kl) == "urn:oasis:names:tc:SAML:2.0:assertion:NameID"
    assert _eq(kl.keys(), ['sp_provided_id', 'sp_name_qualifier', 
                            'name_qualifier', 'format', 'text'])

    kl = create_class_from_xml_string(NameID, ITEMS[NameID][1])
    assert kl != None
    assert kl.format == "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    assert kl.sp_name_qualifier == "https://foo.example.com/sp"
    assert kl.text.strip() == "_1632879f09d08ea5ede2dc667cbed7e429ebc4335c"
    assert _eq(kl.keyswv(), ['sp_name_qualifier', 'format', 'text'])
    assert class_name(kl) == "urn:oasis:names:tc:SAML:2.0:assertion:NameID"

    kl = create_class_from_xml_string(NameID, ITEMS[NameID][2])
    assert kl != None
    assert kl.format == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    assert kl.name_qualifier == "http://authentic.example.com/saml/metadata"
    assert kl.sp_name_qualifier == "http://auth.example.com/saml/metadata"
    assert kl.text.strip() == "test"
    assert _eq(kl.keyswv(), ['sp_name_qualifier', 'format', 'name_qualifier',
                            'text'])
    assert class_name(kl) == "urn:oasis:names:tc:SAML:2.0:assertion:NameID"

def test_create_class_from_xml_string_issuer():
    kl = create_class_from_xml_string(Issuer, ITEMS[Issuer])
    assert kl != None
    assert kl.text.strip() == "http://www.example.com/test"
    assert _eq(kl.keyswv(), ['text'])
    assert class_name(kl) == "urn:oasis:names:tc:SAML:2.0:assertion:Issuer"

def test_create_class_from_xml_string_subject_locality():
    kl = create_class_from_xml_string(SubjectLocality, ITEMS[SubjectLocality])
    assert kl != None
    assert _eq(kl.keyswv(), ['address', "dns_name"])
    assert kl.address == "127.0.0.1"
    assert kl.dns_name == "localhost"
    assert class_name(kl) == "urn:oasis:names:tc:SAML:2.0:assertion:SubjectLocality"

def test_create_class_from_xml_string_subject_confirmation_data():
    kl = create_class_from_xml_string(SubjectConfirmationData, 
                                        ITEMS[SubjectConfirmationData])
    assert kl != None
    assert _eq(kl.keyswv(), ['in_response_to', 'not_on_or_after',
                                'not_before', 'recipient'])
    assert kl.in_response_to == "_1683146e27983964fbe7bf8f08961108d166a652e5"
    assert kl.not_on_or_after == "2010-02-18T13:52:13.959Z"
    assert kl.not_before == "2010-01-16T12:00:00Z"
    assert kl.recipient == "http://192.168.0.10/saml/sp"
    assert class_name(kl) == \
                "urn:oasis:names:tc:SAML:2.0:assertion:SubjectConfirmationData"

def test_create_class_from_xml_string_subject_confirmation():
    kl = create_class_from_xml_string(SubjectConfirmation, 
                                        ITEMS[SubjectConfirmation])
    assert kl != None
    assert _eq(kl.keyswv(), ['method', 'name_id',
                                'subject_confirmation_data'])
    assert kl.method == "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    name_id = kl.name_id
    assert _eq(name_id.keyswv(), ['format', 'name_qualifier', 'text'])
    assert name_id.format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert name_id.name_qualifier == "http://authentic.example.com/saml/metadata"
    assert name_id.text.strip() == "test@example.com"
    subject_confirmation_data = kl.subject_confirmation_data
    assert _eq(subject_confirmation_data.keyswv(), ['not_on_or_after', 
                            'recipient', 'in_response_to'])
    assert subject_confirmation_data.recipient == \
                    "http://auth.example.com/saml/proxySingleSignOnRedirect"
    assert subject_confirmation_data.not_on_or_after == "2010-02-17T17:02:38Z"
    assert subject_confirmation_data.in_response_to == \
                    "_59B3A01B03334032C31E434C63F89E3E"
    assert class_name(kl) == \
                "urn:oasis:names:tc:SAML:2.0:assertion:SubjectConfirmation"


def test_ee_1():
    ee = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?><foo>bar</foo>""")
    assert ee != None
    print ee.__dict__
    assert ee.attributes == {}
    assert ee.tag == "foo"
    assert ee.namespace == None
    assert ee.children == []
    assert ee.text == "bar"

def test_ee_2():
    ee = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?><foo id="xyz">bar</foo>""")
    assert ee != None
    print ee.__dict__
    assert ee.attributes == {"id":"xyz"}
    assert ee.tag == "foo"
    assert ee.namespace == None
    assert ee.children == []
    assert ee.text == "bar"
    
def test_ee_3():
    ee = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?>
        <foo xmlns="urn:mace:example.com:saml:ns" 
        id="xyz">bar</foo>""")
    assert ee != None
    print ee.__dict__
    assert ee.attributes == {"id":"xyz"}
    assert ee.tag == "foo"
    assert ee.namespace == "urn:mace:example.com:saml:ns"
    assert ee.children == []
    assert ee.text == "bar"

def test_ee_4():
    ee = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?>
        <foo xmlns="urn:mace:example.com:saml:ns">
        <id>xyz</id><bar>tre</bar></foo>""")
    assert ee != None
    print ee.__dict__
    assert ee.attributes == {}
    assert ee.tag == "foo"
    assert ee.namespace == "urn:mace:example.com:saml:ns"
    assert len(ee.children) == 2
    assert ee.text.strip() == ""
    id = ee.find_children("id", "urn:mace:example.com:saml:namespace")
    assert id == []
    ids = ee.find_children("id", "urn:mace:example.com:saml:ns")
    assert ids != []
    id = ids[0]
    print id.__dict__
    assert id.attributes == {}
    assert id.tag == "id"
    assert id.namespace == "urn:mace:example.com:saml:ns"
    assert id.children == []
    assert id.text.strip() == "xyz"

def test_ee_5():
    ee = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?>
        <foo xmlns="urn:mace:example.com:saml:ns">bar</foo>""")
        
    ce = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?>
        <educause xmlns="urn:mace:example.com:saml:cu">rev</educause>""")
    
    ee.children.append(ce)
    
    assert ee != None
    print ee.__dict__
    assert ee.attributes == {}
    assert ee.tag == "foo"
    assert ee.namespace == "urn:mace:example.com:saml:ns"
    assert len(ee.children) == 1
    assert ee.text.strip() == "bar"
    
    c = ee.children[0]
    print c.__dict__
    
    child = ee.find_children(namespace="urn:mace:example.com:saml:cu")
    assert len(child) == 1
    child = ee.find_children(namespace="urn:mace:example.com:saml:ns")
    assert len(child) == 0
    child = ee.find_children("educause","urn:mace:example.com:saml:cu")
    assert len(child) == 1
    child = ee.find_children("edugain","urn:mace:example.com:saml:cu")
    assert len(child) == 0
    print ee.to_string()
    
def test_ee_6():
    ee = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?>
        <foo xmlns="urn:mace:example.com:saml:ns">bar</foo>""")
        
    ce = saml2.extension_element_from_string(
        """<?xml version='1.0' encoding='UTF-8'?>
        <educause xmlns="urn:mace:example.com:saml:cu">rev</educause>""")
    
    et = ee.transfer_to_element_tree()
    ce.become_child_element(et)
    
    pee = saml2._extension_element_from_element_tree(et)
    
    assert pee != None
    print pee.__dict__
    assert pee.attributes == {}
    assert pee.tag == "foo"
    assert pee.namespace == "urn:mace:example.com:saml:ns"
    assert len(pee.children) == 1
    assert pee.text.strip() == "bar"
    
    c = pee.children[0]
    print c.__dict__
    
    child = pee.find_children(namespace="urn:mace:example.com:saml:cu")
    assert len(child) == 1
    child = pee.find_children(namespace="urn:mace:example.com:saml:ns")
    assert len(child) == 0
    child = pee.find_children("educause","urn:mace:example.com:saml:cu")
    assert len(child) == 1
    child = pee.find_children("edugain","urn:mace:example.com:saml:cu")
    assert len(child) == 0
    print pee.to_string()
    

NAMEID_WITH_ATTRIBUTE_EXTENSION = """<?xml version="1.0" encoding="utf-8"?>
<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
  xmlns:local="urn:mace:example.com:saml:assertion"
  Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  SPProvidedID="sp provided id"
  local:Foo="BAR">
  roland@example.com
</NameID>
"""

def test_nameid_with_extension():
    kl = create_class_from_xml_string(NameID, NAMEID_WITH_ATTRIBUTE_EXTENSION)
    assert kl != None
    print kl.__dict__
    assert kl.format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert kl.sp_provided_id == "sp provided id"
    assert kl.text.strip() == "roland@example.com"
    assert _eq(kl.keyswv(), ['sp_provided_id', 'format', 
                            'extension_attributes', 'text'])
    assert class_name(kl) == "urn:oasis:names:tc:SAML:2.0:assertion:NameID"
    assert _eq(kl.keys(), ['sp_provided_id', 'sp_name_qualifier', 
                            'name_qualifier', 'format', 'text'])
    assert kl.extension_attributes == {
                            '{urn:mace:example.com:saml:assertion}Foo': 'BAR'}

SUBJECT_CONFIRMATION_WITH_MEMBER_EXTENSION = """<?xml version="1.0" encoding="utf-8"?>
<SubjectConfirmation xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<NameID
Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NameQualifier="http://authentic.example.com/saml/metadata">test@example.com
</NameID>
<SubjectConfirmationData
NotOnOrAfter="2010-02-17T17:02:38Z"
Recipient="http://auth.example.com/saml/proxySingleSignOnRedirect"
InResponseTo="_59B3A01B03334032C31E434C63F89E3E"/>
<local:Trustlevel xmlns:local="urn:mace:example.com:saml:assertion">
Excellent
</local:Trustlevel>
</SubjectConfirmation>"""

def test_subject_confirmation_with_extension():
    kl = create_class_from_xml_string(SubjectConfirmation,  
                                    SUBJECT_CONFIRMATION_WITH_MEMBER_EXTENSION)
    assert kl != None
    print kl.__dict__
    assert kl.extension_attributes == {}
    assert kl.method == "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    name_id = kl.name_id
    assert _eq(name_id.keyswv(), ['format', 'name_qualifier', 'text'])
    assert name_id.format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert name_id.name_qualifier == "http://authentic.example.com/saml/metadata"
    assert name_id.text.strip() == "test@example.com"
    subject_confirmation_data = kl.subject_confirmation_data
    assert _eq(subject_confirmation_data.keyswv(), ['not_on_or_after', 
                            'recipient', 'in_response_to'])
    assert subject_confirmation_data.recipient == \
                    "http://auth.example.com/saml/proxySingleSignOnRedirect"
    assert subject_confirmation_data.not_on_or_after == "2010-02-17T17:02:38Z"
    assert subject_confirmation_data.in_response_to == \
                    "_59B3A01B03334032C31E434C63F89E3E"
    assert len(kl.extension_elements) == 1
    ee = kl.extension_elements[0]
    assert ee.tag == "Trustlevel"
    assert ee.namespace == "urn:mace:example.com:saml:assertion"
    assert ee.text.strip() == "Excellent"
    