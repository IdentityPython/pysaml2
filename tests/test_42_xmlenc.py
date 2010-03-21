import saml2
import xmlenc
import xmldsig

data1 = """<?xml version='1.0'?> 
<EncryptedData xmlns='http://www.w3.org/2001/04/xmlenc#'
MimeType='text/xml'>
<CipherData>
  <CipherValue>A23B45C56</CipherValue>
</CipherData>
</EncryptedData>"""

def test_1():
    ed = xmlenc.encrypted_data_from_string(data1)
    assert ed
    assert ed.mime_type == "text/xml"
    assert len(ed.cipher_data) == 1
    cd = ed.cipher_data[0]
    assert len(cd.cipher_value) == 1
    assert cd.cipher_value[0].text == "A23B45C56"
    
data2 = """<EncryptedData xmlns='http://www.w3.org/2001/04/xmlenc#'
        Type='http://www.w3.org/2001/04/xmlenc#Element'>
    <EncryptionMethod
        Algorithm='http://www.w3.org/2001/04/xmlenc#tripledes-cbc'/>
    <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
        <ds:KeyName>John Smith</ds:KeyName>
    </ds:KeyInfo>
    <CipherData><CipherValue>DEADBEEF</CipherValue></CipherData>
</EncryptedData>"""

def test_2():
    ed = xmlenc.encrypted_data_from_string(data2)
    assert ed
    print ed
    assert ed.typ == "http://www.w3.org/2001/04/xmlenc#Element"
    assert len(ed.encryption_method) == 1
    em = ed.encryption_method[0]
    assert em.algorithm == 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
    assert len(ed.key_info) == 1
    ki = ed.key_info[0]
    assert ki.key_name[0].text == "John Smith"
    assert len(ed.cipher_data) == 1
    cd = ed.cipher_data[0]
    assert len(cd.cipher_value) == 1
    assert cd.cipher_value[0].text == "DEADBEEF"

data3 = """<EncryptedData Id='ED' 
         xmlns='http://www.w3.org/2001/04/xmlenc#'>
    <EncryptionMethod 
        Algorithm='http://www.w3.org/2001/04/xmlenc#aes128-cbc'/>
    <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
        <ds:RetrievalMethod URI='#EK'
             Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey"/>
        <ds:KeyName>Sally Doe</ds:KeyName>
    </ds:KeyInfo>
    <CipherData><CipherValue>DEADBEEF</CipherValue></CipherData>
</EncryptedData>"""

def test_3():
    ed = xmlenc.encrypted_data_from_string(data3)
    assert ed
    print ed
    assert len(ed.encryption_method) == 1
    em = ed.encryption_method[0]
    assert em.algorithm == 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
    assert len(ed.key_info) == 1
    ki = ed.key_info[0]
    assert ki.key_name[0].text == "Sally Doe"
    assert len(ki.retrieval_method) == 1
    rm = ki.retrieval_method[0]
    assert rm.uri == "#EK"
    assert rm.type == "http://www.w3.org/2001/04/xmlenc#EncryptedKey"
    assert len(ed.cipher_data) == 1
    cd = ed.cipher_data[0]
    assert len(cd.cipher_value) == 1
    assert cd.cipher_value[0].text == "DEADBEEF"

data4 = """<EncryptedKey Id='EK' xmlns='http://www.w3.org/2001/04/xmlenc#'>
    <EncryptionMethod 
           Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
    <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
        <ds:KeyName>John Smith</ds:KeyName>
    </ds:KeyInfo>
    <CipherData><CipherValue>xyzabc</CipherValue></CipherData>
    <ReferenceList>
        <DataReference URI='#ED'/>
    </ReferenceList>
    <CarriedKeyName>Sally Doe</CarriedKeyName>
</EncryptedKey>"""

def test_4():
    ek = xmlenc.encrypted_key_from_string(data4)
    assert ek
    print ek
    assert len(ek.encryption_method) == 1
    em = ek.encryption_method[0]
    assert em.algorithm == 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
    assert len(ek.key_info) == 1
    ki = ek.key_info[0]
    assert ki.key_name[0].text == "John Smith"
    assert len(ek.reference_list) == 1
    rl = ek.reference_list[0]
    assert len(rl.data_reference)
    dr = rl.data_reference[0]
    assert dr.uri == "#ED"
    assert len(ek.cipher_data) == 1
    cd = ek.cipher_data[0]
    assert len(cd.cipher_value) == 1
    assert cd.cipher_value[0].text == "xyzabc"

data5 = """<CipherReference URI="http://www.example.com/CipherValues.xml"
    xmlns="http://www.w3.org/2001/04/xmlenc#">
    <Transforms xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
        <ds:Transform 
           Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
           <ds:XPath xmlns:rep="http://www.example.org/repository">
             self::text()[parent::rep:CipherValue[@Id="example1"]]
           </ds:XPath>
        </ds:Transform>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
    </Transforms>
</CipherReference>"""

def test_5():
    cr = xmlenc.cipher_reference_from_string(data5)
    assert cr
    print cr
    assert len(cr.transforms) == 1
    trs = cr.transforms[0]
    assert len(trs.transform) == 2
    tr = trs.transform[0]
    assert tr.algorithm in ["http://www.w3.org/TR/1999/REC-xpath-19991116",
            "http://www.w3.org/2000/09/xmldsig#base64"]
    if tr.algorithm == "http://www.w3.org/2000/09/xmldsig#base64":
        pass
    elif tr.algorithm == "http://www.w3.org/TR/1999/REC-xpath-19991116":
        assert len(tr.xpath) == 1
        xp = tr.xpath[0]
        assert xp.text.strip() == """self::text()[parent::rep:CipherValue[@Id="example1"]]"""
        
        
data6 = """<ReferenceList xmlns="http://www.w3.org/2001/04/xmlenc#">
    <DataReference URI="#invoice34">
      <ds:Transforms xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
          <ds:XPath xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
              self::xenc:EncryptedData[@Id="example1"]
          </ds:XPath>
        </ds:Transform>
      </ds:Transforms>
    </DataReference>
</ReferenceList>"""

def test_6():
    rl = xmlenc.reference_list_from_string(data6)
    assert rl
    print rl
    assert len(rl.data_reference) == 1
    dr = rl.data_reference[0]
    assert dr.uri == "#invoice34"
    assert len(dr.extension_elements) == 1
    ee = dr.extension_elements[0]
    assert ee.c_tag == "Transforms"
    assert ee.c_namespace == "http://www.w3.org/2000/09/xmldsig#"
    trs = saml2.extension_element_to_element(ee, xmldsig.ELEMENT_FROM_STRING,
                                        namespace=xmldsig.NAMESPACE)
    
    assert trs
    assert len(trs.transform) == 1
    tr = trs.transform[0]
    assert tr.algorithm == "http://www.w3.org/TR/1999/REC-xpath-19991116"
    assert len(tr.xpath) == 1
    assert tr.xpath[0].text.strip() == """self::xenc:EncryptedData[@Id="example1"]"""
    