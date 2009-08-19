
import saml2
from saml2 import SamlBase

DS_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'

class Foo(SamlBase):
    etag = "Foo"
    enamespace = DS_NAMESPACE
    
    def __init__(self, extension_elements=None, extension_attributes=None,
            text=None):
        SamlBase.__init__(self, extension_elements, extension_attributes, text)
        
def cmplist(list0,list1):
    return set(list0) == set(list1)
    
class TestBase:
    def test_init(self):
        b = saml2.SamlBase()
        assert b._attributes == {}
        assert cmplist(b.__dict__.keys(), ['extension_attributes', '_children', 
            'text', '_attributes', 'etag',
            'enamespace', '_child_order', 'extension_elements'])
        assert b.text == None
        assert b.etag == ''
        assert b.enamespace == ''
        assert b._attributes == {}
        assert b._children == {}
        assert b._child_order == []
        assert b.extension_attributes == {}
        assert b.extension_elements == []

    def test_init_attr(self):
        b = saml2.SamlBase()
        b._init_attribute('Id','identifier',"urn:mace:example.org:foo#bar")
        assert b._attributes == {'Id': 'identifier'}
        assert b.identifier == 'urn:mace:example.org:foo#bar'
        assert b.text == None
        assert b.etag == ''
        assert b.enamespace == ''
        assert b._children == {}
        assert b._child_order == []
        assert b.extension_attributes == {}
        assert b.extension_elements == []

    def test_init_child(self):
        b = saml2.SamlBase()
        xml_name = '{%s}Foo' % DS_NAMESPACE
        b._init_child(xml_name, 'foo', [Foo], [])

        assert b.text == None
        assert b.etag == ''
        assert b.enamespace == ''
        assert b._attributes == {}
        assert b._children.has_key(xml_name)
        assert b._children[xml_name] == ("foo", [Foo])
        assert b._child_order == []
        assert b.extension_attributes == {}
        assert b.extension_elements == []

        