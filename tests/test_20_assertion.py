from saml2.mdie import to_dict
from saml2 import md, assertion
from saml2.saml import Attribute, NAME_FORMAT_URI, AttributeValue
from saml2.assertion import Policy, Assertion, filter_on_attributes
from saml2.assertion import filter_attribute_value_assertions, from_local
from saml2.s_utils import MissingValue
from saml2 import attribute_converter
from saml2.attribute_converter import ac_factory

from py.test import raises

from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
from saml2 import saml
import xmldsig
import xmlenc

from pathutils import full_path

ONTS = [saml, mdui, mdattr, dri, ui, idpdisc, md, xmldsig, xmlenc]

def _eq(l1,l2):
    return set(l1) == set(l2)

gn = to_dict(md.RequestedAttribute(name="urn:oid:2.5.4.42",
                                   friendly_name="givenName",
                                   name_format=NAME_FORMAT_URI),ONTS)

sn = to_dict(md.RequestedAttribute(name="urn:oid:2.5.4.4",
                                   friendly_name="surName",
                                   name_format=NAME_FORMAT_URI), ONTS)

mail = to_dict(md.RequestedAttribute(name="urn:oid:0.9.2342.19200300.100.1.3",
                                     friendly_name="mail",
                                     name_format=NAME_FORMAT_URI), ONTS)

# ---------------------------------------------------------------------------

def test_filter_on_attributes_0():
    a = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber"), ONTS)

    required = [a]
    ava = { "serialNumber": ["12345"]}
    
    ava = filter_on_attributes(ava, required)
    assert ava.keys() == ["serialNumber"]
    assert ava["serialNumber"] == ["12345"]

def test_filter_on_attributes_1():
    a = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber"), ONTS)
    
    required = [a]
    ava = { "serialNumber": ["12345"], "givenName":["Lars"]}
    
    ava = filter_on_attributes(ava, required)
    assert ava.keys() == ["serialNumber"]
    assert ava["serialNumber"] == ["12345"]


# ----------------------------------------------------------------------

def test_lifetime_1():
    conf = {
            "default": {
                "lifetime": {"minutes":15},
                "attribute_restrictions": None # means all I have
            },
            "urn:mace:umu.se:saml:roland:sp": {
                "lifetime": {"minutes": 5},
                "attribute_restrictions":{
                    "givenName": None,
                    "surName": None,
                    "mail": [".*@.*\.umu\.se"],
                }
            }}
    
    r = Policy(conf)
    assert r is not None
    
    assert r.get_lifetime("urn:mace:umu.se:saml:roland:sp") == {"minutes": 5}               
    assert r.get_lifetime("urn:mace:example.se:saml:sp") == {"minutes": 15}
    
def test_lifetime_2():
    conf = {
            "default": {
                "attribute_restrictions": None # means all I have
            },
            "urn:mace:umu.se:saml:roland:sp": {
                "lifetime": {"minutes": 5},
                "attribute_restrictions":{
                    "givenName": None,
                    "surName": None,
                    "mail": [".*@.*\.umu\.se"],
                }
            }}
    
    r = Policy(conf)
    assert r is not None
    
    assert r.get_lifetime("urn:mace:umu.se:saml:roland:sp") == {"minutes": 5}               
    assert r.get_lifetime("urn:mace:example.se:saml:sp") == {"hours": 1}        

    
def test_ava_filter_1():
    conf = {
        "default": {
            "lifetime": {"minutes":15},
            "attribute_restrictions": None # means all I have
        },
        "urn:mace:umu.se:saml:roland:sp": {
            "lifetime": {"minutes": 5},
            "attribute_restrictions":{
                "givenName": None,
                "surName": None,
                "mail": [".*@.*\.umu\.se"],
            }
        }}

    r = Policy(conf)
    
    ava = {"givenName":"Derek", 
            "surName": "Jeter", 
            "mail":"derek@example.com"}
    
    ava = r.filter(ava,"urn:mace:umu.se:saml:roland:sp",None,None)
    assert _eq(ava.keys(), ["givenName","surName"])

    ava = {"givenName":"Derek", 
            "mail":"derek@nyy.umu.se"}

    assert _eq(ava.keys(), ["givenName","mail"])

def test_ava_filter_2():
    conf = {
        "default": {
            "lifetime": {"minutes":15},
            "attribute_restrictions": None # means all I have
        },
        "urn:mace:umu.se:saml:roland:sp": {
            "lifetime": {"minutes": 5},
            "attribute_restrictions":{
                "givenName": None,
                "surName": None,
                "mail": [".*@.*\.umu\.se"],
            }
        }}

    policy = Policy(conf)
    
    ava = {"givenName":"Derek", 
            "surName": "Jeter", 
            "mail":"derek@example.com"}

    raises(Exception, policy.filter, ava, 'urn:mace:umu.se:saml:roland:sp',
           [mail], [gn, sn])

    ava = {"givenName":"Derek", 
            "surName": "Jeter"}

    # it wasn't there to begin with
    raises(Exception, policy.filter, ava, 'urn:mace:umu.se:saml:roland:sp',
           [gn, sn, mail])

def test_filter_attribute_value_assertions_0(AVA):    
    p = Policy({
        "default": {
            "attribute_restrictions": {
                "surName": [".*berg"],
            }
        }
    })
    
    ava = filter_attribute_value_assertions(AVA[3].copy(), 
                                            p.get_attribute_restriction(""))
    
    print ava
    assert ava.keys() == ["surName"]
    assert ava["surName"] == ["Hedberg"]

def test_filter_attribute_value_assertions_1(AVA):
    p = Policy({
        "default": {
            "attribute_restrictions": {
                "surName": None,
                "givenName": [".*er.*"],
            }
        }
    })
        
    ava = filter_attribute_value_assertions(AVA[0].copy(), 
                                            p.get_attribute_restriction(""))
    
    print ava
    assert _eq(ava.keys(), ["givenName","surName"])
    assert ava["surName"] == ["Jeter"]
    assert ava["givenName"] == ["Derek"]

    ava = filter_attribute_value_assertions(AVA[1].copy(),
                                            p.get_attribute_restriction(""))
    
    print ava
    assert _eq(ava.keys(), ["surName"])
    assert ava["surName"] == ["Howard"]
    
    
def test_filter_attribute_value_assertions_2(AVA):
    p = Policy({
        "default": {
            "attribute_restrictions": {
                "givenName": ["^R.*"],
            }
        }
    })
    
    ava = filter_attribute_value_assertions(AVA[0].copy(), 
                                            p.get_attribute_restriction(""))
    
    print ava
    assert _eq(ava.keys(), [])
    
    ava = filter_attribute_value_assertions(AVA[1].copy(), 
                                            p.get_attribute_restriction(""))
    
    print ava
    assert _eq(ava.keys(), ["givenName"])
    assert ava["givenName"] == ["Ryan"]

    ava = filter_attribute_value_assertions(AVA[3].copy(), 
                                            p.get_attribute_restriction(""))
    
    print ava
    assert _eq(ava.keys(), ["givenName"])
    assert ava["givenName"] == ["Roland"]

# ----------------------------------------------------------------------------

def test_assertion_1(AVA):
    ava = Assertion(AVA[0])
    
    print ava
    print ava.__dict__

    policy = Policy({
        "default": {
            "attribute_restrictions": {
                "givenName": ["^R.*"],
            }
        }
    })

    ava = ava.apply_policy( "", policy )
    
    print ava
    assert _eq(ava.keys(), [])

    ava = Assertion(AVA[1].copy())
    ava = ava.apply_policy( "", policy )
    assert _eq(ava.keys(), ["givenName"])
    assert ava["givenName"] == ["Ryan"]

    ava = Assertion(AVA[3].copy())
    ava = ava.apply_policy( "", policy )
    assert _eq(ava.keys(), ["givenName"])
    assert ava["givenName"] == ["Roland"]

def test_assertion_2():
    AVA = {'mail': u'roland.hedberg@adm.umu.se',
           'eduPersonTargetedID': 'http://lingon.ladok.umu.se:8090/idp!http://lingon.ladok.umu.se:8088/sp!95e9ae91dbe62d35198fbbd5e1fb0976',
           'displayName': u'Roland Hedberg',
           'uid': 'http://roland.hedberg.myopenid.com/'}

    ava = Assertion(AVA)

    policy = Policy( {
        "default": {
            "lifetime": {"minutes": 240},
            "attribute_restrictions": None, # means all I have
            "name_form": NAME_FORMAT_URI
        },
    })

    ava = ava.apply_policy( "", policy )
    acs = ac_factory(full_path("attributemaps"))
    attribute=from_local(acs, ava, policy.get_name_form(""))

    assert len(attribute) == 4
    names = [attr.name for attr in attribute]
    assert _eq(names, ['urn:oid:0.9.2342.19200300.100.1.3',
                       'urn:oid:1.3.6.1.4.1.5923.1.1.1.10',
                       'urn:oid:2.16.840.1.113730.3.1.241',
                       'urn:oid:0.9.2342.19200300.100.1.1'])

# ----------------------------------------------------------------------------
    
def test_filter_values_req_2():
    a1 = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber"), ONTS)
    a2 = to_dict(Attribute(name="urn:oid:2.5.4.4", name_format=NAME_FORMAT_URI,
                    friendly_name="surName"), ONTS)
    
    required = [a1,a2]
    ava = { "serialNumber": ["12345"], "givenName":["Lars"]}
    
    raises(MissingValue, filter_on_attributes, ava, required)

def test_filter_values_req_3():
    a = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="12345")]), ONTS)
    
    required = [a]
    ava = { "serialNumber": ["12345"]}
    
    ava = filter_on_attributes(ava, required)
    assert ava.keys() == ["serialNumber"]
    assert ava["serialNumber"] == ["12345"]

def test_filter_values_req_4():
    a = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="54321")]), ONTS)
    
    required = [a]
    ava = { "serialNumber": ["12345"]}
    
    raises(MissingValue, filter_on_attributes, ava, required)

def test_filter_values_req_5():
    a = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="12345")]), ONTS)
    
    required = [a]
    ava = { "serialNumber": ["12345", "54321"]}
    
    ava = filter_on_attributes(ava, required)
    assert ava.keys() == ["serialNumber"]
    assert ava["serialNumber"] == ["12345"]

def test_filter_values_req_6():
    a = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="54321")]),ONTS)
    
    required = [a]
    ava = { "serialNumber": ["12345", "54321"]}
    
    ava = filter_on_attributes(ava, required)
    assert ava.keys() == ["serialNumber"]
    assert ava["serialNumber"] == ["54321"]

def test_filter_values_req_opt_0():
    r = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="54321")]),ONTS)
    o = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="12345")]),ONTS)
    
    ava = { "serialNumber": ["12345", "54321"]}
    
    ava = filter_on_attributes(ava, [r], [o])
    assert ava.keys() == ["serialNumber"]
    assert _eq(ava["serialNumber"], ["12345","54321"])

def test_filter_values_req_opt_1():
    r = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="54321")]), ONTS)
    o = to_dict(Attribute(name="urn:oid:2.5.4.5", name_format=NAME_FORMAT_URI,
                    friendly_name="serialNumber", attribute_value=[
                        AttributeValue(text="12345"),
                        AttributeValue(text="abcd0")]), ONTS)
    
    ava = { "serialNumber": ["12345", "54321"]}
    
    ava = filter_on_attributes(ava, [r], [o])
    assert ava.keys() == ["serialNumber"]
    assert _eq(ava["serialNumber"], ["12345","54321"])

def test_filter_values_req_opt_2():
    r = [to_dict(Attribute(friendly_name="surName",
                name="urn:oid:2.5.4.4",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
                ONTS),
         to_dict(Attribute(friendly_name="givenName",
                name="urn:oid:2.5.4.42",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
                ONTS),
         to_dict(Attribute(friendly_name="mail",
                name="urn:oid:0.9.2342.19200300.100.1.3",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
                ONTS)]
    o = [to_dict(Attribute(friendly_name="title",
                name="urn:oid:2.5.4.12",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
                ONTS)]
                    
    
    ava = { "surname":["Hedberg"], "givenName":["Roland"],
            "eduPersonAffiliation":["staff"],"uid":["rohe0002"]}
    
    raises(MissingValue, "filter_on_attributes(ava, r, o)")

# ---------------------------------------------------------------------------

def test_filter_values_req_opt_4():
    r = [Attribute(friendly_name="surName",
                name="urn:oid:2.5.4.4",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
         Attribute(friendly_name="givenName",
                name="urn:oid:2.5.4.42",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),]
    o = [Attribute(friendly_name="title",
                name="urn:oid:2.5.4.12",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")]

    acs = attribute_converter.ac_factory(full_path("attributemaps"))
                    
    rava = attribute_converter.ava_fro(acs, r)
    oava = attribute_converter.ava_fro(acs, o)
    
    ava = { "sn":["Hedberg"], "givenName":["Roland"],
            "eduPersonAffiliation":["staff"],"uid":["rohe0002"]}
    
    ava = assertion.filter_on_demands(ava, rava, oava)
    print ava
    assert _eq(ava.keys(), ['givenName', 'sn'])
    assert ava == {'givenName': ['Roland'], 'sn': ['Hedberg']}
    
# ---------------------------------------------------------------------------


def test_filter_ava_0():
    policy = Policy({
                "default": {
                    "lifetime": {"minutes":15},
                    "attribute_restrictions": None # means all I have
                },
                "urn:mace:example.com:saml:roland:sp": {
                    "lifetime": {"minutes": 5},
                }
            })
            
    ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
            "mail": ["derek@nyy.mlb.com"]}
    
    # No restrictions apply
    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp",
                            [], [])
                                
    assert _eq(ava.keys(), ["givenName", "surName", "mail"])
    assert ava["givenName"] == ["Derek"]
    assert ava["surName"] == ["Jeter"]
    assert ava["mail"] == ["derek@nyy.mlb.com"]
        
        
def test_filter_ava_1():
    """ No mail address returned """
    policy = Policy({
            "default": {
                "lifetime": {"minutes":15},
                "attribute_restrictions": None # means all I have
            },
            "urn:mace:example.com:saml:roland:sp": {
                "lifetime": {"minutes": 5},
                "attribute_restrictions":{
                    "givenName": None,
                    "surName": None,
                }
            }})
    
    ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
            "mail": ["derek@nyy.mlb.com"]}
    
    # No restrictions apply
    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp", [], [])
                                
    assert _eq(ava.keys(), ["givenName", "surName"])
    assert ava["givenName"] == ["Derek"]
    assert ava["surName"] == ["Jeter"]

def test_filter_ava_2():
    """ Only mail returned """
    policy = Policy({
            "default": {
                "lifetime": {"minutes":15},
                "attribute_restrictions": None # means all I have
            },
            "urn:mace:example.com:saml:roland:sp": {
                "lifetime": {"minutes": 5},
                "attribute_restrictions":{
                    "mail": None,
                }
            }})
    
    ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
            "mail": ["derek@nyy.mlb.com"]}
    
    # No restrictions apply
    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp", [], [])
                                
    assert _eq(ava.keys(), ["mail"])
    assert ava["mail"] == ["derek@nyy.mlb.com"]

def test_filter_ava_3():
    """ Only example.com mail addresses returned """
    policy = Policy({
            "default": {
                "lifetime": {"minutes":15},
                "attribute_restrictions": None # means all I have
            },
            "urn:mace:example.com:saml:roland:sp": {
                "lifetime": {"minutes": 5},
                "attribute_restrictions":{
                    "mail": [".*@example\.com$"],
                }
            }})
    
    ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
            "mail": ["derek@nyy.mlb.com", "dj@example.com"]}
    
    # No restrictions apply
    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp", [], [])
                                
    assert _eq(ava.keys(), ["mail"])
    assert ava["mail"] == ["dj@example.com"]

def test_filter_ava_4():
    """ Return everything as default policy is used """
    policy = Policy({
            "default": {
                "lifetime": {"minutes":15},
                "attribute_restrictions": None # means all I have
            },
            "urn:mace:example.com:saml:roland:sp": {
                "lifetime": {"minutes": 5},
                "attribute_restrictions":{
                    "mail": [".*@example\.com$"],
                }
            }})
    
    ava = { "givenName": ["Derek"], "surName": ["Jeter"], 
            "mail": ["derek@nyy.mlb.com", "dj@example.com"]}
    
    # No restrictions apply
    ava = policy.filter(ava, "urn:mace:example.com:saml:curt:sp", [], [])
                                
    assert _eq(ava.keys(), ['mail', 'givenName', 'surName'])
    assert _eq(ava["mail"], ["derek@nyy.mlb.com", "dj@example.com"])

def test_req_opt():
    req = [to_dict(md.RequestedAttribute(friendly_name="surname", name="urn:oid:2.5.4.4",
                                 name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                 is_required="true"),ONTS),
           to_dict(md.RequestedAttribute(friendly_name="givenname",
                                 name="urn:oid:2.5.4.42",
                                 name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                 is_required="true"),ONTS),
           to_dict(md.RequestedAttribute(friendly_name="edupersonaffiliation",
                                 name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
                                 name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                 is_required="true"),ONTS)]

    opt = [to_dict(md.RequestedAttribute(friendly_name="title",
                    name="urn:oid:2.5.4.12",
                    name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                    is_required="false"), ONTS)]
                
    policy = Policy()
    ava = {'givenname': 'Roland', 'surname': 'Hedberg', 
            'uid': 'rohe0002', 'edupersonaffiliation': 'staff'}
            
    sp_entity_id = "urn:mace:example.com:saml:curt:sp"
    fava = policy.filter(ava, sp_entity_id, req, opt)
    assert fava

def test_filter_on_wire_representation_1():
    r = [Attribute(friendly_name="surName",
            name="urn:oid:2.5.4.4",
            name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
        Attribute(friendly_name="givenName",
                name="urn:oid:2.5.4.42",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")]
    o = [Attribute(friendly_name="title",
                name="urn:oid:2.5.4.12",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")]

    acs = attribute_converter.ac_factory(full_path("attributemaps"))

    ava = { "sn":["Hedberg"], "givenname":["Roland"],
            "edupersonaffiliation":["staff"],"uid":["rohe0002"]}

    ava = assertion.filter_on_wire_representation(ava, acs, r, o)
    assert _eq(ava.keys(), ["sn", "givenname"])

def test_filter_on_wire_representation_2():
    r = [Attribute(friendly_name="surName",
            name="urn:oid:2.5.4.4",
            name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
        Attribute(friendly_name="givenName",
                name="urn:oid:2.5.4.42",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")]
    o = [Attribute(friendly_name="title",
                name="urn:oid:2.5.4.12",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")]

    acs = attribute_converter.ac_factory(full_path("attributemaps"))

    ava = { "sn":["Hedberg"], "givenname":["Roland"],
            "title":["Master"],"uid":["rohe0002"]}

    ava = assertion.filter_on_wire_representation(ava, acs, r, o)
    assert _eq(ava.keys(), ["sn", "givenname", "title"])
