from contextlib import closing

from pathutils import full_path
from saml2 import config
from saml2 import sigver
from saml2.assertion import Policy
from saml2.attribute_converter import ac_factory
from saml2.extension import mdattr
from saml2.mdie import to_dict
from saml2.mdstore import MetadataStore
from saml2.saml import Attribute, NAME_FORMAT_URI
from saml2.server import Server

ATTRCONV = ac_factory(full_path("attributemaps"))
sec_config = config.Config()
sec_config.xmlsec_binary = sigver.get_xmlsec_binary(["/opt/local/bin"])

__author__ = 'rolandh'

MDS = MetadataStore(ATTRCONV, sec_config,
                    disable_ssl_certificate_validation=True)
MDS.imp([{"class": "saml2.mdstore.MetaDataMD",
          "metadata": [(full_path("swamid.md"),)]}])


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_filter_ava():
    policy_conf = {
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    }
    policy = Policy(policy_conf, MDS)

    ava = {
        "givenName": ["Derek"],
        "sn": ["Jeter"],
        "mail": ["derek@nyy.mlb.com", "dj@example.com"],
        "c": ["USA"]
    }

    ava = policy.filter(ava, "https://connect.sunet.se/shibboleth")

    assert _eq(list(ava.keys()), ['mail', 'givenName', 'sn', 'c'])
    assert _eq(ava["mail"], ["derek@nyy.mlb.com", "dj@example.com"])


def test_filter_ava2():
    policy_conf = {
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["refeds", "edugain"]
        }
    }
    policy = Policy(policy_conf, MDS)

    ava = {
        "givenName": ["Derek"],
        "sn": ["Jeter"],
        "mail": ["derek@nyy.mlb.com"],
        "c": ["USA"],
        "eduPersonTargetedID": "foo!bar!xyz"
    }

    ava = policy.filter(ava, "https://connect.sunet.se/shibboleth")

    # Mismatch, policy deals with eduGAIN, metadata says SWAMID
    # So only minimum should come out
    assert _eq(list(ava.keys()), ['eduPersonTargetedID'])


def test_filter_ava3():
    mds = MetadataStore(ATTRCONV, sec_config, disable_ssl_certificate_validation=True)
    mds.imp(
        [
            {
                "class": "saml2.mdstore.MetaDataFile",
                "metadata": [(full_path("entity_cat_sfs_hei.xml"),)]
            }
        ]
    )

    policy_conf = {
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    }
    policy = Policy(policy_conf, mds)

    ava = {
        "givenName": ["Derek"],
        "sn": ["Jeter"],
        "mail": ["derek@nyy.mlb.com"],
        "c": ["USA"],
        "eduPersonTargetedID": "foo!bar!xyz",
        "norEduPersonNIN": "19800101134"
    }

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp")
    assert _eq(list(ava.keys()), ["norEduPersonNIN"])


def test_filter_ava4():
    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True)
    mds.imp([{"class": "saml2.mdstore.MetaDataFile",
              "metadata": [(full_path("entity_cat_re_nren.xml"),)]}])

    policy_conf = {
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    }
    policy = Policy(policy_conf, mds)

    ava = {
        "givenName": ["Derek"],
        "sn": ["Jeter"],
        "mail": ["derek@nyy.mlb.com"],
        "c": ["USA"],
        "eduPersonTargetedID": "foo!bar!xyz",
        "norEduPersonNIN": "19800101134"
    }

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp")
    assert _eq(
        list(ava.keys()), ["givenName", "c", "mail", "sn"]
    )


def test_filter_ava5():
    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True)
    mds.imp([{"class": "saml2.mdstore.MetaDataFile",
              "metadata": [(full_path("entity_cat_re.xml"),)]}])

    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    }, mds)

    ava = {
        "givenName": ["Derek"],
        "sn": ["Jeter"],
        "mail": ["derek@nyy.mlb.com"],
        "c": ["USA"],
        "eduPersonTargetedID": "foo!bar!xyz",
        "norEduPersonNIN": "19800101134"
    }

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp")

    assert _eq(list(ava.keys()), [])


def test_idp_policy_filter():
    with closing(Server("idp_conf_ec")) as idp:
        ava = {
            "givenName": ["Derek"],
            "sn": ["Jeter"],
            "mail": ["derek@nyy.mlb.com"],
            "c": ["USA"],
            "eduPersonTargetedID": "foo!bar!xyz",
            "norEduPersonNIN": "19800101134"
        }

        policy = idp.config.getattr("policy", "idp")
        ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp")
        # because no entity category
        assert list(ava.keys()) == ["eduPersonTargetedID"]


def test_entity_category_import_from_path():
    mds = MetadataStore(ATTRCONV, sec_config, disable_ssl_certificate_validation=True)
    # The file entity_cat_rs.xml contains the SAML metadata for an SP
    # tagged with the REFEDs R&S entity category.
    mds.imp([{"class": "saml2.mdstore.MetaDataFile",
              "metadata": [(full_path("entity_cat_rs.xml"),)]}])

    # The entity category module myentitycategory.py is in the tests
    # directory which is on the standard module search path.
    # The module uses a custom interpretation of the REFEDs R&S entity category
    # by adding eduPersonUniqueId.
    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            "entity_categories": ["myentitycategory"]
        }
    }, mds)

    ava = {
        "givenName": ["Derek"],
        "sn": ["Jeter"],
        "displayName": "Derek Jeter",
        "mail": ["derek@nyy.mlb.com"],
        "c": ["USA"],
        "eduPersonTargetedID": "foo!bar!xyz",
        "eduPersonUniqueId": "R13ET7UD68K0HGR153KE@my.org",
        "eduPersonScopedAffiliation": "member@my.org",
        "eduPersonPrincipalName": "user01@my.org",
        "norEduPersonNIN": "19800101134"
    }

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp")

    # We expect c and norEduPersonNIN to be filtered out since they are not
    # part of the custom entity category.
    assert _eq(
        list(ava.keys()),
        [
            "eduPersonTargetedID",
            "eduPersonPrincipalName",
            "eduPersonUniqueId",
            "displayName",
            "givenName",
            "eduPersonScopedAffiliation",
            "mail",
            "sn"
        ]
    )


def test_filter_ava_required_attributes_with_no_friendly_name():
    mds = MetadataStore(ATTRCONV, sec_config, disable_ssl_certificate_validation=True)
    mds.imp(
        [
            {
                "class": "saml2.mdstore.MetaDataFile",
                "metadata": [(full_path("entity_no_friendly_name_sp.xml"),)]
            }
        ]
    )

    policy_conf = {
        "default": {
            "lifetime": {"minutes": 15},
            "entity_categories": ["swamid"]
        }
    }

    policy = Policy(policy_conf, mds)

    ava = {
        "givenName": ["Derek"],
        "sn": ["Jeter"],
        "mail": ["derek@nyy.mlb.com"],
        "c": ["USA"],
        "eduPersonTargetedID": "foo!bar!xyz",
        "norEduPersonNIN": "19800101134"
    }

    # Require attribute eduPersonTargetedID but leave out friendlyName in attribute creation
    edu_person_targeted_id_oid = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.10'
    edu_person_targeted_id = to_dict(
        Attribute(name=edu_person_targeted_id_oid,
                  name_format=NAME_FORMAT_URI), onts=[mdattr])
    ava = policy.filter(ava, "https://no-friendly-name.example.edu/saml2/metadata/", required=[edu_person_targeted_id])
    assert _eq(list(ava.keys()), ["eduPersonTargetedID"])
