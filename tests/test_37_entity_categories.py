from contextlib import closing
from saml2 import sigver
from saml2 import config
from saml2.assertion import Policy
from saml2.attribute_converter import ac_factory
from pathutils import full_path
from saml2.mdstore import MetadataStore
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
    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    })

    ava = {"givenName": ["Derek"], "sn": ["Jeter"],
           "mail": ["derek@nyy.mlb.com", "dj@example.com"], "c": ["USA"]}

    ava = policy.filter(ava, "https://connect.sunet.se/shibboleth", MDS)

    assert _eq(list(ava.keys()), ['mail', 'givenName', 'sn', 'c'])
    assert _eq(ava["mail"], ["derek@nyy.mlb.com", "dj@example.com"])


def test_filter_ava2():
    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["refeds", "edugain"]
        }
    })

    ava = {"givenName": ["Derek"], "sn": ["Jeter"],
           "mail": ["derek@nyy.mlb.com"], "c": ["USA"],
           "eduPersonTargetedID": "foo!bar!xyz"}

    ava = policy.filter(ava, "https://connect.sunet.se/shibboleth", MDS)

    # Mismatch, policy deals with eduGAIN, metadata says SWAMID
    # So only minimum should come out
    assert _eq(list(ava.keys()), ['eduPersonTargetedID'])


def test_filter_ava3():
    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    })

    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True)
    mds.imp([{"class": "saml2.mdstore.MetaDataFile",
              "metadata": [(full_path("entity_cat_sfs_hei.xml"),)]}])

    ava = {"givenName": ["Derek"], "sn": ["Jeter"],
           "mail": ["derek@nyy.mlb.com"], "c": ["USA"],
           "eduPersonTargetedID": "foo!bar!xyz",
           "norEduPersonNIN": "19800101134"}

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp", mds)

    assert _eq(list(ava.keys()), ['eduPersonTargetedID', "norEduPersonNIN"])


def test_filter_ava4():
    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    })

    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True)
    mds.imp([{"class": "saml2.mdstore.MetaDataFile",
              "metadata": [(full_path("entity_cat_re_nren.xml"),)]}])

    ava = {"givenName": ["Derek"], "sn": ["Jeter"],
           "mail": ["derek@nyy.mlb.com"], "c": ["USA"],
           "eduPersonTargetedID": "foo!bar!xyz",
           "norEduPersonNIN": "19800101134"}

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp", mds)

    assert _eq(list(ava.keys()),
               ['eduPersonTargetedID', "givenName", "c", "mail",
                "sn"])


def test_filter_ava5():
    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            # "attribute_restrictions": None  # means all I have
            "entity_categories": ["swamid"]
        }
    })

    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True)
    mds.imp([{"class": "saml2.mdstore.MetaDataFile",
              "metadata": [(full_path("entity_cat_re.xml"),)]}])

    ava = {"givenName": ["Derek"], "sn": ["Jeter"],
           "mail": ["derek@nyy.mlb.com"], "c": ["USA"],
           "eduPersonTargetedID": "foo!bar!xyz",
           "norEduPersonNIN": "19800101134"}

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp", mds)

    assert _eq(list(ava.keys()), ['eduPersonTargetedID'])


def test_idp_policy_filter():
    with closing(Server("idp_conf_ec")) as idp:
        ava = {"givenName": ["Derek"], "sn": ["Jeter"],
               "mail": ["derek@nyy.mlb.com"], "c": ["USA"],
               "eduPersonTargetedID": "foo!bar!xyz",
               "norEduPersonNIN": "19800101134"}

        policy = idp.config.getattr("policy", "idp")
        ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp",
                            idp.metadata)

        print(ava)
        assert list(ava.keys()) == [
            "eduPersonTargetedID"]  # because no entity category


def test_entity_category_import_from_path():
    # The entity category module myentitycategory.py is in the tests
    # directory which is on the standard module search path.
    # The module uses a custom interpretation of the REFEDs R&S entity category
    # by adding eduPersonUniqueId.
    policy = Policy({
        "default": {
            "lifetime": {"minutes": 15},
            "entity_categories": ["myentitycategory"]
        }
    })

    mds = MetadataStore(ATTRCONV, sec_config,
                        disable_ssl_certificate_validation=True)

    # The file entity_cat_rs.xml contains the SAML metadata for an SP
    # tagged with the REFEDs R&S entity category.
    mds.imp([{"class": "saml2.mdstore.MetaDataFile",
              "metadata": [(full_path("entity_cat_rs.xml"),)]}])

    ava = {"givenName": ["Derek"], "sn": ["Jeter"],
           "displayName": "Derek Jeter",
           "mail": ["derek@nyy.mlb.com"], "c": ["USA"],
           "eduPersonTargetedID": "foo!bar!xyz",
           "eduPersonUniqueId": "R13ET7UD68K0HGR153KE@my.org",
           "eduPersonScopedAffiliation": "member@my.org",
           "eduPersonPrincipalName": "user01@my.org",
           "norEduPersonNIN": "19800101134"}

    ava = policy.filter(ava, "urn:mace:example.com:saml:roland:sp", mds)

    # We expect c and norEduPersonNIN to be filtered out since they are not
    # part of the custom entity category.
    assert _eq(list(ava.keys()),
               ["eduPersonTargetedID", "eduPersonPrincipalName",
                "eduPersonUniqueId", "displayName", "givenName",
                "eduPersonScopedAffiliation", "mail", "sn"])


if __name__ == "__main__":
    test_filter_ava3()
