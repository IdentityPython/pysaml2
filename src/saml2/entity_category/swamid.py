__author__ = "rolandh"

NAME = [
    "givenName",
    "displayName",
    "sn",
    "cn",
]

STATIC_ORG_INFO = [
    "c",
    "o",
    "co",
    "norEduOrgAcronym",
    "schacHomeOrganization",
    "schacHomeOrganizationType",
]

OTHER = ["eduPersonPrincipalName", "eduPersonScopedAffiliation", "mail", "eduPersonAssurance"]

R_AND_S = [
    "eduPersonPrincipalName",
    "eduPersonUniqueID",
    "mail",
    "displayName",
    "givenName",
    "sn",
    "eduPersonAssurance",
    "eduPersonScopedAffiliation",
]

GEANT_COCO = [
    "pairwise-id",
    "subject-id",
    "eduPersonTargetedID",
    "eduPersonPrincipalName",
    "eduPersonOrcid",
    "norEduPersonNIN",
    "personalIdentityNumber",
    "schacDateOfBirth",
    "mail",
    "mailLocalAddress",
    "displayName",
    "cn",
    "givenName",
    "sn",
    "eduPersonAssurance",
    "eduPersonScopedAffiliation",
    "eduPersonAffiliation",
    "o",
    "norEduOrgAcronym",
    "c",
    "co",
    "schacHomeOrganization",
    "schacHomeOrganizationType",
]

REFEDS_COCO = GEANT_COCO  # for now these two are identical

MYACADEMICID_ESI = ["schacPersonalUniqueCode"]

REFEDS_PERSONALIZED_ACCESS = [
    "subject-id",
    "mail",
    "displayName",
    "givenName",
    "sn",
    "eduPersonScopedAffiliation",
    "eduPersonAssurance",
    "schacHomeOrganization",
]

REFEDS_PSEUDONYMOUS_ACCESS = [
    "pairwise-id",
    "eduPersonScopedAffiliation",
    "eduPersonAssurance",
    "schacHomeOrganization",
]

REFEDS_ANONYMOUS_ACCESS = [
    "eduPersonScopedAffiliation",
    "schacHomeOrganization",
]


# These give you access to information
RESEARCH_AND_EDUCATION = "http://www.swamid.se/category/research-and-education"  # Deprecated from 2021-03-31
SFS_1993_1153 = "http://www.swamid.se/category/sfs-1993-1153"  # Deprecated from 2021-03-31
RESEARCH_AND_SCHOLARSHIP = "http://refeds.org/category/research-and-scholarship"
COCOv1 = "http://www.geant.net/uri/dataprotection-code-of-conduct/v1"
COCOv2 = "https://refeds.org/category/code-of-conduct/v2"
ESI = "https://myacademicid.org/entity-categories/esi"
PERSONALIZED = "https://refeds.org/category/personalized"
PSEUDONYMOUS = "https://refeds.org/category/pseudonymous"
ANONYMOUS = "https://refeds.org/category/anonymous"

# presently these don't by themselves
EU = "http://www.swamid.se/category/eu-adequate-protection"  # Deprecated from 2021-03-31
NREN = "http://www.swamid.se/category/nren-service"  # Deprecated from 2021-03-31
HEI = "http://www.swamid.se/category/hei-service"  # Deprecated from 2021-03-31

RELEASE = {
    "": [],
    SFS_1993_1153: ["norEduPersonNIN", "eduPersonAssurance"],
    (RESEARCH_AND_EDUCATION, EU): NAME + STATIC_ORG_INFO + OTHER,
    (RESEARCH_AND_EDUCATION, NREN): NAME + STATIC_ORG_INFO + OTHER,
    (RESEARCH_AND_EDUCATION, HEI): NAME + STATIC_ORG_INFO + OTHER,
    RESEARCH_AND_SCHOLARSHIP: R_AND_S,
    COCOv1: GEANT_COCO,
    COCOv2: REFEDS_COCO,
    ESI: MYACADEMICID_ESI,
    (ESI, COCOv1): MYACADEMICID_ESI + GEANT_COCO,
    (ESI, COCOv2): MYACADEMICID_ESI + REFEDS_COCO,
}

ONLY_REQUIRED = {
    COCOv1: True,
    COCOv2: True,
    (ESI, COCOv1): True,
    (ESI, COCOv2): True,
}

# These restrictions are parsed (and validated) into a list of saml2.assertion.EntityCategoryRule instances.
RESTRICTIONS = [
    {
        "match": {
            "required": [PERSONALIZED],
            "conflicts": [PSEUDONYMOUS, ANONYMOUS],
        },
        "attributes": REFEDS_PERSONALIZED_ACCESS,
    },
    {
        "match": {
            "required": [PSEUDONYMOUS],
            "conflicts": [ANONYMOUS],
        },
        "attributes": REFEDS_PSEUDONYMOUS_ACCESS,
    },
    {
        "match": {
            "required": [ANONYMOUS],
        },
        "attributes": REFEDS_ANONYMOUS_ACCESS,
    },
    # Example of conversion of some of the rules in RELEASE to this new format:
    #
    # {
    #     "match": {
    #         "required": [COCOv1],
    #     },
    #     "attributes": GEANT_COCO,
    #     "only_required": True,
    # },
    # {
    #     "match": {
    #         "required": [ESI, COCOv1],
    #     },
    #     "attributes": MYACADEMICID_ESI + GEANT_COCO,
    #     "only_required": True,
    # },
]
