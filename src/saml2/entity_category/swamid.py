__author__ = 'rolandh'

NAME = [
    'givenName',
    'displayName',
    'sn',
    'cn',
]

STATIC_ORG_INFO = [
    'c',
    'o',
    'co',
    'norEduOrgAcronym',
    'schacHomeOrganization',
    'schacHomeOrganizationType',
]

OTHER = [
    'eduPersonPrincipalName',
    'eduPersonScopedAffiliation',
    'mail',
    'eduPersonAssurance'
]

R_AND_S = [
    'eduPersonTargetedID',
    'eduPersonPrincipalName',
    'eduPersonUniqueID',
    'mail',
    'displayName',
    'givenName',
    'sn',
    'eduPersonAssurance',
    'eduPersonScopedAffiliation'
]

GEANT_COCO = [
    'eduPersonTargetedID',
    'eduPersonPrincipalName',
    'eduPersonUniqueID',
    'eduPersonOrcid',
    'norEduPersonNIN',
    'personalIdentityNumber',
    'schacDateOfBirth',
    'mail',
    'displayName',
    'cn',
    'givenName',
    'sn',
    'eduPersonAssurance',
    'eduPersonScopedAffiliation',
    'eduPersonAffiliation',
    'o',
    'norEduOrgAcronym',
    'c',
    'co',
    'schacHomeOrganization',
    'schacHomeOrganizationType',
]

# These give you access to information
RESEARCH_AND_EDUCATION = 'http://www.swamid.se/category/research-and-education'  # Deprecated from 2021-03-31
SFS_1993_1153 = 'http://www.swamid.se/category/sfs-1993-1153'                    # Deprecated from 2021-03-31
RESEARCH_AND_SCHOLARSHIP = 'http://refeds.org/category/research-and-scholarship'
COCO = 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1'

# presently these don't by themself
EU = 'http://www.swamid.se/category/eu-adequate-protection'  # Deprecated from 2021-03-31
NREN = 'http://www.swamid.se/category/nren-service'          # Deprecated from 2021-03-31
HEI = 'http://www.swamid.se/category/hei-service'            # Deprecated from 2021-03-31

RELEASE = {
    '': ['eduPersonTargetedID'],
    SFS_1993_1153: ['norEduPersonNIN', 'eduPersonAssurance'],
    (RESEARCH_AND_EDUCATION, EU): NAME + STATIC_ORG_INFO + OTHER,
    (RESEARCH_AND_EDUCATION, NREN): NAME + STATIC_ORG_INFO + OTHER,
    (RESEARCH_AND_EDUCATION, HEI): NAME + STATIC_ORG_INFO + OTHER,
    RESEARCH_AND_SCHOLARSHIP: R_AND_S,
    COCO: GEANT_COCO,
}

ONLY_REQUIRED = {COCO: True}
