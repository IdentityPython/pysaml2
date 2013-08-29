__author__ = 'rolandh'


NAME = ["givenName", "displayName", "sn"]
STATIC_ORG_INFO = ["c", "o", "co"]
OTHER = ["eduPersonPrincipalName", "eduPersonScopedAffiliation", "mail"]

# These give you access to information
RESEARCH_AND_EDUCATION = "http://www.swamid.se/category/research-and-education"
SFS_1993_1153 = "http://www.swamid.se/category/sfs-1993-1153"

# presently these don't
EU = "http://www.swamid.se/category/eu-adequate-protection"
NREN = "http://www.swamid.se/category/nren-service"
HEI = "http://www.swamid.se/category/hei-service"

RELEASE = {
    "": ["eduPersonTargetedID"],
    SFS_1993_1153: ["norEduPersonNIN"],
    RESEARCH_AND_EDUCATION: NAME + STATIC_ORG_INFO + OTHER,
}