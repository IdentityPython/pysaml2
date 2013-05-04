__author__ = 'rolandh'


NAME = ["givenName", "surname", "initials", "displayName"]
STATIC_ORG_INFO = ["c", "o", "ou"]
OTHER = ["eduPersonPrincipalName", "eduPersonScopedAffiliation", "email"]

RESEARCH_AND_EDUCATION = "http://www.swamid.se/category/research-and-education"
SFS_1993_1153 = "http://www.swamid.se/category/sfs-1993-1153"

EU = "http://www.swamid.se/category/eu-adequate-protection"
NREN = "http://www.swamid.se/category/nren-service"
HEI = "http://www.swamid.se/category/hei-service"

RELEASE = {
    "": ["eduPersonTargetedID"],
    SFS_1993_1153: ["norEduPersonNIN"],
    RESEARCH_AND_EDUCATION: NAME + STATIC_ORG_INFO + OTHER,
}

