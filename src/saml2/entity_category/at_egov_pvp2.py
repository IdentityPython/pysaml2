__author__ = 'rainerh'  #2013-08-28
# Preliminary version, not including all attributes defined for eGov Token


PRINCIPAL = ["PVP-PRINCIPALNAME", 
             "PVP-GIVENNAME", 
]
ORG_INFO  = ["PVP-OU", 
             "PVP-OU-GV-OU-ID", 
]
OTHER = ["PVP-GID",
         "PVP-ROLES",
         "PVP-BPK",
         "PVP-USERID",
         "PVP-MAIL",
         "PVP-TEL",
]

# These give you access to information
PVP2 = "http://www.ref.gv.at/ns/names/agiz/pvp/egovtoken"
PVP2CHARGE = "http://www.ref.gv.at/ns/names/agiz/pvp/egovtoken-charge"

RELEASE = {
    PVP2: PRINCIPAL + ORG_INFO + OTHER,
}
