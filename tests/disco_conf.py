from saml2.extension.idpdisc import BINDING_DISCO

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

BASE = "http://localhost:8088"

CONFIG = {
    "entityid" : "%s/disco.xml" % BASE,
    "name" : "Rolands Discoserver",
    "service": {
        "ds": {
            "endpoints" : {
                "disco_service": [
                    ("%s/disco" % BASE, BINDING_DISCO),
                ]
            },
        },
    },
    "debug" : 1,
    "xmlsec_binary" : xmlsec_path,
    "metadata": {
        "local": ["servera.xml"],
    },
}
