from urllib import urlencode
from urlparse import urlparse, parse_qs
from saml2.entity import Entity
from saml2.response import VerificationError

__author__ = 'rolandh'

IDPDISC_POLICY = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single"

class DiscoveryServer(Entity):
    def __init__(self, config=None, config_file=""):
        Entity.__init__(self, "disco", config, config_file)

    def parse_discovery_service_request(self, url="", query=""):
        if url:
            part = urlparse(url)
            dsr = parse_qs(part[4])
        elif query:
            dsr = parse_qs(query)
        else:
            dsr = {}

        # verify

        try:
            assert dsr["isPassive"] in ["true", "false"]
        except KeyError:
            pass

        if "return" in dsr:
            part = urlparse(dsr["return"])
            if part.query:
                qp = parse_qs(part.query)
                if "returnIDParam" in dsr:
                    assert dsr["returnIDParam"] not in qp.keys()
                else:
                    assert "entityID" not in qp.keys()
        else:
            # If metadata not used this is mandatory
            raise VerificationError("Missing mandatory parameter 'return'")

        if "policy" not in dsr:
            dsr["policy"] = IDPDISC_POLICY

        if "isPassive" in dsr and dsr["isPassive"] == "true":
            dsr["isPassive"] = True
        else:
            dsr["isPassive"] = False

        return dsr

    # -------------------------------------------------------------------------

    def create_discovery_service_response(self, url, IDparam="entityID",
                                          entity_id=None):
        if entity_id:
            qp = urlencode({IDparam:entity_id})

            part = urlparse(url)
            if part.query:
                # Iff there is a query part add the new info at the end
                url = "%s&%s" % (url, qp)
            else:
                url = "%s?%s" % (url, qp)

        return url

    def verify_sp_in_metadata(self, entity_id):
        if self.metadata:
            endp = self.metadata.discovery_response(entity_id)
            if endp:
                return True

        return False
