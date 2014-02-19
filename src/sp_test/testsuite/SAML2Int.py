#!/usr/bin/env python

__author__ = 'Riaas Mokiem'

from saml2test.check import Check
from saml2.saml import NAMEID_FORMAT_TRANSIENT

# Import the status codes used indicate the test results
from saml2test.status import *


# TODO: change this IdP metadata check to an SP metadata check and
#       add the missing tests
#
# Check that the SP Metadata conforms to the SAML2Int profile
class CheckSaml2IntMetaData(Check):
    """
    Checks that the SP  Metadata follows the Saml2Int profile
    """
    cid = "check-saml2int-metadata"
    msg = "SP Metadata error"

    def _func(self, conv):
        mds = conv.client.metadata.metadata[0]
        # Should only be one
        ed = mds.entity.values()[0]
        res = {}

        assert len(ed["spsso_descriptor"])
        spsso = ed["spsso_descriptor"][0]

        # contact person
        if "contact_person" not in spsso and "contact_person" not in ed:
            self._message = "Metadata should contain contact person "
            "information"
            self._status = WARNING
            return res
        else:
            item = {"support": False, "technical": False}
            if "contact_person" in spsso:
                for contact in spsso["contact_person"]:
                    try:
                        item[contact["contact_type"]] = True
                    except KeyError:
                        pass
            if "contact_person" in ed:
                for contact in ed["contact_person"]:
                    try:
                        item[contact["contact_type"]] = True
                    except KeyError:
                        pass

            if "support" in item and "technical" in item:
                pass
            elif "support" not in item and "technical" not in item:
                self._message = \
                    "Missing technical and support contact information"
                self._status = WARNING
            elif "technical" not in item:
                self._message = "Missing technical contact information"
                self._status = WARNING
            elif "support" not in item:
                self._message = "Missing support contact information"
                self._status = WARNING

            if self._message:
                return res

        # NameID format
        if "name_id_format" not in spsso:
            self._message = "Metadata should specify NameID format support"
            self._status = WARNING
            return res
        else:
            # should support Transient
            item = {NAMEID_FORMAT_TRANSIENT: False}
            for nformat in spsso["name_id_format"]:
                try:
                    item[nformat["text"]] = True
                except KeyError:
                    pass

            if not item[NAMEID_FORMAT_TRANSIENT]:
                self._message = "IdP should support Transient NameID Format"
                self._status = WARNING
                return res

        return res
