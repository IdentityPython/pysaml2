#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2011 Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Contains classes used in the SAML ECP profile
"""

from saml2 import element_to_extension_element
from saml2 import samlp
from saml2 import saml

from saml2.profile import paos
from saml2.profile import ecp

from saml2.client import Saml2Client
from saml2.server import Server

from saml2.schema import soapenv
from saml2.s_utils import sid

SERVICE = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"

def ecp_capable(headers):
    if "application/vnd.paos+xml" in headers["Accept"]:
        if "PAOS" in headers:
            if 'ver="%s";"%s"' % (paos.NAMESPACE,
                                  SERVICE) in headers["PAOS"]:
                return True

    return False

ACTOR = "http://schemas.xmlsoap.org/soap/actor/next"

class ECPClient(Saml2Client):
    """ This is the SP side of the ECP communication

    TODO: Still tentative
    """
    def __init__(self, config=None, debug=0,identity_cache=None,
                 state_cache=None, virtual_organization=None,
                 config_file="", logger=None):
        Saml2Client.__init__(self, config, debug,identity_cache, state_cache,
                                virtual_organization, config_file, logger)

    def ecp_auth_request(self, entityid=None, relay_state="",
                         log=None, sign=False):
        """ Makes an authentication request.

        :param entityid: The entity ID of the IdP to send the request to
        :param relay_state: To where the user should be returned after
            successfull log in.
        :param log: Where to write log messages
        :param sign: Whether the request should be signed or not.
        :return: AuthnRequest response
        """

        eelist = []

        # ----------------------------------------
        # <paos:Request>
        # ----------------------------------------
        my_url = self._my_name()

        # must_understan and actor according to the standard
        #
        paos_request = paos.Request(must_understand="1", actor=ACTOR,
                                    response_consumer_url=my_url,
                                    service = SERVICE)

        eelist.append(element_to_extension_element(paos_request))

        # ----------------------------------------
        # <ecp:Request>
        # ----------------------------------------

#        idp = samlp.IDPEntry(
#            provider_id = "https://idp.example.org/entity",
#            name = "Example identity provider",
#            loc = "https://idp.example.org/saml2/sso",
#            )
#
#        idp_list = samlp.IDPList(idp_entry= [idp])
#
#        ecp_request = ecp.Request(actor = ACTOR, must_understand = "1",
#                        provider_name = "Example Service Provider",
#                        issuer=saml.Issuer(text="https://sp.example.org/entity"),
#                        idp_list = idp_list)
#
#        eelist.append(element_to_extension_element(ecp_request))

        # ----------------------------------------
        # <ecp:RelayState>
        # ----------------------------------------

        relay_state = ecp.RelayState(actor=ACTOR, must_understand="1",
                                     text=relay_state)

        eelist.append(element_to_extension_element(relay_state))

        header = soapenv.Header()
        header.extension_elements = eelist

        # ----------------------------------------
        # <samlp:AuthnRequest>
        # ----------------------------------------

        location = self._sso_location(entityid)
        session_id = sid()
        authn_req = self.authn(location, session_id, log=log)

        body = soapenv.Body()
        body.extension_elements = [element_to_extension_element(authn_req)]

        # ----------------------------------------
        # The SOAP envelope
        # ----------------------------------------

        soap_envelope = soapenv.Envelope(header=header, body=body)

        return session_id, "%s" % soap_envelope

#    def handle_ecp_response(self):
#        pass
#
#    def ecp_relaystate(self, state=""):
#        relay_state = ecp.RelayState(text=state)

class ECPServer(Server):
    """ This deals with what the IdP has to do

    TODO: Still tentative
    """
    def __init__(self, config_file="", config=None, _cache="",
                    log=None, debug=0):
        Server.__init__(self, config_file, config, _cache, log, debug)

    def parse_ecp_authn_query(self):
        
    def ecp_response(self):

        # ----------------------------------------
        # <ecp:Response
        # ----------------------------------------
        target_url = ""
        
        ecp_response = ecp.Response(assertion_consumer_service_url=target_url)
        header = soapenv.Body()
        header.extension_elements = [element_to_extension_element(ecp_response)]

        # ----------------------------------------
        # <samlp:Response
        # ----------------------------------------

        response = samlp.Response()
        body = soapenv.Body()
        body.extension_elements = [element_to_extension_element(response)]

        soap_envelope = soapenv.Envelope(header=header, body=body)

        return "%s" % soap_envelope
