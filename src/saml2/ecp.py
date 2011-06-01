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

import cookielib
import getpass
import sys

from saml2 import soap
from saml2 import element_to_extension_element
from saml2 import samlp
from saml2 import saml

from saml2.profile import paos
from saml2.profile import ecp

from saml2.client import Saml2Client
from saml2.server import Server
from saml2.metadata import MetaData

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

class ECP(object):
    def __init__(self, user, passwd, sp, idp=None, metadata_file=None,
                 xmlsec_binary=None, debug=0):
        self._idp = idp
        self._sp = sp
        self._user = user
        self._passwd = passwd
        if metadata_file:
            self._metadata = MetaData()
            self._metadata.import_metadata(open(metadata_file).read(),
                                            xmlsec_binary)
        else:
            self._metadata = None
        self._debug = debug
        self.cookie_jar = None
        self.cookie_handler = None
        self.http = None
        
    def init(self):
        """ Handles the initial connection to the SP """
        self.cookie_jar = cookielib.LWPCookieJar()
        self.http = soap.HTTPClient(self._sp, cookiejar=self.cookie_jar)

        # ********************************************
        # Phase 1 - First conversation with the SP
        # ********************************************
        # headers needed to indicate to the SP an ECP request
        headers = {
                    'Accept' : 'text/html; application/vnd.paos+xml',
                    'PAOS'   : 'ver="%s";"%s"' % (paos.NAMESPACE, SERVICE)
                    }

        # request target from SP
        response = self.http.get(headers=headers)
        if self._debug:
            print >> sys.stderr, "SP reponse: %s" % response

        if response is None:
            raise Exception(
                "Request to SP failed: %s" % self.http.response.status)

        # So the response should be a AuthnRequest instance in a SOAP envelope
        # body.
        # Two SOAP header blocks too; paos:Request and ecp:Request
        # may contain a ecp:RelayState SOAP header block
        # If channel-binding was part of the PAOS header any number of
        # <cb:ChannelBindings> header blocks may also be present
        # if 'holder-of-key' option then one or more <ecp:SubjectConfirmation>
        # header blocks may also be present
        respdict = soap.class_instances_from_soap_enveloped_saml_thingies(
                                                                    response,
                                                                    [paos, ecp,
                                                                     samlp])
        if respdict is None:
            raise Exception("Unexpected reply from the SP")

        if self._debug:
            print >> sys.stderr, "SP reponse dict: %s" % respdict

        # AuthnRequest in the body or not
        authn_request = respdict["body"]
        assert authn_request.c_tag == "AuthnRequest"

        # ecp.RelayState among headers
        _relay_state = None
        _paos_request = None
        for item in respdict["header"]:
            if item.c_tag == "RelayState" and \
               item.c_namespace == ecp.NAMESPACE:
                _relay_state = item
            if item.c_tag == "Request" and \
               item.c_namespace == paos.NAMESPACE:
                _paos_request = item

        _rc_url = _paos_request.response_consumer_url

        # **********************
        # Phase 2 - talk to the IdP
        # **********************
        idp_request = soap.make_soap_enveloped_saml_thingy(authn_request)
        idp_endpoint = self._idp
        
        # prompt the user for a password 
        if not self._passwd:
            self._passwd = getpass.getpass(
                                "Enter password for login '%s': " % self._user)

        self.http.add_credentials(self._user, self._passwd)

        # POST the request to the IdP
        response = self.http.post(idp_request, path=idp_endpoint)

        if response is None:
            raise Exception(
                "Request to IdP failed: %s" % self.http.response.reason)

        if self._debug:
            print >> sys.stderr, "IdP response: %s" % response

        # SAMLP response in a SOAP envelope body, ecp response in headers
        respdict = soap.class_instances_from_soap_enveloped_saml_thingies(
                                                                response,
                                                                [paos, ecp,
                                                                 samlp])

        if respdict is None:
            raise Exception("Unexpected reply from the IdP")

        if self._debug:
            print >> sys.stderr, "IdP reponse dict: %s" % respdict

        idp_response = respdict["body"]
        assert idp_response.c_tag == "Response"

        if self._debug:
            print >> sys.stderr, "IdP AUTHN response: %s" % idp_response

        print idp_response
        print 
        _ecp_response = None
        for item in respdict["header"]:
            if item.c_tag == "Response" and \
               item.c_namespace == ecp.NAMESPACE:
                _ecp_response = item

        _acs_url = _ecp_response.assertion_consumer_service_url
        if _rc_url != _acs_url:
            error = ("response_consumer_url '%s' does not match" % _rc_url,
                     "assertion_consumer_service_url '%s" % _acs_url)
            # Send an error message to the SP
            fault_text = soap.soap_fault(error)
            _ = self.http.post(fault_text, path=_rc_url)
            # Raise an exception so the user knows something went wrong
            raise Exception(error)

        # **********************************
        # Phase 3 - back to the SP
        # **********************************
        sp_response = soap.make_soap_enveloped_saml_thingy(idp_response,
                                                           [_relay_state])

        print sp_response
        
        headers = {'Content-Type' : 'application/vnd.paos+xml',}

        # POST the package to the SP
        response = self.http.post(sp_response, headers, _acs_url)

        if not response:
            print self.http.error_description
            raise Exception(
                "Error POSTing package to SP: %s" % self.http.response.reason)

        if self._debug:
            print >> sys.stderr, "Final SP reponse: %s" % response

        return None

    def get(self, path=None):
        if path is None:
            path = self._sp
            
        if self.http is None:
            try:
                return self.init()
            except Exception,e:
                return "%s" % e

        # use existing established session to request the original target
        # from the SP
        response = self.http.get(path)

        if response is None:
            raise Exception( "Error requesting target %s from SP: %s" % (
                                            path, self.http.response.reason))

        return response


ACTOR = "http://schemas.xmlsoap.org/soap/actor/next"

class ECPClient(Saml2Client):
    """ This is the SP side of the communication

    TODO: Still tentative
    """
    def __init__(self, config=None, debug=0,identity_cache=None,
                 state_cache=None, virtual_organization=None,
                 config_file="", logger=None):
        Saml2Client.__init__(self, config, debug,identity_cache, state_cache,
                                virtual_organization, config_file, logger)

    def ecp_auth_request(self, entityid=None, relay_state="",
                         log=None, scoping=None, sign=False):
        """ Makes an authentication request.

        :param entityid: The entity ID of the IdP to send the request to
        :param relay_state: To where the user should be returned after
            successfull log in.
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param scoping: For which IdPs this query are aimed.
        :param sign: Whether the request should be signed or not.
        :return: AuthnRequest response
        """

        eelist = []

        # ----------------------------------------
        # <paos:Request>
        # ----------------------------------------
        my_url = ""

        # must_understan and actor according to the standard
        #
        paos_request = paos.Request(must_understand="1", actor=ACTOR,
                                    response_consumer_url=my_url,
                                    service = SERVICE)

        eelist.append(element_to_extension_element(paos_request))

        # ----------------------------------------
        # <ecp:Request>
        # ----------------------------------------

        idp = samlp.IDPEntry(
            provider_id = "https://idp.example.org/entity",
            name = "Example identity provider",
            loc = "https://idp.example.org/saml2/sso",
            )

        idp_list = samlp.IDPList(idp_entry= [idp])

        ecp_request = ecp.Request(actor = ACTOR, must_understand = "1",
                        provider_name = "Example Service Provider",
                        issuer=saml.Issuer(text="https://sp.example.org/entity"),
                        idp_list = idp_list)

        eelist.append(element_to_extension_element(ecp_request))

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
