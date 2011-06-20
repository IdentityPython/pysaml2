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
Contains a class that can be used handle all the ECP handling for other python
programs.
"""

import cookielib
import getpass
import sys

from saml2 import soap
from saml2 import samlp
from saml2 import BINDING_PAOS

from saml2.profile import paos
from saml2.profile import ecp

from saml2.metadata import MetaData

SERVICE = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"

class Client(object):
    def __init__(self, user, passwd, sp, idp=None, metadata_file=None,
                 xmlsec_binary=None, verbose=0):
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
        self._verbose = verbose
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
        if self._verbose:
            print >> sys.stderr, "SP reponse: %s" % response

        if response is None or response is False:
            raise Exception(
                "Request to SP failed: %s" % self.http.response.status)

        # So the response should be a AuthnRequest instance in a SOAP envelope
        # body.
        # Two SOAP header blocks; paos:Request and ecp:Request
        # may also contain a ecp:RelayState SOAP header block
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

        if self._verbose:
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

        if response is None or response is False:
            raise Exception(
                "Request to IdP failed (%s): %s" % (self.http.response.status,
                                                self.http.error_description))

        if self._verbose:
            print >> sys.stderr, "IdP response: %s" % response

        # SAMLP response in a SOAP envelope body, ecp response in headers
        respdict = soap.class_instances_from_soap_enveloped_saml_thingies(
                                                                response,
                                                                [paos, ecp,
                                                                 samlp])

        if respdict is None:
            raise Exception("Unexpected reply from the IdP")

        if self._verbose:
            print >> sys.stderr, "IdP reponse dict: %s" % respdict

        idp_response = respdict["body"]
        assert idp_response.c_tag == "Response"

        if self._verbose:
            print >> sys.stderr, "IdP AUTHN response: %s" % idp_response
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

        if self._verbose:
            print >> sys.stderr, sp_response
            print

        headers = {'Content-Type' : 'application/vnd.paos+xml',}

        # POST the package to the SP
        response = self.http.post(sp_response, headers, _acs_url)

        if not response:
            if self.http.response.status == 302:
                # ignore where the SP is redirecting us to and go for the
                # url I started off with.
                response = self.http.get(headers)
                return response
            else:
                print self.http.error_description
                raise Exception(
                    "Error POSTing package to SP: %s" % self.http.response.reason)

        if self._verbose:
            print >> sys.stderr, "Final SP reponse: %s" % response

        return None

    def get(self, path=None, idp_entity_id=None):
        if path is None:
            path = self._sp

        if self.http is None:
            if idp_entity_id and not self._metadata:
                raise Exception(
                        "Can't handle IdP entity ID if I don't have metadata")

            if idp_entity_id:
                ssos = self._metadata.single_sign_on_services(idp_entity_id,
                                                            binding=BINDING_PAOS)
                try:
                    self._idp = ssos[0]
                except TypeError:
                    raise Exception(
                            "No suitable endpoint found for entity id '%s'"\
                                    % (idp_entity_id,))

            try:
                return self.init()
            except Exception,e:
                return "Error: %s" % e

        # use existing established session to request the original target
        # from the SP
        response = self.http.get(path)

        if response is None:
            raise Exception( "Error requesting target %s from SP: %s" % (
                                            path, self.http.response.reason))

        return response

