#!/usr/bin/env python
from saml2.virtual_org import VirtualOrg

__author__ = 'rolandh'

import sys
import os
import re
import logging
import logging.handlers

from importlib import import_module

from saml2 import BINDING_SOAP, BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2 import metadata
from saml2 import root_logger

from saml2.attribute_converter import ac_factory
from saml2.assertion import Policy
from saml2.sigver import get_xmlsec_binary

logger = logging.getLogger(__name__)

COMMON_ARGS = ["entityid", "xmlsec_binary", "debug", "key_file", "cert_file",
                "secret", "accepted_time_diff", "name", "ca_certs",
                "description", "valid_for",
                "organization",
                "contact_person",
                "name_form",
                "virtual_organization",
                "logger",
                "only_use_keys_in_metadata",
                "logout_requests_signed",
                "disable_ssl_certificate_validation"
                ]

SP_ARGS = [
            "required_attributes",
            "optional_attributes",
            "idp",
            "aa",
            "subject_data",
            "want_assertions_signed",
            "authn_requests_signed",
            "name_form",
            "endpoints",
            "ui_info",
            "discovery_response",
            "allow_unsolicited",
            "ecp"
            ]

AA_IDP_ARGS = ["want_authn_requests_signed",
               "provided_attributes",
               "subject_data",
               "sp",
               "scope",
               "endpoints",
               "metadata",
               "ui_info"]

PDP_ARGS = ["endpoints", "name_form"]

COMPLEX_ARGS = ["attribute_converters", "metadata", "policy"]
ALL = COMMON_ARGS + SP_ARGS + AA_IDP_ARGS + PDP_ARGS + COMPLEX_ARGS


SPEC = {
    "": COMMON_ARGS + COMPLEX_ARGS,
    "sp": COMMON_ARGS + COMPLEX_ARGS + SP_ARGS,
    "idp": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
    "aa": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
    "pdp": COMMON_ARGS + COMPLEX_ARGS + PDP_ARGS,
}

# --------------- Logging stuff ---------------

LOG_LEVEL = {'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL}

LOG_HANDLER = {
    "rotating": logging.handlers.RotatingFileHandler,
    "syslog": logging.handlers.SysLogHandler,
    "timerotate": logging.handlers.TimedRotatingFileHandler,
}

LOG_FORMAT = "%(asctime)s %(name)s:%(levelname)s %(message)s"

class ConfigurationError(Exception):
    pass

# -----------------------------------------------------------------

class Config(object):
    def_context = ""

    def __init__(self):
        self.entityid = None
        self.xmlsec_binary= None
        self.debug=False
        self.key_file=None
        self.cert_file=None
        self.secret=None
        self.accepted_time_diff=None
        self.name=None
        self.ca_certs=None
        self.description=None
        self.valid_for=None
        self.organization=None
        self.contact_person=None
        self.name_form=None
        self.virtual_organization=None
        self.logger=None
        self.only_use_keys_in_metadata=True
        self.logout_requests_signed=None
        self.disable_ssl_certificate_validation=None
        self.context = ""
        self.attribute_converters=None
        self.metadata=None
        self.policy=None
        self.serves = []
        self.vorg = {}

    def setattr(self, context, attr, val):
        if context == "":
            setattr(self, attr, val)
        else:
            setattr(self, "_%s_%s" % (context,attr), val)

    def getattr(self, attr, context=None):
        if context is None:
            context = self.context

        if context == "":
            return getattr(self, attr, None)
        else:
            return getattr(self, "_%s_%s" % (context,attr), None)

    def load_special(self, cnf, typ, metadata_construction=False):
        for arg in SPEC[typ]:
            try:
                self.setattr(typ, arg, cnf[arg])
            except KeyError:
                pass

        self.context = typ
        self.load_complex(cnf, typ, metadata_construction=metadata_construction)
        self.context = self.def_context

    def load_complex(self, cnf, typ="", metadata_construction=False):
        try:
            self.setattr(typ, "policy", Policy(cnf["policy"]))
        except KeyError:
            pass

        try:
            try:
                acs = ac_factory(cnf["attribute_map_dir"])
            except KeyError:
                acs = ac_factory()

            if not acs:
                raise Exception(("No attribute converters, ",
                                    "something is wrong!!"))

            _acs = self.getattr("attribute_converters", typ)
            if _acs:
                _acs.extend(acs)
            else:
                self.setattr(typ, "attribute_converters", acs)

        except KeyError:
            pass

        if not metadata_construction:
            try:
                self.setattr(typ, "metadata",
                             self.load_metadata(cnf["metadata"]))
            except KeyError:
                pass

    def load(self, cnf, metadata_construction=False):
        """ The base load method, loads the configuration

        :param cnf: The configuration as a dictionary
        :param metadata_construction: Is this only to be able to construct
            metadata. If so some things can be left out.
        :return: The Configuration instance
        """
        for arg in COMMON_ARGS:
            if arg == "virtual_organization":
                if "virtual_organization" in cnf:
                    for key,val in cnf["virtual_organization"].items():
                        self.vorg[key] = VirtualOrg(None, key, val)
                continue


            try:
                setattr(self, arg, cnf[arg])
            except KeyError:
                pass

        if "service" in cnf:
            for typ in ["aa", "idp", "sp", "pdp"]:
                try:
                    self.load_special(cnf["service"][typ], typ,
                                    metadata_construction=metadata_construction)
                    self.serves.append(typ)
                except KeyError:
                    pass

        if not metadata_construction:
            if not self.xmlsec_binary:
                self.xmlsec_binary = get_xmlsec_binary()

            # verify that xmlsec is where it's supposed to be
            if not os.path.exists(self.xmlsec_binary):
                #if not os.access(, os.F_OK):
                raise Exception("xmlsec binary not in '%s' !" % (
                                                            self.xmlsec_binary))

        self.load_complex(cnf, metadata_construction=metadata_construction)
        self.context = self.def_context

        return self

    def load_file(self, config_file, metadata_construction=False):
        if sys.path[0] != ".":
            sys.path.insert(0, ".")

        if config_file.endswith(".py"):
            config_file = config_file[:-3]

        mod = import_module(config_file)
        #return self.load(eval(open(config_file).read()))
        return self.load(mod.CONFIG, metadata_construction)

    def load_metadata(self, metadata_conf):
        """ Loads metadata into an internal structure """

        xmlsec_binary = self.xmlsec_binary
        acs = self.attribute_converters

        if xmlsec_binary is None:
            raise Exception("Missing xmlsec1 specification")
        if acs is None:
            raise Exception("Missing attribute converter specification")

        try:
            ca_certs = self.ca_certs
        except:
            ca_certs = None
        try:
            disable_ssl_certificate_validation = self.disable_ssl_certificate_validation
        except:
            disable_ssl_certificate_validation = False

        metad = metadata.MetaData(xmlsec_binary, acs, ca_certs,
                                  disable_ssl_certificate_validation)
        if "local" in metadata_conf:
            for mdfile in metadata_conf["local"]:
                metad.import_metadata(open(mdfile).read(), mdfile)
        if "inline" in metadata_conf:
            index = 1
            for md in metadata_conf["inline"]:
                metad.import_metadata(md, "inline_xml.%d" % index)
                index += 1
        if "remote" in metadata_conf:
            for spec in metadata_conf["remote"]:
                try:
                    cert = spec["cert"]
                except KeyError:
                    cert = None
                metad.import_external_metadata(spec["url"], cert)
        return metad

    def endpoint(self, service, binding=None, context=None):
        """ Goes through the list of endpoint specifications for the
        given type of service and returnes the first endpoint that matches
        the given binding. If no binding is given any endpoint for that
        service will be returned.

        :param service: The service the endpoint should support
        :param binding: The expected binding
        :return: All the endpoints that matches the given restrictions
        """
        spec = []
        unspec = []
        endps = self.getattr("endpoints")
        if endps and service in endps:
            for endpspec in endps[service]:
                try:
                    endp, bind = endpspec
                    if binding is None or bind == binding:
                        spec.append(endp)
                except ValueError:
                    unspec.append(endpspec)

        if spec:
            return spec
        else:
            return unspec

    def log_handler(self):
        try:
            _logconf = self.logger
        except KeyError:
            return None

        handler = None
        for htyp in LOG_HANDLER:
            if htyp in _logconf:
                if htyp == "syslog":
                    args = _logconf[htyp]
                    if "socktype" in args:
                        import socket
                        if args["socktype"] == "dgram":
                            args["socktype"] = socket.SOCK_DGRAM
                        elif args["socktype"] == "stream":
                            args["socktype"] = socket.SOCK_STREAM
                        else:
                            raise Exception("Unknown socktype!")
                    try:
                        handler = LOG_HANDLER[htyp](**args)
                    except TypeError: # difference between 2.6 and 2.7
                        del args["socktype"]
                        handler = LOG_HANDLER[htyp](**args)
                else:
                    handler = LOG_HANDLER[htyp](**_logconf[htyp])
                break

        if handler is None:
            # default if rotating logger
            handler = LOG_HANDLER["rotating"]()

        if "format" in _logconf:
            formatter = logging.Formatter(_logconf["format"])
        else:
            formatter = logging.Formatter(LOG_FORMAT)

        handler.setFormatter(formatter)
        return handler
    
    def setup_logger(self):
        if root_logger.level != logging.NOTSET: # Someone got there before me
            return root_logger

        _logconf = self.logger
        if _logconf is None:
            return root_logger

        try:
            root_logger.setLevel(LOG_LEVEL[_logconf["loglevel"].lower()])
        except KeyError: # reasonable default
            root_logger.setLevel(logging.INFO)

        root_logger.addHandler(self.log_handler())
        root_logger.info("Logging started")
        return root_logger

class SPConfig(Config):
    def_context = "sp"

    def __init__(self):
        Config.__init__(self)

    def single_logout_services(self, entity_id, binding=BINDING_SOAP):
        """ returns a list of endpoints to use for sending logout requests to

        :param entity_id: The entity ID of the service
        :param binding: The preferred binding (which for logout by default is
            the SOAP binding)
        :return: list of endpoints
        """
        return self.metadata.single_logout_service(entity_id, binding=binding)

    def single_sign_on_services(self, entity_id,
                                binding=BINDING_HTTP_REDIRECT):
        """ returns a list of endpoints to use for sending login requests to

        :param entity_id: The entity ID of the service
        :param binding: The preferred binding 
        :return: list of endpoints
        """
        return self.metadata.single_sign_on_service(entity_id, binding=binding)

    def attribute_services(self, entity_id, binding=BINDING_SOAP):
        """ returns a list of endpoints to use for attribute requests to

        :param entity_id: The entity ID of the service
        :param binding: The preferred binding (which for logout by default is
            the SOAP binding)
        :return: list of endpoints
        """

        res = []
        aa_eid = self.getattr("entity_id")
        if aa_eid:
            if entity_id in aa_eid:
                for aad in self.metadata.attribute_authority(entity_id):
                    for attrserv in aad.attribute_service:
                        if attrserv.binding == binding:
                            res.append(attrserv)
        else:
            return self.metadata.attribute_authority()

        return res

    def idps(self, langpref=None):
        """ Returns a dictionary of useful IdPs, the keys being the
        entity ID of the service and the names of the services as values

        :param langpref: The preferred languages of the name, the first match
            is used.
        :return: Dictionary
        """
        if langpref is None:
            langpref = ["en"]

        eidp = self.getattr("entity_id")
        if eidp:
            return dict([(e, nd[0]) for (e,
                nd) in self.metadata.idps(langpref).items() if e in eidp])
        else:
            return dict([(e, nd[0]) for (e,
                                         nd) in self.metadata.idps(langpref).items()])

    def vo_conf(self, vo_name):
        try:
            return self.virtual_organization[vo_name]
        except KeyError:
            return None

    def ecp_endpoint(self, ipaddress):
        """
        Returns the entity ID of the IdP which the ECP client should talk to

        :param ipaddress: The IP address of the user client
        :return: IdP entity ID or None
        """
        _ecp = self.getattr("ecp")
        if _ecp:
            for key, eid in _ecp.items():
                if re.match(key, ipaddress):
                    return eid

        return None

class IdPConfig(Config):
    def_context = "idp"
    
    def __init__(self):
        Config.__init__(self)
        
    def single_logout_services(self, entity_id, binding=BINDING_SOAP):
        """ returns a list of endpoints to use for sending logout requests to

        :param entity_id: The entity ID of the service
        :param binding: The preferred binding (which for logout by default is
            the SOAP binding)
        :return: list of endpoints
        """
    
        return self.metadata.single_logout_service(entity_id, binding=binding)

    def assertion_consumer_services(self, entity_id, binding=BINDING_HTTP_POST):
        return self.metadata.assertion_consumer_services(entity_id, binding)

    def authz_services(self, entity_id, binding=BINDING_SOAP):
        return self.metadata.authz_service_endpoints(entity_id, binding=binding)

def config_factory(typ, file):
    if typ == "sp":
        conf = SPConfig().load_file(file)
        conf.context = typ
    elif typ in ["aa", "idp", "pdp"]:
        conf = IdPConfig().load_file(file)
        conf.context = typ
    else:
        conf = Config().load_file(file)
        conf.context = typ
    return conf
