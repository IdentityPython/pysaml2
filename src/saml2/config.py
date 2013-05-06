#!/usr/bin/env python

__author__ = 'rolandh'

import sys
import os
import re
import logging
import logging.handlers

from importlib import import_module

from saml2 import root_logger, BINDING_URI
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_ARTIFACT

from saml2.attribute_converter import ac_factory
from saml2.assertion import Policy
from saml2.mdstore import MetadataStore
from saml2.virtual_org import VirtualOrg

logger = logging.getLogger(__name__)

from saml2 import md
from saml2 import saml
from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
import xmldsig
import xmlenc


ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc
}

COMMON_ARGS = [
    "entityid", "xmlsec_binary", "debug", "key_file", "cert_file",
    "secret", "accepted_time_diff", "name", "ca_certs",
    "description", "valid_for", "verify_ssl_cert",
    "organization",
    "contact_person",
    "name_form",
    "virtual_organization",
    "logger",
    "only_use_keys_in_metadata",
    "logout_requests_signed",
    "disable_ssl_certificate_validation",
    "referred_binding",
    "session_storage",
    "entity_category"
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
    "ecp",
    "name_id_format"
]

AA_IDP_ARGS = [
    "want_authn_requests_signed",
    "provided_attributes",
    "subject_data",
    "sp",
    "scope",
    "endpoints",
    "metadata",
    "ui_info",
    "name_id_format",
    "domain",
    "name_qualifier",
    "edu_person_targeted_id",
]

PDP_ARGS = ["endpoints", "name_form", "name_id_format"]

AQ_ARGS = ["endpoints"]

COMPLEX_ARGS = ["attribute_converters", "metadata", "policy"]
ALL = set(COMMON_ARGS + SP_ARGS + AA_IDP_ARGS + PDP_ARGS + COMPLEX_ARGS)

SPEC = {
    "": COMMON_ARGS + COMPLEX_ARGS,
    "sp": COMMON_ARGS + COMPLEX_ARGS + SP_ARGS,
    "idp": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
    "aa": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
    "pdp": COMMON_ARGS + COMPLEX_ARGS + PDP_ARGS,
    "aq": COMMON_ARGS + COMPLEX_ARGS + AQ_ARGS,
}

# --------------- Logging stuff ---------------

LOG_LEVEL = {
    'debug': logging.DEBUG,
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

_RPA = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST, BINDING_HTTP_ARTIFACT]
_PRA = [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_HTTP_ARTIFACT]
_SRPA = [BINDING_SOAP, BINDING_HTTP_REDIRECT, BINDING_HTTP_POST,
         BINDING_HTTP_ARTIFACT]

PREFERRED_BINDING = {
    "single_logout_service": _SRPA,
    "manage_name_id_service": _SRPA,
    "assertion_consumer_service": _PRA,
    "single_sign_on_service": _RPA,
    "name_id_mapping_service": [BINDING_SOAP],
    "authn_query_service": [BINDING_SOAP],
    "attribute_service": [BINDING_SOAP],
    "authz_service": [BINDING_SOAP],
    "assertion_id_request_service": [BINDING_URI],
    "artifact_resolution_service": [BINDING_SOAP],
    "attribute_consuming_service": _RPA
}


class ConfigurationError(Exception):
    pass

# -----------------------------------------------------------------


class Config(object):
    def_context = ""

    def __init__(self, homedir="."):
        self._homedir = homedir
        self.entityid = None
        self.xmlsec_binary = None
        self.debug = False
        self.key_file = None
        self.cert_file = None
        self.secret = None
        self.accepted_time_diff = None
        self.name = None
        self.ca_certs = None
        self.verify_ssl_cert = False
        self.description = None
        self.valid_for = None
        self.organization = None
        self.contact_person = None
        self.name_form = None
        self.nameid_form = None
        self.virtual_organization = None
        self.logger = None
        self.only_use_keys_in_metadata = True
        self.logout_requests_signed = None
        self.disable_ssl_certificate_validation = None
        self.context = ""
        self.attribute_converters = None
        self.metadata = None
        self.policy = None
        self.serves = []
        self.vorg = {}
        self.preferred_binding = PREFERRED_BINDING
        self.domain = ""
        self.name_qualifier = ""
        self.entity_category = ""
        self.crypto_backend = 'xmlsec1'

    def setattr(self, context, attr, val):
        if context == "":
            setattr(self, attr, val)
        else:
            setattr(self, "_%s_%s" % (context, attr), val)

    def getattr(self, attr, context=None):
        if context is None:
            context = self.context

        if context == "":
            return getattr(self, attr, None)
        else:
            return getattr(self, "_%s_%s" % (context, attr), None)

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

        # for srv, spec in cnf["service"].items():
        #     try:
        #         self.setattr(srv, "policy",
        #                      Policy(cnf["service"][srv]["policy"]))
        #     except KeyError:
        #         pass

        try:
            try:
                acs = ac_factory(cnf["attribute_map_dir"])
            except KeyError:
                acs = ac_factory()

            if not acs:
                raise Exception("No attribute converters, something is wrong!!")

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

    def unicode_convert(self, item):
        try:
            return unicode(item, "utf-8")
        except TypeError:
            _uc = self.unicode_convert
            if isinstance(item, dict):
                return dict([(key, _uc(val)) for key, val in item.items()])
            elif isinstance(item, list):
                return [_uc(v) for v in item]
            elif isinstance(item, tuple):
                return tuple([_uc(v) for v in item])
            else:
                return item

    def load(self, cnf, metadata_construction=False):
        """ The base load method, loads the configuration

        :param cnf: The configuration as a dictionary
        :param metadata_construction: Is this only to be able to construct
            metadata. If so some things can be left out.
        :return: The Configuration instance
        """
        _uc = self.unicode_convert
        for arg in COMMON_ARGS:
            if arg == "virtual_organization":
                if "virtual_organization" in cnf:
                    for key, val in cnf["virtual_organization"].items():
                        self.vorg[key] = VirtualOrg(None, key, val)
                continue

            try:
                setattr(self, arg, _uc(cnf[arg]))
            except KeyError:
                pass
            except TypeError:  # Something that can't be a string
                setattr(self, arg, cnf[arg])

        if "service" in cnf:
            for typ in ["aa", "idp", "sp", "pdp", "aq"]:
                try:
                    self.load_special(
                        cnf["service"][typ], typ,
                        metadata_construction=metadata_construction)
                    self.serves.append(typ)
                except KeyError:
                    pass

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

        acs = self.attribute_converters

        if acs is None:
            raise Exception("Missing attribute converter specification")

        try:
            ca_certs = self.ca_certs
        except:
            ca_certs = None
        try:
            disable_validation = self.disable_ssl_certificate_validation
        except:
            disable_validation = False

        mds = MetadataStore(
            ONTS.values(), acs, self, ca_certs,
            disable_ssl_certificate_validation=disable_validation)

        mds.imp(metadata_conf)

        return mds

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
        endps = self.getattr("endpoints", context)
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
                    except TypeError:  # difference between 2.6 and 2.7
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
        if root_logger.level != logging.NOTSET:  # Someone got there before me
            return root_logger

        _logconf = self.logger
        if _logconf is None:
            return root_logger

        try:
            root_logger.setLevel(LOG_LEVEL[_logconf["loglevel"].lower()])
        except KeyError:  # reasonable default
            root_logger.setLevel(logging.INFO)

        root_logger.addHandler(self.log_handler())
        root_logger.info("Logging started")
        return root_logger


class SPConfig(Config):
    def_context = "sp"

    def __init__(self):
        Config.__init__(self)

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


def config_factory(typ, filename):
    if typ == "sp":
        conf = SPConfig().load_file(filename)
        conf.context = typ
    elif typ in ["aa", "idp", "pdp", "aq"]:
        conf = IdPConfig().load_file(filename)
        conf.context = typ
    else:
        conf = Config().load_file(filename)
        conf.context = typ
    return conf
