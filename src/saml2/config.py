#!/usr/bin/env python

__author__ = 'rolandh'

import sys
import os
import re
import logging
import logging.handlers

from importlib import import_module

from saml2 import BINDING_SOAP, BINDING_HTTP_REDIRECT
from saml2 import metadata
from saml2 import root_logger

from saml2.attribute_converter import ac_factory
from saml2.assertion import Policy
from saml2.sigver import get_xmlsec_binary

COMMON_ARGS = ["entityid", "xmlsec_binary", "debug", "key_file", "cert_file",
                "secret", "accepted_time_diff", "name", "ca_certs",
                "description",
                "organization",
                "contact_person",
                "name_form",
                "virtual_organization",
                "logger",
                "only_use_keys_in_metadata",
                "logout_requests_signed",
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

LOG_FORMAT = "%(asctime)s %(name)s: %(levelname)s %(message)s"
#LOG_FORMAT = "%(asctime)s %(name)s: %(levelname)s [%(sid)s][%(func)s] %
# (message)s"

class ConfigurationError(Exception):
    pass

# -----------------------------------------------------------------

class Config(object):
    def_context = ""

    def __init__(self):
        self._attr = {"": {}, "sp": {}, "idp": {}, "aa": {}, "pdp": {}}
        self.context = ""

    def serves(self):
        return [t for t in ["sp", "idp", "aa", "pdp"] if self._attr[t]]

    def copy_into(self, typ=""):
        if typ == "sp":
            copy = SPConfig()
        elif typ in ["idp", "aa"]:
            copy = IdPConfig()
        else:
            copy = Config()
        copy.context = typ
        copy._attr = self._attr.copy()
        return copy

    def __getattribute__(self, item):
        if item == "context":
            return object.__getattribute__(self, item)

        _context = self.context
        if item in ALL:
            try:
                return self._attr[_context][item]
            except KeyError:
                if _context:
                    try:
                        return self._attr[""][item]
                    except KeyError:
                        pass
                return None
        else:
            return object.__getattribute__(self, item)

    def setattr(self, context, attr, val):
        self._attr[context][attr] = val

    def load_special(self, cnf, typ, metadata_construction=False):
        for arg in SPEC[typ]:
            try:
                self._attr[typ][arg] = cnf[arg]
            except KeyError:
                pass

        self.context = typ
        self.load_complex(cnf, typ, metadata_construction=metadata_construction)
        self.context = self.def_context

    def load_complex(self, cnf, typ="", metadata_construction=False):
        _attr_typ = self._attr[typ]
        try:
            _attr_typ["policy"] = Policy(cnf["policy"])
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
            try:
                _attr_typ["attribute_converters"].extend(acs)
            except KeyError:
                _attr_typ["attribute_converters"] = acs
        except KeyError:
            pass

        if not metadata_construction:
            try:
                _attr_typ["metadata"] = self.load_metadata(cnf["metadata"])
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
            try:
                self._attr[""][arg] = cnf[arg]
            except KeyError:
                pass

        if "service" in cnf:
            for typ in ["aa", "idp", "sp", "pdp"]:
                try:
                    self.load_special(cnf["service"][typ], typ,
                                    metadata_construction=metadata_construction)

                except KeyError:
                    pass

        if not metadata_construction:
            if "xmlsec_binary" not in self._attr[""]:
                self._attr[""]["xmlsec_binary"] = get_xmlsec_binary()
            # verify that xmlsec is where it's supposed to be
            if not os.access(self._attr[""]["xmlsec_binary"], os.F_OK):
                raise Exception("xmlsec binary not in '%s' !" % (
                                            self._attr[""]["xmlsec_binary"]))

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

    def get_metadata_loader(self, func_spec):
        if callable(func_spec):
            return func_spec

        i = func_spec.rfind('.')
        module, attr = func_spec[:i], func_spec[i + 1:]
        try:
            mod = import_module(module)
        except Exception, e:
            raise RuntimeError('Cannot find metadata provider function %s: "%s"' % (func_spec, e))

        try:
            metadata_loader = getattr(mod, attr)
        except AttributeError:
            raise RuntimeError(
                'Module "%s" does not define a "%s" metadata loader' %
                (module, attr)
                )

        if not callable(metadata_loader):
            raise RuntimeError(
                'Metadata loader %s.%s must be callable' %
                (module, attr)
                )

        return metadata_loader

    def load_metadata(self, metadata_conf):
        """ Loads metadata into an internal structure """

        xmlsec_binary = self.xmlsec_binary
        acs = self.attribute_converters

        if xmlsec_binary is None:
            raise Exception("Missing xmlsec1 specification")
        if acs is None:
            raise Exception("Missing attribute converter specification")

        metad = metadata.MetaData(xmlsec_binary, acs)
        if "local" in metadata_conf:
            for mdfile in metadata_conf["local"]:
                metad.import_metadata(open(mdfile).read(), mdfile)
        if "remote" in metadata_conf:
            for spec in metadata_conf["remote"]:
                try:
                    cert = spec["cert"]
                except KeyError:
                    cert = None
                metad.import_external_metadata(spec["url"], cert)
        if 'loader' in metadata_conf:
            for spec in metadata_conf['loader']:
                loader = self.get_metadata_loader(spec)
                metad.import_metadata(loader(), spec)

        return metad

    def endpoint(self, service, binding=None):
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
        for endpspec in self.endpoints[service]:
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
        try:
            _logconf = self.logger
        except KeyError:
            return None

        if root_logger.level != logging.NOTSET:  # Someone got there before me
            return root_logger

        if _logconf is None:
            return None

        try:
            root_logger.setLevel(LOG_LEVEL[_logconf["loglevel"].lower()])
        except KeyError:  # reasonable default
            root_logger.setLevel(logging.WARNING)

        root_logger.addHandler(self.log_handler())
        root_logger.info("Logging started")
        return root_logger

    def keys(self):
        keys = []

        for dir in ["", "sp", "idp", "aa"]:
            keys.extend(self._attr[dir].keys())

        return list(set(keys))

    def __contains__(self, item):
        for dir in ["", "sp", "idp", "aa"]:
            if item in self._attr[dir]:
                return True
        return False

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
        return self.metadata.single_logout_services(entity_id, "idp",
                                                     binding=binding)

    def single_sign_on_services(self, entity_id,
                                binding=BINDING_HTTP_REDIRECT):
        """ returns a list of endpoints to use for sending login requests to

        :param entity_id: The entity ID of the service
        :param binding: The preferred binding
        :return: list of endpoints
        """
        return self.metadata.single_sign_on_services(entity_id,
                                                     binding=binding)

    def attribute_services(self, entity_id, binding=BINDING_SOAP):
        """ returns a list of endpoints to use for attribute requests to

        :param entity_id: The entity ID of the service
        :param binding: The preferred binding (which for logout by default is
            the SOAP binding)
        :return: list of endpoints
        """

        res = []
        if self.aa is None or entity_id in self.aa:
            for aad in self.metadata.attribute_authority(entity_id):
                for attrserv in aad.attribute_service:
                    if attrserv.binding == binding:
                        res.append(attrserv)

        return res

    def idps(self, langpref=None):
        """ Returns a dictionary of usefull IdPs, the keys being the
        entity ID of the service and the names of the services as values

        :param langpref: The preferred languages of the name, the first match
            is used.
        :return: Dictionary
        """
        if langpref is None:
            langpref = ["en"]

        if self.idp:
            return dict([(e, nd[0]) for (e,
                nd) in self.metadata.idps(langpref).items() if e in self.idp])
        else:
            return self.metadata.idps()

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
        if "ecp" in self._attr["sp"]:
            for key, eid in self._attr["sp"]["ecp"].items():
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

        return self.metadata.single_logout_services(entity_id, "sp",
                                                     binding=binding)

    def assertion_consumer_services(self, entity_id, binding):
        typ = "assertion_consumer_service"
        if self.sp is None or entity_id in self.sp:
            acs = self.metadata.sp_services(entity_id, typ, binding=binding)
            if acs:
                return [s[binding] for s in acs]

        return []

    def authz_services(self, entity_id, binding=BINDING_SOAP):
        return self.metadata.authz_services(entity_id, "pdp",
                                                     binding=binding)

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
