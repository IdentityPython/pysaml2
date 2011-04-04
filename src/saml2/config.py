#!/usr/bin/env python

__author__ = 'rolandh'

import sys
import logging
import logging.handlers

from importlib import import_module

from saml2 import BINDING_SOAP, BINDING_HTTP_REDIRECT
from saml2 import metadata
from saml2 import root_logger

from saml2.attribute_converter import ac_factory
from saml2.assertion import Policy

COMMON_ARGS = ["entityid", "xmlsec_binary", "debug", "key_file", "cert_file",
                "secret", "accepted_time_diff", "name",
                "description",
                "organization",
                "contact_person",
                "name_form",
                "virtual_organization",
                "logger"
                ]

SP_ARGS = [
            "required_attributes",
            "optional_attributes",
            "idp",
            "subject_data",
            "want_assertions_signed",
            "authn_requests_signed",
            "name_form",
            "endpoints",
            ]

AA_IDP_ARGS = ["want_authn_requests_signed",
               "provided_attributes",
               "subject_data",
               "sp",
               "scope",
               "endpoints",
               "metadata"]

COMPLEX_ARGS = ["attribute_converters", "metadata", "policy"]
ALL = COMMON_ARGS + SP_ARGS + AA_IDP_ARGS + COMPLEX_ARGS


SPEC = {
    "": COMMON_ARGS + COMPLEX_ARGS,
    "sp": COMMON_ARGS + COMPLEX_ARGS + SP_ARGS,
    "idp": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
    "aa": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
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

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# -----------------------------------------------------------------

class Config(object):
    def_context = ""

    def __init__(self):
        self._attr = {"": {}, "sp": {}, "idp": {}, "aa": {}}
        self.context = ""

    def serves(self):
        return [t for t in ["sp", "idp", "aa"] if self._attr[t]]

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

    def load_special(self, cnf, typ):
        for arg in SPEC[typ]:
            try:
                self._attr[typ][arg] = cnf[arg]
            except KeyError:
                pass

        self.context = typ
        self.load_complex(cnf, typ)
        self.context = self.def_context

    def load_complex(self, cnf, typ=""):
        _attr_typ = self._attr[typ]
        try:
            _attr_typ["policy"] = Policy(cnf["policy"])
        except KeyError:
            pass

        try:
            acs = ac_factory(cnf["attribute_map_dir"])
            try:
                _attr_typ["attribute_converters"].extend(acs)
            except KeyError:
                _attr_typ["attribute_converters"] = acs
        except KeyError:
            pass

        try:
            _attr_typ["metadata"] = self.load_metadata(cnf["metadata"])
        except KeyError:
            pass

    def load(self, cnf):

        for arg in COMMON_ARGS:
            try:
                self._attr[""][arg] = cnf[arg]
            except KeyError:
                pass

        if "service" in cnf:
            for typ in ["aa", "idp", "sp"]:
                try:
                    self.load_special(cnf["service"][typ], typ)
                except KeyError:
                    pass

        self.load_complex(cnf)
        self.context = self.def_context
        return self

    def load_file(self, config_file):
        if sys.path[0] != ".":
            sys.path.insert(0, ".")
        mod = import_module(config_file)
        #return self.load(eval(open(config_file).read()))
        return self.load(mod.CONFIG)

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
        return metad

    def endpoint(self, service, binding=None):
        """ Goes through the list of endpoint specifications for the
        given type of service and returnes the first endpoint that matches
        the given binding. If no binding is given any endpoint for that
        service will be returned.

        :param service: The service the endpoint should support
        :param binding: The expected binding
        :return: At the most one endpoint that matches the given restrictions
        """
        res = []
        for endpspec in self.endpoints[service]:
            try:
                endp, bind = endpspec
                if binding is None or bind == binding:
                    res.append(endp)
            except ValueError:
                res.append(endpspec)
    
        try:
            return res[0]
        except IndexError:
            return None

    def setup_logger(self):
        try:
            _logconf = self.logger
        except KeyError:
            return None

        if root_logger.level != logging.NOTSET: # Someone got there before me
            return root_logger

        if _logconf is None:
            return None

        try:
            root_logger.setLevel(LOG_LEVEL[_logconf["loglevel"]])
        except KeyError: # reasonable default
            root_logger.setLevel(logging.WARNING)

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
                    handler = LOG_HANDLER[htyp](**args)
                else:
                    handler = LOG_HANDLER[htyp](**_logconf[htyp])
                break

        if handler is None:
            raise Exception("You have to define a log handler")

        if "format" in _logconf:
            formatter = logging.Formatter(_logconf["format"])
        else:
            formatter = logging.Formatter(LOG_FORMAT)
        
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

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
        typ = "attribute_service"
        if self.aa is None or entity_id in self.aa:
            slo = self.metadata.attribute_services(entity_id, typ,
                                                    binding=binding)
            if slo:
                return [s[binding] for s in slo]
            
        return []

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

def config_factory(typ, file):
    if typ == "sp":
        conf = SPConfig().load_file(file)
        conf.context = typ
    elif typ in ["aa", "idp"]:
        conf = IdPConfig().load_file(file)
        conf.context = typ
    else:
        conf = Config().load_file(file)
        conf.context = typ
    return conf
