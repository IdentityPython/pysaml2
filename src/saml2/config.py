#!/usr/bin/env python

__author__ = 'rolandh'

import sys
from importlib import import_module
from saml2 import BINDING_SOAP, BINDING_HTTP_REDIRECT
from saml2 import metadata
from saml2.attribute_converter import ac_factory
from saml2.assertion import Policy

COMMON_ARGS = ["entityid", "xmlsec_binary", "debug", "key_file", "cert_file",
                "secret", "accepted_time_diff", "name",
                "description",
                "organization",
                "contact_person",
                "name_form",
                "virtual_organization",
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

class Config(object):
    def_context = ""

    def __init__(self):
        self._attr = {"": {}, "sp": {}, "idp": {}, "aa": {}}
        self.context = ""

    def serves(self):
        return [t for t in ["sp", "idp", "aa"] if self._attr[t]]
    
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
        try:
            self._attr[typ]["policy"] = Policy(cnf["policy"])
        except KeyError:
            pass

        try:
            acs = ac_factory(cnf["attribute_map_dir"])
            try:
                self._attr[typ]["attribute_converters"].extend(acs)
            except KeyError:
                self._attr[typ]["attribute_converters"] = acs
        except KeyError:
            pass

        try:
            self._attr[typ]["metadata"] = self.load_metadata(cnf["metadata"])
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

    def idps(self, langpref=["en"]):
        """ Returns a dictionary of usefull IdPs, the keys being the
        entity ID of the service and the names of the services as values

        :param langpref: The preferred languages of the name, the first match
            is used.
        :return: Dictionary
        """
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
