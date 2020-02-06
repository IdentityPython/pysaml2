#!/usr/bin/env python

import copy
import importlib
import logging
import logging.handlers
import os
import re
import sys
from functools import partial
import re
from urllib import parse
from iso3166 import countries

import six

from saml2 import root_logger, BINDING_URI, SAMLError
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_ARTIFACT

from saml2.attribute_converter import ac_factory
from saml2.assertion import Policy
from saml2.mdstore import MetadataStore
from saml2.saml import NAME_FORMAT_URI
from saml2.virtual_org import VirtualOrg
from saml2.utility import not_empty
from saml2.utility.config import ConfigValidationError

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


COMMON_ARGS = [
    "debug",
    "entityid",
    "xmlsec_binary",
    "key_file",
    "cert_file",
    "encryption_keypairs",
    "additional_cert_files",
    "metadata_key_usage",
    "secret",
    "accepted_time_diff",
    "name",
    "ca_certs",
    "description",
    "valid_for",
    "verify_ssl_cert",
    "organization",
    "contact_person",
    "name_form",
    "virtual_organization",
    "logger",
    "only_use_keys_in_metadata",
    "disable_ssl_certificate_validation",
    "preferred_binding",
    "session_storage",
    "assurance_certification",
    "entity_category",
    "entity_category_support",
    "xmlsec_path",
    "extension_schemas",
    "cert_handler_extra_class",
    "generate_cert_func",
    "generate_cert_info",
    "verify_encrypt_cert_advice",
    "verify_encrypt_cert_assertion",
    "tmp_cert_file",
    "tmp_key_file",
    "validate_certificate",
    "extensions",
    "allow_unknown_attributes",
    "crypto_backend",
    "id_attr_name",
    "delete_tmpfiles",
]

SP_ARGS = [
    "required_attributes",
    "optional_attributes",
    "idp",
    "aa",
    "subject_data",
    "want_response_signed",
    "want_assertions_signed",
    "want_assertions_or_response_signed",
    "authn_requests_signed",
    "name_form",
    "endpoints",
    "ui_info",
    "discovery_response",
    "allow_unsolicited",
    "ecp",
    "name_id_format",
    "name_id_format_allow_create",
    "logout_requests_signed",
    "requested_attribute_name_format",
    "hide_assertion_consumer_service",
    "force_authn",
    "sp_type",
    "sp_type_in_metadata",
    "requested_attributes",
    "node_country",
    "application_identifier",
    "protocol_version"
]

AA_IDP_ARGS = [
    "sign_assertion",
    "sign_response",
    "encrypt_assertion",
    "encrypted_advice_attributes",
    "encrypt_assertion_self_contained",
    "want_authn_requests_signed",
    "want_authn_requests_only_with_valid_cert",
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
    "node_country",
    "application_identifier"
    "protocol_version"
]

PDP_ARGS = ["endpoints", "name_form", "name_id_format"]

AQ_ARGS = ["endpoints"]

AA_ARGS = ["attribute", "attribute_profile"]

COMPLEX_ARGS = ["attribute_converters", "metadata", "policy"]
ALL = set(COMMON_ARGS + SP_ARGS + AA_IDP_ARGS + PDP_ARGS + COMPLEX_ARGS +
          AA_ARGS)

SPEC = {
    "": COMMON_ARGS + COMPLEX_ARGS,
    "sp": COMMON_ARGS + COMPLEX_ARGS + SP_ARGS,
    "idp": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS,
    "aa": COMMON_ARGS + COMPLEX_ARGS + AA_IDP_ARGS + AA_ARGS,
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
    "memory": logging.handlers.MemoryHandler,
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


class ConfigurationError(SAMLError):
    pass


# -----------------------------------------------------------------


class Config(object):
    def_context = ""

    def __init__(self, homedir="."):
        self._homedir = homedir
        self.entityid = None
        self.xmlsec_binary = None
        self.xmlsec_path = []
        self.debug = False
        self.key_file = None
        self.cert_file = None
        self.encryption_keypairs = None
        self.additional_cert_files = None
        self.metadata_key_usage = 'both'
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
        self.name_id_format = None
        self.name_id_format_allow_create = None
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
        self.assurance_certification = []
        self.entity_category = []
        self.entity_category_support = []
        self.crypto_backend = 'xmlsec1'
        self.id_attr_name = None
        self.scope = ""
        self.allow_unknown_attributes = False
        self.extension_schema = {}
        self.cert_handler_extra_class = None
        self.verify_encrypt_cert_advice = None
        self.verify_encrypt_cert_assertion = None
        self.generate_cert_func = None
        self.generate_cert_info = None
        self.tmp_cert_file = None
        self.tmp_key_file = None
        self.validate_certificate = None
        self.extensions = {}
        self.attribute = []
        self.attribute_profile = []
        self.requested_attribute_name_format = NAME_FORMAT_URI
        self.delete_tmpfiles = True

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
                _val = cnf[arg]
            except KeyError:
                pass
            else:
                if _val == "true":
                    _val = True
                elif _val == "false":
                    _val = False
                self.setattr(typ, arg, _val)

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
                raise ConfigurationError(
                    "No attribute converters, something is wrong!!")

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
            return six.text_type(item, "utf-8")
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
            elif arg == "extension_schemas":
                # List of filename of modules representing the schemas
                if "extension_schemas" in cnf:
                    for mod_file in cnf["extension_schemas"]:
                        _mod = self._load(mod_file)
                        self.extension_schema[_mod.NAMESPACE] = _mod

            try:
                setattr(self, arg, _uc(cnf[arg]))
            except KeyError:
                pass
            except TypeError:  # Something that can't be a string
                setattr(self, arg, cnf[arg])

        if not self.delete_tmpfiles:
            logger.warning(
                "delete_tmpfiles is set to False; "
                "temporary files will not be deleted."
            )

        if "service" in cnf:
            for typ in ["aa", "idp", "sp", "pdp", "aq"]:
                try:
                    self.load_special(
                        cnf["service"][typ], typ,
                        metadata_construction=metadata_construction)
                    self.serves.append(typ)
                except KeyError:
                    pass

        if "extensions" in cnf:
            self.do_extensions(cnf["extensions"])

        self.load_complex(cnf, metadata_construction=metadata_construction)
        self.context = self.def_context

        return self

    def _load(self, fil):
        head, tail = os.path.split(fil)
        if head == "":
            if sys.path[0] != ".":
                sys.path.insert(0, ".")
        else:
            sys.path.insert(0, head)

        return importlib.import_module(tail)

    def load_file(self, config_filename, metadata_construction=False):
        if config_filename.endswith(".py"):
            config_filename = config_filename[:-3]

        mod = self._load(config_filename)
        return self.load(copy.deepcopy(mod.CONFIG), metadata_construction)

    def load_metadata(self, metadata_conf):
        """ Loads metadata into an internal structure """

        acs = self.attribute_converters

        if acs is None:
            raise ConfigurationError(
                "Missing attribute converter specification")

        try:
            ca_certs = self.ca_certs
        except:
            ca_certs = None
        try:
            disable_validation = self.disable_ssl_certificate_validation
        except:
            disable_validation = False

        mds = MetadataStore(acs, self, ca_certs,
            disable_ssl_certificate_validation=disable_validation)

        mds.imp(metadata_conf)

        return mds

    def endpoint(self, service, binding=None, context=None):
        """ Goes through the list of endpoint specifications for the
        given type of service and returns a list of endpoint that matches
        the given binding. If no binding is given all endpoints available for
        that service will be returned.

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
                            raise ConfigurationError("Unknown socktype!")
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

    def endpoint2service(self, endpoint, context=None):
        endps = self.getattr("endpoints", context)

        for service, specs in endps.items():
            for endp, binding in specs:
                if endp == endpoint:
                    return service, binding

        return None, None

    def do_extensions(self, extensions):
        for key, val in extensions.items():
            self.extensions[key] = val

    def service_per_endpoint(self, context=None):
        """
        List all endpoint this entity publishes and which service and binding
        that are behind the endpoint

        :param context: Type of entity
        :return: Dictionary with endpoint url as key and a tuple of
            service and binding as value
        """
        endps = self.getattr("endpoints", context)
        res = {}
        for service, specs in endps.items():
            for endp, binding in specs:
                res[endp] = (service, binding)
        return res

    def validate(self):
        pass


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


class eIDASConfig(Config):
    def get_endpoint_element(self, element):
        pass

    def get_protocol_version(self):
        pass

    def get_application_identifier(self):
        pass

    def get_node_country(self):
        pass

    @staticmethod
    def validate_node_country_format(node_country):
        try:
            return countries.get(node_country).alpha2 == node_country
        except KeyError:
            return False

    @staticmethod
    def validate_application_identifier_format(application_identifier):
        if not application_identifier:
            return True

        return re.search(r"([a-zA-Z0-9])+:([a-zA-Z0-9():_\-])+:([0-9])+"
                         r"(\.([0-9])+){1,2}", application_identifier)

    @staticmethod
    def get_type_contact_person(contacts, ctype):
        return [contact for contact in contacts
                if contact.get("contact_type") == ctype]

    @staticmethod
    def contact_has_email_address(contact):
        return not_empty(contact.get("email_address"))


class eIDASSPConfig(SPConfig, eIDASConfig):
    def get_endpoint_element(self, element):
        return getattr(self, "_sp_endpoints", {}).get(element, None)

    def get_application_identifier(self):
        return getattr(self, "_sp_application_identifier", None)

    def get_protocol_version(self):
        return getattr(self, "_sp_protocol_version", None)

    def get_node_country(self):
        return getattr(self, "_sp_node_country", None)

    def validate(self):
        warning_validators = {
            "single_logout_service SHOULD NOT be declared":
                self.get_endpoint_element("single_logout_service") is None,
            "artifact_resolution_service SHOULD NOT be declared":
                self.get_endpoint_element("artifact_resolution_service") is None,
            "manage_name_id_service SHOULD NOT be declared":
                self.get_endpoint_element("manage_name_id_service") is None,
            "application_identifier SHOULD be declared":
                not_empty(self.get_application_identifier()),
            "protocol_version SHOULD be declared":
                not_empty(self.get_protocol_version()),
            "minimal organization info (name/dname/url) SHOULD be declared":
                not_empty(self.organization),
            "contact_person with contact_type 'technical' and at least one "
            "email_address SHOULD be declared":
                any(filter(self.contact_has_email_address,
                           self.get_type_contact_person(self.contact_person,
                                                        ctype="technical"))),
            "contact_person with contact_type 'support' and at least one "
            "email_address SHOULD be declared":
                any(filter(self.contact_has_email_address,
                           self.get_type_contact_person(self.contact_person,
                                                        ctype="support")))
        }

        if not all(warning_validators.values()):
            logger.warning(
                "Configuration validation warnings occurred: {}".format(
                    [msg for msg, check in warning_validators.items()
                     if check is not True]
                )
            )

        error_validators = {
            "KeyDescriptor MUST be declared":
                self.cert_file or self.encryption_keypairs,
            "node_country MUST be declared in ISO 3166-1 alpha-2 format":
                self.validate_node_country_format(self.get_node_country()),
            "application_identifier MUST be in the form <vendor name>:<software "
            "identifier>:<major-version>.<minor-version>[.<patch-version>]":
                self.validate_application_identifier_format(
                    self.get_application_identifier()),
            "entityid MUST be an HTTPS URL pointing to the location of its published "
            "metadata":
                parse.urlparse(self.entityid).scheme == "https",
            "authn_requests_signed MUST be set to True":
                getattr(self, "_sp_authn_requests_signed", None) is True
        }

        if not all(error_validators.values()):
            error = "Configuration validation errors occurred:".format(
                    [msg for msg, check in error_validators.items()
                     if check is not True])
            logger.error(error)
            raise ConfigValidationError(error)


class IdPConfig(Config):
    def_context = "idp"

    def __init__(self):
        Config.__init__(self)


class eIDASIdPConfig(IdPConfig):
    pass


def config_factory(_type, config):
    """

    :type _type: str
    :param _type:

    :type config: str or dict
    :param config: Name of file with pysaml2 config or CONFIG dict

    :return:
    """
    if _type == "sp":
        conf = SPConfig()
    elif _type in ["aa", "idp", "pdp", "aq"]:
        conf = IdPConfig()
    else:
        conf = Config()

    if isinstance(config, dict):
        conf.load(copy.deepcopy(config))
    elif isinstance(config, str):
        conf.load_file(config)
    else:
        raise ValueError('Unknown type of config')

    conf.context = _type
    return conf
