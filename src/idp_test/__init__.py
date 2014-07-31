from importlib import import_module
import json
import os
import pprint
import types
import argparse
import sys

import logging
import imp
import xmldsig
import xmlenc

from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.mdstore import MetadataStore, ToOld
from saml2.mdstore import MetaData

from saml2test import CheckError, FatalError
from saml2test import exception_trace
from saml2test import ContextFilter

from idp_test.base import Conversation
from idp_test.check import CheckSaml2IntMetaData

# Schemas supported
from saml2 import md
from saml2 import saml
from saml2 import root_logger
from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
from saml2.metadata import entity_descriptor
from saml2.saml import NAME_FORMAT_UNSPECIFIED

SCHEMA = [dri, idpdisc, md, mdattr, mdui, saml, ui, xmldsig, xmlenc]

__author__ = 'rolandh'

logger = logging.getLogger("")
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")
formatter_2 = logging.Formatter("%(delta).6f - %(levelname)s - [%(name)s] %(message)s")

cf = ContextFilter()
cf.start()

streamhandler = logging.StreamHandler(sys.stderr)
streamhandler.setFormatter(formatter_2)

memoryhandler = logging.handlers.MemoryHandler(1024*10, logging.DEBUG)
memoryhandler.addFilter(cf)

saml2testlog = logging.getLogger("saml2test")
saml2testlog.addHandler(memoryhandler)
saml2testlog.setLevel(logging.DEBUG)


def recursive_find_module(name, path=None):
    parts = name.split(".")

    mod_a = None
    for part in parts:
        try:
            (fil, pathname, desc) = imp.find_module(part, path)
        except ImportError:
            raise

        mod_a = imp.load_module(name, fil, pathname, desc)
        sys.modules[name] = mod_a
        path = mod_a.__path__

    return mod_a


def get_mod(name, path=None):
    try:
        mod_a = sys.modules[name]
        if not isinstance(mod_a, types.ModuleType):
            raise KeyError
    except KeyError:
        try:
            (fil, pathname, desc) = imp.find_module(name, path)
            mod_a = imp.load_module(name, fil, pathname, desc)
        except ImportError:
            if "." in name:
                mod_a = recursive_find_module(name, path)
            else:
                raise
        sys.modules[name] = mod_a
    return mod_a


class SAML2client(object):

    def __init__(self, check_factory):
        self.tests = None
        self.check_factory = check_factory

        self._parser = argparse.ArgumentParser()
        self._parser.add_argument('-d', dest='debug', action='store_true',
                                  help="Print debug information")
        self._parser.add_argument('-L', dest='log', action='store_true',
                                  help="Print log information")
        self._parser.add_argument(
            '-C', dest="cacerts",
            help=("CA certs to use to verify HTTPS server certificates, ",
                  "if HTTPS is used and no server CA certs are defined then ",
                  "no cert verification will be done"))
        self._parser.add_argument('-J', dest="json_config_file",
                                  help="Test target configuration")
        self._parser.add_argument('-m', dest="metadata", action='store_true',
                                  help="Return the SP metadata")
        self._parser.add_argument(
            "-l", dest="list", action="store_true",
            help="List all the test flows as a JSON object")
        self._parser.add_argument(
            "-c", dest="spconfig", default="config",
            help=("Configuration module for the SP Test Driver at the current"
                  "directory or the path specified with the -P option. Do not"
                  "use relative paths or filename extension."))
        self._parser.add_argument(
            "-P", dest="path", default=".",
            help="Path to the configuration stuff")
        self._parser.add_argument("-t", dest="testpackage",
                                  help="Module describing tests")
        self._parser.add_argument("-O", dest="operations",
                                  help="Tests")
        self._parser.add_argument("-Y", dest="pysamllog", action='store_true',
                                  help="Print PySAML2 logs")
        self._parser.add_argument("-H", dest="pretty", action='store_true',
                                  help="Output summary on stdout as pretty "
                                       "printed python dict instead of JSON")
        self._parser.add_argument("-i", dest="insecure", action='store_true',
                                  help="Do not verify SSL certificate")
        self._parser.add_argument("oper", nargs="?", help="Which test to run")

        self.interactions = None
        self.entity_id = None
        self.sp_config = None
        self.constraints = {}
        self.operations = None
        self.args = None

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def sp_configure(self, metadata_construction=False):
        """
        Need to know where 4 different things are. The config, key_file and
        cert_file files and the attributemaps directory
        """
        # Always first look in the present working directory
        sys.path.insert(0, self.args.path)
        if self.args.path != ".":
            sys.path.insert(0, ".")
        mod = import_module(self.args.spconfig)

        if self.args.path != ".":
            for param in ["attribute_map_dir", "key_file", "cert_file"]:
                if mod.CONFIG[param].startswith("/"):  # Absolute path
                    continue

                for _path in [".", self.args.path]:
                    _obj = os.path.join(_path, mod.CONFIG[param])
                    _obj = os.path.normpath(_obj)
                    if os.path.exists(_obj):
                        mod.CONFIG[param] = _obj
                        break

        self.sp_config = SPConfig().load(mod.CONFIG, metadata_construction)

        if not self.args.insecure:
            self.sp_config.verify_ssl_cert = False
        else:
            if self.args.ca_certs:
                self.sp_config.ca_certs = self.args.ca_certs
            else:
                self.sp_config.ca_certs = "../keys/cacert.pem"

    def setup(self):
        self.json_config = self.json_config_file()

        _jc = self.json_config

        try:
            self.interactions = _jc["interaction"]
        except KeyError:
            self.interactions = []

        self.sp_configure()

        metadata = MetadataStore(SCHEMA, self.sp_config.attribute_converters,
                                 self.sp_config)
        info = _jc["metadata"].encode("utf-8")
        md = MetaData(SCHEMA, self.sp_config.attribute_converters, info)
        md.load()
        metadata[0] = md
        self.sp_config.metadata = metadata

        if self.args.testpackage:
            self.tests = import_module("idp_test.package.%s" %
                                       self.args.testpackage)

        try:
            self.entity_id = _jc["entity_id"]
            # Verify its the correct metadata
            assert self.entity_id in md.entity.keys(), "metadata does not contain entityId %s" % self.entity_id
        except KeyError:
            if len(md.entity.keys()) == 1:
                self.entity_id = md.entity.keys()[0]
            else:
                raise Exception("Don't know which entity to talk to")

        if "constraints" in _jc:
            self.constraints = _jc["constraints"]
            if "name_format" not in self.constraints:
                self.constraints["name_format"] = NAME_FORMAT_UNSPECIFIED

    def test_summation(self, sid):
        status = 0
        for item in self.test_log:
            if item["status"] > status:
                status = item["status"]

        if status == 0:
            status = 1

        info = {
            "id": sid,
            "status": status,
            "tests": self.test_log
        }

        if status == 5:
            info["url"] = self.test_log[-1]["url"]
            info["htmlbody"] = self.test_log[-1]["message"]

        return info

    def output_log(self, memhndlr, hndlr2):
        """
        """

        print >> sys.stderr, 80 * ":"
        hndlr2.setFormatter(formatter_2)
        memhndlr.setTarget(hndlr2)
        memhndlr.flush()
        memhndlr.close()
        # streamhandler.setFormatter(formatter_2)
        # pys_memoryhandler.setTarget(streamhandler)
        # pys_memoryhandler.flush()
        # pys_memoryhandler.close()

    def run(self):
        self.args = self._parser.parse_args()

        if self.args.pysamllog:
            root_logger.addHandler(memoryhandler)
            root_logger.setLevel(logging.DEBUG)

        if self.args.operations:
            path, name = os.path.split(self.args.operations)
            self.operations = get_mod(name, [path])
        else:
            self.operations = __import__("idp_test.saml2base",
                                         fromlist=["idp_test"])

        if self.args.metadata:
            return self.make_meta()
        elif self.args.list:
            return self.list_operations()
        elif self.args.oper == "check":
            return self.verify_metadata()
        else:
            if not self.args.oper:
                raise Exception("Missing test case specification")
            self.args.oper = self.args.oper.strip("'")
            self.args.oper = self.args.oper.strip('"')

        try:
            self.setup()
        except (AttributeError, ToOld), err:
            print >> sys.stdout, "Configuration Error: %s" % err

        self.client = Saml2Client(self.sp_config)
        conv = None

        if self.args.pretty:
            pp = pprint.PrettyPrinter(indent=4)
        else:
            pp = None

        try:
            try:
                oper = self.operations.OPERATIONS[self.args.oper]
            except KeyError:
                if self.tests:
                    try:
                        oper = self.tests.OPERATIONS[self.args.oper]
                    except ValueError:
                        logger.error("Undefined testcase")
                        return
                else:
                    logger.error("Undefined testcase")
                    return

            logger.info("Starting conversation")
            conv = Conversation(self.client, self.sp_config, self.interactions,
                                check_factory=self.check_factory,
                                entity_id=self.entity_id,
                                constraints=self.constraints)
            conv.do_sequence(oper)
            #testres, trace = do_sequence(oper,
            self.test_log = conv.test_output
            tsum = self.test_summation(self.args.oper)
            err = None
        except CheckError, err:
            self.test_log = conv.test_output
            tsum = self.test_summation(self.args.oper)
        except FatalError, err:
            if conv:
                self.test_log = conv.test_output
                self.test_log.append(exception_trace("RUN", err))
            else:
                self.test_log = exception_trace("RUN", err)
            tsum = self.test_summation(self.args.oper)
        except Exception, err:
            if conv:
                self.test_log = conv.test_output
                self.test_log.append(exception_trace("RUN", err))
            else:
                self.test_log = exception_trace("RUN", err)
            tsum = self.test_summation(self.args.oper)

        if pp:
            pp.pprint(tsum)
        else:
            print >> sys.stdout, json.dumps(tsum)

        if tsum["status"] > 1 or self.args.debug or err:
            self.output_log(memoryhandler, streamhandler)

    def list_operations(self):
        lista = []
        for key, val in self.operations.OPERATIONS.items():
            item = {"id": key, "name": val["name"]}
            try:
                _desc = val["descr"]
                if isinstance(_desc, basestring):
                    item["descr"] = _desc
                else:
                    item["descr"] = "\n".join(_desc)
            except KeyError:
                pass

            for key in ["depend", "endpoints"]:
                try:
                    item[key] = val[key]
                except KeyError:
                    pass

            lista.append(item)

        if self.args.testpackage:
            mod = import_module(self.args.testpackage, "idp_test")
            for key, val in mod.OPERATIONS.items():
                item = {"id": key, "name": val["name"]}
                try:
                    _desc = val["descr"]
                    if isinstance(_desc, basestring):
                        item["descr"] = _desc
                    else:
                        item["descr"] = "\n".join(_desc)
                except KeyError:
                    pass

                for key in ["depends", "endpoints"]:
                    try:
                        item[key] = val[key]
                    except KeyError:
                        pass

                lista.append(item)

        print json.dumps(lista)

    def _get_operation(self, operation):
        return self.operations.OPERATIONS[operation]

    def make_meta(self):
        self.sp_configure(True)
        print entity_descriptor(self.sp_config)

    def list_conf_id(self):
        sys.path.insert(0, ".")
        mod = import_module("config")
        _res = dict([(key, cnf["description"]) for key, cnf in
                    mod.CONFIG.items()])
        print json.dumps(_res)

    def verify_metadata(self):
        self.json_config = self.json_config_file()
        self.sp_configure()

        metadata = MetadataStore(SCHEMA, self.sp_config.attribute_converters,
                                 self.sp_config.xmlsec_binary)
        info = self.json_config["metadata"].encode("utf-8")
        md = MetaData(SCHEMA, self.sp_config.attribute_converters, info)
        md.load()
        metadata[0] = md
        env = {"metadata": metadata}
        chk = CheckSaml2IntMetaData()
        output = []
        res = chk(env, output)
        print >> sys.stdout, res
