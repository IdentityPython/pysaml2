from importlib import import_module
import json
import argparse
import sys

import logging

from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.mdstore import MetadataStore
from saml2.mdstore import MetaData

from srtest import FatalError
from srtest import Trace
from srtest import exception_trace

from idp_test.base import Conversation
from idp_test.check import CheckSaml2IntMetaData

# Schemas supported
from saml2 import md
from saml2 import saml
from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
from saml2.metadata import entity_descriptor
from saml2.saml import NAME_FORMAT_UNSPECIFIED
import xmldsig
import xmlenc

SCHEMA = [dri, idpdisc, md, mdattr, mdui, saml, ui, xmldsig, xmlenc]

__author__ = 'rolandh'

logger = logging.getLogger("")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")
memoryhandler = logging.handlers.MemoryHandler(1024*10, logging.DEBUG)
logger.addHandler(memoryhandler)


class SAML2client(object):

    def __init__(self, operations, check_factory):
        self.trace = Trace()
        self.operations = operations
        self.tests = None
        self.check_factory = check_factory

        self._parser = argparse.ArgumentParser()
        self._parser.add_argument('-d', dest='debug', action='store_true',
                                  help="Print debug information")
        self._parser.add_argument('-v', dest='verbose', action='store_true',
                                  help="Print runtime information")
        self._parser.add_argument(
            '-C', dest="ca_certs",
            help=("CA certs to use to verify HTTPS server certificates, ",
                  "if HTTPS is used and no server CA certs are defined then ",
                  "no cert verification will be done"))
        self._parser.add_argument('-J', dest="json_config_file",
                                  help="Script configuration")
        self._parser.add_argument('-m', dest="metadata", action='store_true',
                                  help="Return the SP metadata")
        self._parser.add_argument(
            "-l", dest="list", action="store_true",
            help="List all the test flows as a JSON object")
        self._parser.add_argument("-c", dest="spconfig", default="config_file",
                                  help="Configuration file for the SP")
        self._parser.add_argument(
            "-P", dest="configpath", default=".",
            help="Path to the configuration file for the SP")
        self._parser.add_argument("-t", dest="testpackage",
                                  help="Module describing tests")
        self._parser.add_argument("oper", nargs="?", help="Which test to run")

        self.interactions = None
        self.entity_id = None
        self.sp_config = None
        self.constraints = {}

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def sp_configure(self, metadata_construction=False):
        sys.path.insert(0, self.args.configpath)
        mod = import_module(self.args.spconfig)
        self.sp_config = SPConfig().load(mod.CONFIG, metadata_construction)

    def setup(self):
        self.json_config = self.json_config_file()

        _jc = self.json_config

        try:
            self.interactions = _jc["interaction"]
        except KeyError:
            self.interactions = []

        self.sp_configure()

        metadata = MetadataStore(SCHEMA, self.sp_config.attribute_converters,
                                 self.sp_config.xmlsec_binary)
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
            assert self.entity_id in md.entity.keys()
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

    def pysaml_log(self):
        print >> sys.stderr, 80 * ":"
        stderrHandler = logging.StreamHandler(sys.stderr)
        stderrHandler.setFormatter(formatter)
        memoryhandler.setTarget(stderrHandler)
        memoryhandler.flush()
        memoryhandler.close()

    def run(self):
        self.args = self._parser.parse_args()

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

        self.setup()

        self.client = Saml2Client(self.sp_config)
        try:
            try:
                oper = self.operations.OPERATIONS[self.args.oper]
            except KeyError:
                if self.tests:
                    try:
                        oper = self.tests.OPERATIONS[self.args.oper]
                    except ValueError:
                        print >> sys.stderr, "Undefined testcase"
                        return
                else:
                    print >> sys.stderr, "Undefined testcase"
                    return

            conv = Conversation(self.client, self.sp_config, self.trace,
                                self.interactions,
                                check_factory=self.check_factory,
                                entity_id=self.entity_id,
                                constraints=self.constraints)
            conv.do_sequence(oper)
            #testres, trace = do_sequence(oper,
            self.test_log = conv.test_output
            tsum = self.test_summation(self.args.oper)
            print >>sys.stdout, json.dumps(tsum)
            if tsum["status"] > 1 or self.args.debug:
                print >> sys.stderr, self.trace
        except FatalError, err:
            print >> sys.stderr, self.trace
            print err
            #exception_trace("RUN", err)
        except Exception, err:
            print >> sys.stderr, self.trace
            try:
                print err
            except (UnicodeDecodeError, UnicodeEncodeError):
                print err.message.encode("utf-8", "replace")
            exception_trace("RUN", err)

        if self.args.debug:
            self.pysaml_log()

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

            for key in ["depends", "endpoints"]:
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
        mod = import_module("config_file")
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
