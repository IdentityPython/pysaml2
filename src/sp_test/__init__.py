import json
import argparse
import sys
from importlib import import_module

from idp_test import Trace, SCHEMA

from saml2.mdstore import MetadataStore, MetaData
from saml2.saml import NAME_FORMAT_UNSPECIFIED
from saml2.server import Server
from saml2.config import IdPConfig

from sp_test.base import Conversation

from srtest import FatalError, CheckError
from srtest import exception_trace

__author__ = 'rolandh'


class Client(object):

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
                                  help="Return the IdP metadata")
        self._parser.add_argument(
            "-l", dest="list", action="store_true",
            help="List all the test flows as a JSON object")
        self._parser.add_argument("-c", dest="idpconfig", default="idp_conf",
                                  help="Configuration file for the IdP")
        self._parser.add_argument(
            "-P", dest="configpath", default=".",
            help="Path to the configuration file for the IdP")
        self._parser.add_argument("-t", dest="testpackage",
                                  help="Module describing tests")
        self._parser.add_argument("oper", nargs="?", help="Which test to run")

        self.interactions = None
        self.entity_id = None
        self.constraints = {}
        self.args = None
        self.idp = None
        self.idp_config = None

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def idp_configure(self, metadata_construction=False):
        sys.path.insert(0, self.args.configpath)
        mod = import_module(self.args.idpconfig)
        self.idp_config = IdPConfig().load(mod.CONFIG, metadata_construction)
        self.idp = Server(config=self.idp_config)

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

        opers = [self.operations.PHASES[flow] for flow in oper["sequence"]]

        conv = Conversation(self.idp, self.idp_config, self.trace,
                            self.interactions, self.json_config,
                            check_factory=self.check_factory,
                            entity_id=self.entity_id,
                            constraints=self.constraints)
        try:
            conv.do_sequence(opers, oper["tests"])
            self.test_log = conv.test_output
            tsum = self.test_summation(self.args.oper)
            print >>sys.stdout, json.dumps(tsum)
            if tsum["status"] > 1 or self.args.debug:
                print >> sys.stderr, self.trace
        except CheckError, err:
            self.test_log = conv.test_output
            tsum = self.test_summation(self.args.oper)
            print >>sys.stdout, json.dumps(tsum)
            print >> sys.stderr, self.trace
        except FatalError, err:
            if conv:
                self.test_log = conv.test_output
                self.test_log.append(exception_trace("RUN", err))
            else:
                self.test_log = exception_trace("RUN", err)
            tsum = self.test_summation(self.args.oper)
            print >>sys.stdout, json.dumps(tsum)
            print >> sys.stderr, self.trace
        except Exception, err:
            if conv:
                self.test_log = conv.test_output
                self.test_log.append(exception_trace("RUN", err))
            else:
                self.test_log = exception_trace("RUN", err)
            tsum = self.test_summation(self.args.oper)
            print >>sys.stdout, json.dumps(tsum)

    def setup(self):
        self.json_config = self.json_config_file()

        _jc = self.json_config

        try:
            self.interactions = _jc["interaction"]
        except KeyError:
            self.interactions = []

        self.idp_configure()

        metadata = MetadataStore(SCHEMA, self.idp_config.attribute_converters,
                                 self.idp_config.xmlsec_binary)
        info = _jc["metadata"].encode("utf-8")
        md = MetaData(SCHEMA, self.idp_config.attribute_converters, info)
        md.load()
        metadata[0] = md
        self.idp.metadata = metadata
        #self.idp_config.metadata = metadata

        if self.args.testpackage:
            self.tests = import_module("sp_test.package.%s" %
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

    def make_meta(self):
        pass

    def list_operations(self):
        pass

    def verify_metadata(self):
        pass
