import json
import pprint
import argparse
import os.path
import sys
import traceback
from importlib import import_module

from idp_test import SCHEMA
from saml2 import root_logger

from saml2.mdstore import MetadataStore, MetaData
from saml2.saml import NAME_FORMAT_UNSPECIFIED
from saml2.server import Server
from saml2.config import IdPConfig
from saml2.config import logging

from sp_test.base import Conversation

from saml2test import FatalError
from saml2test import CheckError
from saml2test import ContextFilter
from saml2test import exception_trace
from saml2test.check import CRITICAL

__author__ = 'rolandh'

#formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")
formatter_2 = logging.Formatter(
    "%(delta).6f - %(levelname)s - [%(name)s] %(message)s")

cf = ContextFilter()
cf.start()

streamhandler = logging.StreamHandler(sys.stderr)
streamhandler.setFormatter(formatter_2)

memoryhandler = logging.handlers.MemoryHandler(1024 * 10, logging.DEBUG)
memoryhandler.addFilter(cf)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(memoryhandler)
logger.setLevel(logging.DEBUG)


class Client(object):
    def __init__(self, operations, check_factory):
        self.operations = operations
        self.tests = None
        self.check_factory = check_factory

        self._parser = argparse.ArgumentParser()
        self._parser.add_argument("-c", dest="config", default="config",
                                  help="Configuration file for the IdP")
        self._parser.add_argument(
            '-C', dest="ca_certs",
            help=("CA certs to use to verify HTTPS server certificates, ",
                  "if HTTPS is used and no server CA certs are defined then ",
                  "no cert verification will be done"))
        self._parser.add_argument('-d', dest='debug', action='store_true',
                                  help="Print debug information")
        self._parser.add_argument("-H", dest="pretty", action='store_true',
                                  help="Output summary on stdout as pretty "
                                       "printed python dict instead of JSON")
        self._parser.add_argument("-i", dest="insecure", action='store_true',
                                  help="Do not verify SSL certificate")
        self._parser.add_argument("-I", dest="keysdir", default="keys",
                                  help="Directory for invalid IDP keys")
        self._parser.add_argument('-J', dest="json_config_file",
                                  help="Test target configuration")
        self._parser.add_argument(
            '-k', dest='content_log', action='store_true',
            help="Log HTTP content in spearate files in directory "
                 "<operation>/, which defaults to the path in -L")
        self._parser.add_argument(
            "-l", dest="list", action="store_true",
            help="List all the test flows as a JSON object")
        self._parser.add_argument("-L", dest="logpath", default=".",
                                  help="Path to the logfile directory")
        self._parser.add_argument('-m', dest="metadata", action='store_true',
                                  help="Return the IdP metadata")
        self._parser.add_argument(
            "-P", dest="configpath", default=".",
            help="Path to the configuration file for the IdP")
        self._parser.add_argument("-t", dest="testpackage",
                                  help="Module describing tests")
        #self._parser.add_argument('-v', dest='verbose', action='store_true',
        #                          help="Print runtime information") # unsused
        self._parser.add_argument("-Y", dest="pysamllog", action='store_true',
                                  help="Print PySAML2 logs")
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
        mod = import_module(self.args.config)
        self.idp_config = IdPConfig().load(mod.CONFIG, metadata_construction)

        if not self.args.insecure:
            self.idp_config.verify_ssl_cert = False
        else:
            if self.args.ca_certs:
                self.idp_config.ca_certs = self.args.ca_certs
            else:
                self.idp_config.ca_certs = "../keys/cacert.pem"
        # hack to change idp cert without config change. TODO: find interface to
        # change IDP cert after __init__
        if self.args.oper == 'sp-04':
            self.idp_config.cert_file = os.path.join(self.args.keysdir, "non_md_cert.pem")
            self.idp_config.key_file = os.path.join(self.args.keysdir, "non_md_key.pem")
            for f in [self.idp_config.cert_file, self.idp_config.key_file]:
                if not os.path.isfile(f):
                    print "File not found: %s" % os.path.abspath(f)
                    raise

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

    def output_log(self, memhndlr, hndlr2):
        """
        """

        print >> sys.stderr, 80 * ":"
        hndlr2.setFormatter(formatter_2)
        memhndlr.setTarget(hndlr2)
        memhndlr.flush()
        memhndlr.close()

    def run(self):
        self.args = self._parser.parse_args()

        if self.args.pysamllog:
            root_logger.addHandler(memoryhandler)
            root_logger.setLevel(logging.DEBUG)

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
                    print >> sys.stderr, "Undefined testcase " + self.args.oper
                    return
            else:
                print >> sys.stderr, "Undefined testcase " + self.args.oper
                return

        if self.args.pretty:
            pp = pprint.PrettyPrinter(indent=4)
        else:
            pp = None

        logger.info("Starting conversation")
        conv = Conversation(self.idp, self.idp_config,
                            self.interactions, self.json_config,
                            check_factory=self.check_factory,
                            entity_id=self.entity_id,
                            constraints=self.constraints,
                            commandlineargs = self.args)
        try:
            conv.do_sequence_and_tests(oper["sequence"], oper["tests"])
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
                conv.test_output.append({"status": CRITICAL,
                         "name": "test driver error",
                         "id": "critial exception"})
                self.test_log = conv.test_output
                self.test_log.append(exception_trace("RUN", err))
            else:
                self.test_log = exception_trace("RUN", err)
            tsum = self.test_summation(self.args.oper)
            logger.error("Unexpected exception in test driver %s" %
                         traceback.format_exception(*sys.exc_info()))


        if pp:
            pp.pprint(tsum)
        else:
            print >> sys.stdout, json.dumps(tsum)

        if tsum["status"] > 1 or self.args.debug or err:
            self.output_log(memoryhandler, streamhandler)

    def setup(self):
        self.json_config = self.json_config_file()

        _jc = self.json_config

        try:
            self.interactions = _jc["interaction"]
        except KeyError:
            self.interactions = []

        self.idp_configure()

        metadata = MetadataStore(SCHEMA, self.idp_config.attribute_converters,
                                 self.idp_config)
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
        res = []
        for key, val in self.operations.OPERATIONS.items():
            res.append({"id": key, "name": val["name"]})

        print json.dumps(res)

    def verify_metadata(self):
        pass
