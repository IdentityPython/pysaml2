from importlib import import_module
import json
import argparse
import sys
import time

import logging

from saml2.config import SPConfig

from idp_test.base import FatalError
from idp_test.base import do_sequence
from idp_test.check import CheckSaml2IntMetaData
#from saml2.config import Config
from saml2.mdstore import MetadataStore, MetaData

# Schemas supported
from saml2 import md
from saml2 import saml
from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
from saml2.metadata import entity_descriptor
import xmldsig
import xmlenc

SCHEMA = [dri, idpdisc, md, mdattr, mdui, saml, ui, xmldsig, xmlenc]

__author__ = 'rolandh'

import traceback

logger = logging.getLogger("")

def exception_trace(tag, exc, log=None):
    message = traceback.format_exception(*sys.exc_info())
    if log:
        log.error("[%s] ExcList: %s" % (tag, "".join(message),))
        log.error("[%s] Exception: %s" % (tag, exc))
    else:
        print >> sys.stderr, "[%s] ExcList: %s" % (tag, "".join(message),)
        print >> sys.stderr, "[%s] Exception: %s" % (tag, exc)

class Trace(object):
    def __init__(self):
        self.trace = []
        self.start = time.time()

    def request(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f --> %s" % (delta, msg))

    def reply(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f <-- %s" % (delta, msg))

    def info(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f %s" % (delta, msg))

    def error(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f [ERROR] %s" % (delta, msg))

    def warning(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f [WARNING] %s" % (delta, msg))

    def __str__(self):
        try:
            return "\n".join([t.encode("utf-8") for t in self.trace])
        except UnicodeDecodeError:
            arr = []
            for t in self.trace:
                try:
                    arr.append(t.encode("utf-8"))
                except UnicodeDecodeError:
                    arr.append(t)
        return "\n".join(arr)

    def clear(self):
        self.trace = []

    def __getitem__(self, item):
        return self.trace[item]

    def next(self):
        for line in self.trace:
            yield line

class SAML2client(object):

    def __init__(self, operations):
        self.trace = Trace()
        self.operations = operations
        self.tests = None

        self._parser = argparse.ArgumentParser()
        self._parser.add_argument('-d', dest='debug', action='store_true',
                                  help="Print debug information")
        self._parser.add_argument('-v', dest='verbose', action='store_true',
                                  help="Print runtime information")
        self._parser.add_argument('-C', dest="ca_certs",
                                  help="CA certs to use to verify HTTPS server certificates, if HTTPS is used and no server CA certs are defined then no cert verification will be done")
        self._parser.add_argument('-J', dest="json_config_file",
                                  help="Script configuration")
        self._parser.add_argument('-m', dest="metadata", action='store_true',
                                  help="Return the SP metadata")
        self._parser.add_argument("-l", dest="list", action="store_true",
                                  help="List all the test flows as a JSON object")
        self._parser.add_argument("-c", dest="spconfig", default="config_file",
                                  help="Configuration file for the SP")
        self._parser.add_argument("-P", dest="configpath", default=".",
                                  help="Path to the configuration file for the SP")
        self._parser.add_argument("-t", dest="testdefs",
                                  help="Module describing the tests")
        self._parser.add_argument("oper", nargs="?", help="Which test to run")

        self.interactions = None
        self.entity_id = None
        self.sp_config = None

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
        self.json_config= self.json_config_file()

        _jc = self.json_config

        self.interactions = _jc["interaction"]

        self.sp_configure()

        metadata = MetadataStore(SCHEMA, self.sp_config.attribute_converters,
                                 self.sp_config.xmlsec_binary)
        info = _jc["metadata"].encode("utf-8")
        md = MetaData(SCHEMA, self.sp_config.attribute_converters, info)
        md.load()
        metadata[0] = md
        self.sp_config.metadata = metadata

        if self.args.testdefs:
            self.tests = import_module("idp_test.%s" % self.args.testdefs)

        try:
            self.entity_id = _jc["entity_id"]
            # Verify its the correct metadata
            assert self.entity_id in md.entity.keys()
        except KeyError:
            if len(md.entity.keys()) == 1:
                self.entity_id = md.entity.keys()[0]
            else:
                raise Exception("Don't know which entity to talk to")

    def test_summation(self, id):
        status = 0
        for item in self.test_log:
            if item["status"] > status:
                status = item["status"]

        if status == 0:
            status = 1

        sum = {
            "id": id,
            "status": status,
            "tests": self.test_log
        }

        if status == 5:
            sum["url"] = self.test_log[-1]["url"]
            sum["htmlbody"] = self.test_log[-1]["message"]

        return sum

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

            testres, trace = do_sequence(self.sp_config, oper,
                                         self.trace, self.interactions,
                                         entity_id=self.json_config["entity_id"])
            self.test_log = testres
            sum = self.test_summation(self.args.oper)
            print >>sys.stdout, json.dumps(sum)
            if sum["status"] > 1 or self.args.debug:
                print >> sys.stderr, trace
        except FatalError, err:
            print >> sys.stderr, self.trace
            print err
            #exception_trace("RUN", err)
        except Exception, err:
            print >> sys.stderr, self.trace
            print err
            exception_trace("RUN", err)

    def list_operations(self):
        lista = []
        for key,val in self.operations.OPERATIONS.items():
            item = {"id": key,
                    "name": val["name"],}
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
        if self.args.testdefs:
            mod = import_module(self.args.testdefs, "idp_test")
            for key,val in mod.OPERATIONS.items():
                item = {"id": key,
                        "name": val["name"],}
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
        _res = dict([(key, cnf["description"]) for key, cnf in mod.CONFIG.items()])
        print json.dumps(_res)

    def verify_metadata(self):
        self.json_config= self.json_config_file()
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
