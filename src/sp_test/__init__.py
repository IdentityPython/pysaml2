from importlib import import_module
import json
import argparse
from idp_test import Trace
import sys
from saml2.config import IdPConfig

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
        self._parser.add_argument("-c", dest="idpconfig", default="config_file",
                                  help="Configuration file for the IdP")
        self._parser.add_argument(
            "-P", dest="configpath", default=".",
            help="Path to the configuration file for the IdP")
        self._parser.add_argument("-t", dest="testpackage",
                                  help="Module describing tests")
        self._parser.add_argument("oper", nargs="?", help="Which test to run")

        self.interactions = None
        self.entity_id = None
        self.sp_config = None
        self.constraints = {}
        self.args = None

    def json_config_file(self):
        if self.args.json_config_file == "-":
            return json.loads(sys.stdin.read())
        else:
            return json.loads(open(self.args.json_config_file).read())

    def idp_configure(self, metadata_construction=False):
        sys.path.insert(0, self.args.configpath)
        mod = import_module(self.args.spconfig)
        self.idp_config = IdPConfig().load(mod.CONFIG, metadata_construction)
