#!/usr/bin/env python
import argparse
import os 
import sys
from saml2.metadata import entity_descriptor
from saml2.metadata import entities_descriptor
from saml2.metadata import sign_entity_descriptor

from saml2.sigver import SecurityContext
from saml2.sigver import get_xmlsec_binary
from saml2.validate import valid_instance
from saml2.config import Config

# =============================================================================
# Script that creates a SAML2 metadata file from a pysaml2 entity configuration
# file
# =============================================================================

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='valid',
                    help="How long, in days, the metadata is valid from the time of creation")
parser.add_argument('-c', dest='cert', help='certificate')
parser.add_argument('-e', dest='ed', action='store_true',
                    help="Wrap the whole thing in an EntitiesDescriptor")
parser.add_argument('-i', dest='id',
                    help="The ID of the entities descriptor")
parser.add_argument('-k', dest='keyfile',
                    help="A file with a key to sign the metadata with")
parser.add_argument('-n', dest='name', default="")
parser.add_argument('-p', dest='path',
                    help="path to the configuration file")
parser.add_argument('-s', dest='sign', action='store_true',
                    help="sign the metadata")
parser.add_argument('-x', dest='xmlsec',
                    help="xmlsec binaries to be used for the signing")
parser.add_argument('-w', dest='wellknown',
                    help="Use wellknown namespace prefixes")
parser.add_argument(dest="config", nargs="+")
args = parser.parse_args()

valid_for = 0
nspair = None
paths = [".", "/opt/local/bin"]

if args.valid:
    # translate into hours
    valid_for = int(args.valid) * 24
if args.xmlsec:
    xmlsec = args.xmlsec
else:
    xmlsec = get_xmlsec_binary(paths)

eds = []
for filespec in args.config:
    bas, fil = os.path.split(filespec)
    if bas != "":
        sys.path.insert(0, bas)
    if fil.endswith(".py"):
        fil = fil[:-3]
    cnf = Config().load_file(fil, metadata_construction=True)
    eds.append(entity_descriptor(cnf))

secc = SecurityContext(xmlsec, args.keyfile, cert_file=args.cert)
if args.id:
    desc = entities_descriptor(eds, valid_for, args.name, args.id,
                               args.sign, secc)
    valid_instance(desc)
    print desc.to_string(nspair)
else:
    for eid in eds:
        if args.sign:
            desc = sign_entity_descriptor(eid, id, secc)
        else:
            desc = eid
        valid_instance(desc)
        print desc.to_string(nspair)

