#!/usr/bin/env python
import argparse
import os
import sys

from saml2.cert import read_cert_from_file
from saml2.config import Config
from saml2.metadata import entities_descriptor
from saml2.metadata import entity_descriptor
from saml2.metadata import metadata_tostring_fix
from saml2.metadata import sign_entity_descriptor
from saml2.sigver import make_temp, security_context
from saml2.validate import valid_instance


# =============================================================================
# Script that creates a SAML2 metadata file from a pysaml2 entity configuration
# file
# =============================================================================


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", dest="valid", help="How long, in days, the metadata is valid from the time of creation")
    parser.add_argument("-c", dest="certfile", help="certificate as a file")
    parser.add_argument("-d", dest="certdata", help="certificate as a string")
    parser.add_argument("-e", dest="ed", action="store_true", help="Wrap the whole thing in an EntitiesDescriptor")
    parser.add_argument("-i", dest="id", help="The ID of the entities descriptor")
    parser.add_argument("-k", dest="keyfile", help="A file with a key to sign the metadata with")
    parser.add_argument("-y", dest="keydata", help="A string key to sign the metadata with")
    parser.add_argument("-n", dest="name", default="")
    parser.add_argument("-p", dest="path", help="path to the configuration file")
    parser.add_argument("-s", dest="sign", action="store_true", help="sign the metadata")
    parser.add_argument("-x", dest="xmlsec", help="xmlsec binaries to be used for the signing")
    parser.add_argument("-w", dest="wellknown", help="Use wellknown namespace prefixes")
    parser.add_argument(dest="config", nargs="+")
    args = parser.parse_args()

    valid_for = 0
    nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
    # paths = [".", "/opt/local/bin"]

    if args.valid:
        # translate into hours
        valid_for = int(args.valid) * 24

    eds = []
    for filespec in args.config:
        bas, fil = os.path.split(filespec)
        if bas != "":
            sys.path.insert(0, bas)
        if fil.endswith(".py"):
            fil = fil[:-3]
        cnf = Config().load_file(fil)
        if valid_for:
            cnf.valid_for = valid_for
        eds.append(entity_descriptor(cnf))

    conf = Config()
    if args.keyfile and not args.keydata:
        conf.key_file = args.keyfile
        with open(args.keyfile) as kf: conf.key_data = kf.read()
    elif args.keydata and not args.keyfile:
        conf.key_data = args.keydata
        key_file_tmp = make_temp(args.keydata, suffix=".key", decode=False)
        conf.key_file = key_file_tmp.name
    else:
        conf.key_file = args.keyfile
        conf.key_data = args.keydata
    if args.certfile and not args.certdata:
        conf.cert_file = args.certfile
        conf.cert_data = read_cert_from_file(args.certfile)
    elif args.certdata and not args.certfile:
        conf.cert_data = args.certdata
        cert_file_tmp = make_temp(args.certdata, suffix=".crt", decode=False)
        conf.cert_file = cert_file_tmp.name
    else:
        conf.cert_file = args.certfile
        conf.cert_data = args.certdata
    conf.debug = 1
    conf.xmlsec_binary = args.xmlsec
    secc = security_context(conf)

    if args.id:
        desc, xmldoc = entities_descriptor(eds, valid_for, args.name, args.id, args.sign, secc)
        valid_instance(desc)
        xmldoc = metadata_tostring_fix(desc, nspair, xmldoc)
        print(xmldoc.decode("utf-8"))
    else:
        for eid in eds:
            if args.sign:
                assert conf.key_file
                assert conf.cert_file
                eid, xmldoc = sign_entity_descriptor(eid, args.id, secc)
            else:
                xmldoc = None

            valid_instance(eid)
            xmldoc = metadata_tostring_fix(eid, nspair, xmldoc)
            print(xmldoc.decode("utf-8"))


if __name__ == "__main__":
    main()
