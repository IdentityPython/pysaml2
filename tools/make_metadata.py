#!/usr/bin/env python
import os 
import getopt
import sys

from saml2.metadata import entity_descriptor, entities_descriptor
from saml2.metadata import sign_entity_descriptor
from saml2.sigver import SecurityContext
from saml2.sigver import get_xmlsec_binary
from saml2.validate import valid_instance
from saml2.config import Config

HELP_MESSAGE = """
Usage: make_metadata [options] 1*configurationfile

Valid options:
c:hi:k:np:sv:x:
  -c            : certificate
  -e            : Wrap the whole thing in an EntitiesDescriptor
  -h            : Print this help message
  -i id         : The ID of the entities descriptor
  -k keyfile    : A file with a key to sign the metadata with
  -n            : name
  -p            : path to the configuration file
  -s            : sign the metadata
  -v            : How long, in days, the metadata is valid from the 
                    time of creation
  -x            : xmlsec1 binaries to be used for the signing
  -w            : Use wellknown namespace prefixes
"""

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

NSPAIR = {
    "saml2p":"urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2":"urn:oasis:names:tc:SAML:2.0:assertion",
    "soap11":"http://schemas.xmlsoap.org/soap/envelope/",
    "meta": "urn:oasis:names:tc:SAML:2.0:metadata",
    "xsi":"http://www.w3.org/2001/XMLSchema-instance",
    "ds":"http://www.w3.org/2000/09/xmldsig#",
    "shibmd":"urn:mace:shibboleth:metadata:1.0",
    "md":"urn:oasis:names:tc:SAML:2.0:metadata",
}

def main(args):
    try:
        opts, args = getopt.getopt(args, "c:ehi:k:np:sv:wx",
                        ["help", "name", "id", "keyfile", "sign", 
                        "valid", "xmlsec", "entityid", "path"])
    except getopt.GetoptError, err:
        # print help information and exit:
        raise Usage(err) # will print something like "option -a not recognized"

    output = None
    verbose = False
    valid_for = 0
    name = ""
    id = ""
    sign = False
    xmlsec = ""
    keyfile = ""
    pubkeyfile = ""
    entitiesid = True
    path = []
    nspair = None
    
    try:
        for o, a in opts:
            if o in ("-v", "--valid"):
                valid_for = int(a) * 24
            elif o in ("-h", "--help"):
                raise Usage(HELP_MESSAGE)
            elif o in ("-n", "--name"):
                name = a
            elif o in ("-i", "--id"):
                id = a
            elif o in ("-s", "--sign"):
                sign = True
            elif o in ("-x", "--xmlsec"):
                xmlsec = a
            elif o in ("-k", "--keyfile"):
                keyfile = a
            elif o in ("-c", "--certfile"):
                pubkeyfile = a
            elif o in ("-e", "--entityid"):
                entitiesid = False
            elif o in ("-p", "--path"):
                path = [x.strip() for x in a.split(":")]
            elif o in ("-w",):
                nspair = NSPAIR
            else:
                assert False, "unhandled option %s" % o
    except Usage, err:
        print >> sys.stderr, sys.argv[0].split("/")[-1] + ": " + str(err.msg)
        print >> sys.stderr, "\t for help use --help"
        return 2

    if not xmlsec:
        xmlsec = get_xmlsec_binary(path)
        
    eds = []
    for filespec in args:
        bas, fil = os.path.split(filespec)
        if bas != "":
            sys.path.insert(0, bas)
        if fil.endswith(".py"):
            fil = fil[:-3]
        cnf = Config().load_file(fil, metadata_construction=True)
        eds.append(entity_descriptor(cnf, valid_for))

    secc = SecurityContext(xmlsec, keyfile, cert_file=pubkeyfile)
    if entitiesid:
        desc = entities_descriptor(eds, valid_for, name, id, sign, secc)
        valid_instance(desc)
        print desc.to_string(nspair)
    else:
        for eid in eds:
            if sign:
                desc = sign_entity_descriptor(eid, valid_for, id, secc)
            else:
                desc = eid
            valid_instance(desc)
            print desc.to_string(nspair)

if __name__ == "__main__":
    import sys
    
    main(sys.argv[1:])
