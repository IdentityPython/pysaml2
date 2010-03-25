#!/usr/bin/env python

import time
import base64
import re
from saml2 import samlp, saml, VERSION, sigver, NAME_FORMAT_URI
from saml2.time_util import instant

try:
    from hashlib import md5
except ImportError:
    from md5 import md5
import zlib

class VersionMismatch(Exception):
    pass
    
class UnknownPrincipal(Exception):
    pass
    
class UnsupportedBinding(Exception):
    pass

class OtherError(Exception):
    pass

class MissingValue(Exception):
    pass

    
EXCEPTION2STATUS = {
    VersionMismatch: samlp.STATUS_VERSION_MISMATCH,
    UnknownPrincipal: samlp.STATUS_UNKNOWN_PRINCIPAL,
    UnsupportedBinding: samlp.STATUS_UNSUPPORTED_BINDING,
    OtherError: samlp.STATUS_UNKNOWN_PRINCIPAL,
    MissingValue: samlp.STATUS_REQUEST_UNSUPPORTED,
}

GENERIC_DOMAINS = "aero", "asia", "biz", "cat", "com", "coop", \
        "edu", "gov", "info", "int", "jobs", "mil", "mobi", "museum", \
        "name", "net", "org", "pro", "tel", "travel"

def valid_email(emailaddress, domains = GENERIC_DOMAINS):
    """Checks for a syntactically valid email address."""

    # Email address must be at least 6 characters in total.
    # Assuming noone may have addresses of the type a@com
    if len(emailaddress) < 6:
        return False # Address too short.

    # Split up email address into parts.
    try:
        localpart, domainname = emailaddress.rsplit('@', 1)
        host, toplevel = domainname.rsplit('.', 1)
    except ValueError:
        return False # Address does not have enough parts.

    # Check for Country code or Generic Domain.
    if len(toplevel) != 2 and toplevel not in domains:
        return False # Not a domain name.

    for i in '-_.%+.':
        localpart = localpart.replace(i, "")
    for i in '-_.':
        host = host.replace(i, "")

    if localpart.isalnum() and host.isalnum():
        return True # Email address is fine.
    else:
        return False # Email address has funny characters.
            
def decode_base64_and_inflate( string ):
    """ base64 decodes and then inflates according to RFC1951 
    
    :param string: a deflated and encoded string
    :return: the string after decoding and inflating
    """

    return zlib.decompress( base64.b64decode( string ) , -15)

def deflate_and_base64_encode( string_val ):
    """
    Deflates and the base64 encodes a string
    
    :param string_val: The string to deflate and encode
    :return: The deflated and encoded string
    """
    return base64.b64encode( zlib.compress( string_val )[2:-4] )
    
def sid(seed=""):
    """The hash of the server time + seed makes an unique SID for each session.
    
    :param seed: A seed string
    :return: The hex version of the digest
    """
    ident = md5()
    ident.update(repr(time.time()))
    if seed:
        ident.update(seed)
    return ident.hexdigest()

def parse_attribute_map(filenames):
    """
    Expects a file with each line being composed of the oid for the attribute
    exactly one space, a user friendly name of the attribute and then
    the type specification of the name.
    
    :param filename: List of filenames on mapfiles.
    :return: A 2-tuple, one dictionary with the oid as keys and the friendly 
        names as values, the other one the other way around.
    """
    forward = {}
    backward = {}
    for filename in filenames:
        for line in open(filename).readlines():
            (name, friendly_name, name_format) = line.strip().split()
            forward[(name, name_format)] = friendly_name
            backward[friendly_name] = (name, name_format)
        
    return (forward, backward)
    
def identity_attribute(form, attribute, forward_map=None):
    if form == "friendly":
        if attribute.friendly_name:
            return attribute.friendly_name
        elif forward_map:
            try:
                return forward_map[(attribute.name, attribute.name_format)]
            except KeyError:
                return attribute.name
    # default is name
    return attribute.name        

#----------------------------------------------------------------------------

def _properties(klass):
    props = [val[0] for _, val in klass.c_children.items()]
    props.extend(klass.c_attributes.values())
    return props
    
def args2dict(text=None, **kwargs):
    spec = kwargs.copy()
    if text != None:
        spec["text"] = text
    return spec

def _klassdict(klass, text=None, **kwargs):
    """ Does not remove attributes with no values """
    spec = {}
    if text:
        spec["text"] = text
    props = _properties(klass)
    #print props
    for key, val in kwargs.items():
        #print "?",key
        if key in props:
            spec[key] = val
    return spec
    
def status_from_exception_factory(exception):
    msg = exception.args[0]
    return args2dict(
        status_message=msg,
        status_code=args2dict(
            value=samlp.STATUS_RESPONDER,
            status_code=args2dict(value=EXCEPTION2STATUS[exception.__class__])
            ),
    )
        
def success_status_factory():
    return args2dict(status_code=args2dict(value=samlp.STATUS_SUCCESS))
                                
def assertion_factory(text="", **kwargs):
    kwargs.update({
        "version": VERSION,
        "id" : sid(),
        "issue_instant" : instant(),
    })
    return args2dict(text, **kwargs)        
    
def response_factory(signature=False, encrypt=False, **kwargs):
    kwargs.update({
        "id" : sid(),
        "version": VERSION,
        "issue_instant" : instant(),
    })
    if signature:
        kwargs["signature"] = sigver.pre_signature_part(kwargs["id"])
    if encrypt:
        pass
    return args2dict(**kwargs)        

def _attrval(val):
    if isinstance(val, list) or isinstance(val,set):
        attrval = [args2dict(v) for v in val]
    elif val == None:
        attrval = None
    else:
        attrval = [args2dict(val)]

    return attrval

# --- attribute profiles -----

# xmlns:xs="http://www.w3.org/2001/XMLSchema"
# xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"

def _basic_val(val):
    if isinstance(val, basestring):
        attrval = [args2dict(val, type="xs:string")]
    elif isinstance(val, int):
        attrval = [args2dict(val, type="xs:integer")]
    elif isinstance(val, list):
        attrval = [_basic_val(v) for v in val]
    elif val == None:
        attrval = None
    else:
        raise OtherError("strange value type on: %s" % val)

    return attrval
    
def do_attributes(identity):
    attrs = []
    if not identity:
        return attrs
    for key, val in identity.items():
        dic = {}

        attrval = _attrval(val)
        if attrval:
            dic["attribute_value"] = attrval

        if isinstance(key, basestring):
            dic["name"] = key
        elif isinstance(key, tuple): # 3-tuple
            try:
                (name, nformat, friendly) = key
            except ValueError:
                (name, nformat) = key
                friendly = ""
            if name:
                dic["name"] = name
            if format:
                dic["name_format"] = nformat
            if friendly:
                dic["friendly_name"] = friendly
        attrs.append(args2dict(**dic))
    return attrs
    
def do_attribute_statement(identity):
    """
    :param identity: A dictionary with fiendly names as keys
    :return:
    """
    return args2dict(attribute=do_attributes(identity))

