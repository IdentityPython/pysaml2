#!/usr/bin/env python

import time
import base64
import sys
import hmac

# from python 2.5
if sys.version_info >= (2,5):
    import hashlib
else: # before python 2.5
    import sha

from saml2 import saml
from saml2 import samlp
from saml2 import VERSION
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
    # Undefined
    Exception: samlp.STATUS_AUTHN_FAILED,
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
    :return: The hex version of the digest, prefixed by 'id-' to make it 
        compliant with the NCName specification
    """
    ident = md5()
    ident.update(repr(time.time()))
    if seed:
        ident.update(seed)
    return "id-"+ident.hexdigest()

def parse_attribute_map(filenames):
    """
    Expects a file with each line being composed of the oid for the attribute
    exactly one space, a user friendly name of the attribute and then
    the type specification of the name.
    
    :param filenames: List of filenames on mapfiles.
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
        
    return forward, backward
    
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
    
def error_status_factory(info):
    if isinstance(info, Exception):
        try:
            exc_val = EXCEPTION2STATUS[info.__class__]
        except KeyError:
            exc_val = samlp.STATUS_AUTHN_FAILED
        msg = info.args[0]
        status = samlp.Status(
            status_message=samlp.StatusMessage(text=msg),
            status_code=samlp.StatusCode(
                value=samlp.STATUS_RESPONDER,
                status_code=samlp.StatusCode(
                    value=exc_val)
                ),
        )
    else:
        (errcode, text) = info
        status = samlp.Status(
            status_message=samlp.StatusMessage(text=text),
            status_code=samlp.StatusCode(
                value=samlp.STATUS_RESPONDER,
                status_code=samlp.StatusCode(value=errcode)
                ),
        )
        
    return status
        
def success_status_factory():
    return samlp.Status(status_code=samlp.StatusCode(
                                            value=samlp.STATUS_SUCCESS))
                                
def status_message_factory(message, code, fro=samlp.STATUS_RESPONDER):
    return samlp.Status(
        status_message=samlp.StatusMessage(text=message),
        status_code=samlp.StatusCode(
                        value=fro,
                        status_code=samlp.StatusCode(value=code)))
    
def assertion_factory(**kwargs):
    assertion = saml.Assertion(version=VERSION, id=sid(),
                                issue_instant=instant())
    for key, val in kwargs.items():
        setattr(assertion, key, val)
    return assertion

def _attrval(val, typ=""):
    if isinstance(val, list) or isinstance(val, set):
        attrval = [saml.AttributeValue(text=v) for v in val]
    elif val is None:
        attrval = None
    else:
        attrval = [saml.AttributeValue(text=val)]

    if typ:
        for ava in attrval:
            ava.set_type(typ)
            
    return attrval

# --- attribute profiles -----

# xmlns:xs="http://www.w3.org/2001/XMLSchema"
# xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"

def do_ava(val, typ=""):
    if isinstance(val, basestring):
        ava = saml.AttributeValue()
        ava.set_text(val)
        attrval = [ava]
    elif isinstance(val, list):
        attrval = [do_ava(v)[0] for v in val]
    elif val or val == False:
        ava = saml.AttributeValue()
        ava.set_text(val)        
        attrval = [ava]
    elif val is None:
        attrval = None
    else:
        raise OtherError("strange value type on: %s" % val)

    if typ:
        for ava in attrval:
            ava.set_type(typ)

    return attrval
    
def do_attribute(val, typ, key):
    attr = saml.Attribute()
    attrval = do_ava(val, typ)
    if attrval:
        attr.attribute_value = attrval

    if isinstance(key, basestring):
        attr.name = key
    elif isinstance(key, tuple): # 3-tuple or 2-tuple
        try:
            (name, nformat, friendly) = key
        except ValueError:
            (name, nformat) = key
            friendly = ""
        if name:
            attr.name = name
        if format:
            attr.name_format = nformat
        if friendly:
            attr.friendly_name = friendly
    return attr
    
def do_attributes(identity):
    attrs = []
    if not identity:
        return attrs
    for key, spec in identity.items():
        try:
            val, typ = spec
        except ValueError:
            val = spec
            typ = ""
        except TypeError: 
            val = ""
            typ = ""
            
        attr = do_attribute(val, typ, key)
        attrs.append(attr)
    return attrs
    
def do_attribute_statement(identity):
    """
    :param identity: A dictionary with fiendly names as keys
    :return:
    """
    return saml.AttributeStatement(attribute=do_attributes(identity))

def factory(klass, **kwargs):
    instance = klass()
    for key, val in kwargs.items():
        setattr(instance, key, val)
    return instance

def signature(secret, parts):
    """Generates a signature.
    """
    if sys.version_info >= (2, 5):
        csum = hmac.new(secret, digestmod=hashlib.sha1)
    else:
        csum = hmac.new(secret, digestmod=sha)

    for part in parts:
        csum.update(part)

    return csum.hexdigest()

def verify_signature(secret, parts):
    """ Checks that the signature is correct """
    if signature(secret, parts[:-1]) == parts[-1]:
        return True
    else:
        return False
