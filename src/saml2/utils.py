#!/usr/bin/env python

import time
import base64
from saml2 import samlp, saml, VERSION, sigver
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
}

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

def make_vals(val, klass, klass_inst=None, prop=None, part=False):
    """
    Creates a class instance with a specified value, the specified
    class instance are a value on a property in a defined class instance.
    
    :param klass_inst: The class instance which has a property on which 
        what this function returns is a value.
    :param val: The value
    :param prop: The property which the value should be assigned to.
    :param klass: The value class
    :param part: If the value is one of a possible list of values it should be
        handled slightly different compared to if it isn't.
    :return: Value class instance
    """
    cinst = None
    #print "_make_val: %s %s (%s) [%s]" % (prop,val,klass,part)
    if isinstance(val, bool):
        cinst = klass(text="%s" % val)
    elif isinstance(val, int):
        cinst = klass(text="%d" % val)
    elif isinstance(val, basestring):
        cinst = klass(text=val)
    elif val == None:
        cinst = klass()
    elif isinstance(val, dict):
        cinst = make_instance(klass, val)
    elif not part:
        cis = [make_vals(sval, klass, klass_inst, prop, True) for sval in val]
        setattr(klass_inst, prop, cis)
    else:
        raise ValueError("strange instance type: %s on %s" % (type(val), val))
        
    if part:
        return cinst
    else:        
        if cinst:
            cis = [cinst]
            setattr(klass_inst, prop, cis)
    
def make_instance(klass, spec):
    """
    Constructs a class instance containing the specified information
    
    :param klass: The class
    :param spec: Information to be placed in the instance
    :return: The instance
    """
    #print "----- %s -----" % klass
    #print "..... %s ....." % spec
    klass_inst = klass()
    for prop in klass.c_attributes.values():
        #print "# %s" % (prop)
        if prop in spec:
            if isinstance(spec[prop], bool):
                setattr(klass_inst, prop,"%s" % spec[prop])
            elif isinstance(spec[prop], int):
                setattr(klass_inst, prop, "%d" % spec[prop])
            else:
                setattr(klass_inst, prop, spec[prop])
    if "text" in spec:
        setattr(klass_inst, "text", spec["text"])
        
    for prop, klass in klass.c_children.values():
        #print "## %s, %s" % (prop, klass)
        if prop in spec:
            #print "%s" % spec[prop]
            if isinstance(klass, list): # means there can be a list of values
                make_vals(spec[prop], klass[0], klass_inst, prop)
            else:
                cis = make_vals(spec[prop], klass, klass_inst, prop, True)
                setattr(klass_inst, prop, cis)
    #+print ">>> %s <<<" % klass_inst
    return klass_inst

def parse_attribute_map(filenames):
    """
    Expects a file with each line being composed of the oid for the attribute
    exactly one space and then a user friendly name of the attribute
    
    :param filename: List of filenames on mapfiles.
    :return: A 2-tuple, one dictionary with the oid as keys and the friendly 
        names as values, the other one the other way around.
    """
    forward = {}
    backward = {}
    for filename in filenames:
        for line in open(filename).readlines():
            (name, friendly_name) = line.strip().split(" ")
            forward[name] = friendly_name
            backward[friendly_name] = name
        
    return (forward, backward)

def filter_attribute_value_assertions(ava, attribute_restrictions=None):
    """ Will weed out attribute values and values according to the 
    rules defined in the attribute restrictions. If filtering results in 
    an attribute without values, then the attribute is removed from the
    assertion.
    
    :param ava: The incoming attribute value assertion
    :param attribute_restrictions: The rules that govern which attributes
        and values that are allowed.
    :return: A attribute value assertion
    """
    if not attribute_restrictions:
        return ava
        
    resava = {}
    for attr, vals in ava.items():
        if attr in attribute_restrictions:
            if attribute_restrictions[attr] == None:
                resava[attr] = vals
            else:    
                rvals = []
                for restr in attribute_restrictions[attr]:
                    for val in vals:
                        if restr.match(val):
                            rvals.append(val)
                
                if rvals:
                    resava[attr] = list(set(rvals))
    return resava
    
def identity_attribute(form, attribute, forward_map=None):
    if form == "friendly":
        if attribute.friendly_name:
            return attribute.friendly_name
        elif forward_map:
            try:
                return forward_map[attribute.name]
            except KeyError:
                return attribute.name
    # default is name
    return attribute.name

def filter_values(vals, required=None, optional=None):
    """ Removes values from *val* that does not appear in *attributes*.
    
    :param val: The values that are to be filtered
    :param required: The requires values
    :param optional: The optional values
    :return: The set of values after filtering
    """

    if not required and not optional:
        return vals
        
    valr = []
    valo = []
    if required:
        rvals = [v.text for v in required]
    else:
        rvals = []
    if optional:
        ovals = [v.text for v in optional]
    else:
        ovals = []
    for val in vals:
        if val in rvals:
            valr.append(val)
        elif val in ovals:
            valo.append(val)

    valo.extend(valr)
    if rvals:
        if len(rvals) == len(valr):
            return valo
        else:
            raise MissingValue("Required attribute value missing")
    else:
        return valo
    
def combine(required=None, optional=None):
    res = {}
    if not required:
        required = []
    if not optional:
        optional = []
    for attr in required:
        part = None
        for oat in optional:
            if attr.name == oat.name:
                part = (attr.attribute_value, oat.attribute_value)
                break
        if part:
            res[(attr.name, attr.friendly_name)] = part
        else:
            res[(attr.name, attr.friendly_name)] = (attr.attribute_value, [])

    for oat in optional:
        tag = (oat.name, oat.friendly_name)
        if tag not in res:
            res[tag] = ([], oat.attribute_value)
            
    return res
    
def filter_on_attributes(ava, required=None, optional=None):
    """ Filter
    :param required: list of RequestedAttribute instances
    """
    res = {}
    comb = combine(required, optional)
    for attr, vals in comb.items():
        if attr[0] in ava:
            res[attr[0]] = filter_values(ava[attr[0]], vals[0], vals[1])
        elif attr[1] in ava:
            res[attr[1]] = filter_values(ava[attr[1]], vals[0], vals[1])
        else:
            raise MissingValue("Required attribute missing")
    
    return res
    

#----------------------------------------------------------------------------

def properties(klass):
    props = [val[0] for _, val in klass.c_children.items()]
    props.extend(klass.c_attributes.values())
    return props
    
def klassdict(klass, text=None, **kwargs):
    spec = {}
    if text:
        spec["text"] = text
    props = properties(klass)
    #print props
    for key, val in kwargs.items():
        #print "?",key
        if key in props:
            spec[key] = val
    return spec
    
def kd_status_from_exception(exception):
    return klassdict(samlp.Status,
        status_code=klassdict(samlp.StatusCode,
            value=samlp.STATUS_RESPONDER,
            status_code=klassdict(samlp.StatusCode,
                            value=EXCEPTION2STATUS[exception.__class__])
            ),
        status_message=exception.args[0],
    )
    
def kd_name_id(text="", **kwargs):
    return klassdict(saml.NameID, text, **kwargs)

def kd_status_message(text="", **kwargs):
    return klassdict(samlp.StatusMessage, text, **kwargs)

def kd_status_code(text="", **kwargs):
    return klassdict(samlp.StatusCode, text, **kwargs)

def kd_status(text="", **kwargs):
    return klassdict(samlp.Status, text, **kwargs)
    
def kd_success_status():
    return kd_status(status_code=kd_status_code(value=samlp.STATUS_SUCCESS))
                            
def kd_audience(text="", **kwargs):
    return klassdict(saml.Audience, text, **kwargs)

def kd_audience_restriction(text="", **kwargs):
    return klassdict(saml.AudienceRestriction, text, **kwargs)

def kd_conditions(text="", **kwargs):
    return klassdict(saml.Conditions, text, **kwargs)
    
def kd_attribute(text="", **kwargs):
    return klassdict(saml.Attribute, text, **kwargs)

def kd_attribute_value(text="", **kwargs):
    return klassdict(saml.AttributeValue, text, **kwargs)
        
def kd_attribute_statement(text="", **kwargs):
    return klassdict(saml.AttributeStatement, text, **kwargs)

def kd_subject_confirmation_data(text="", **kwargs):
    return klassdict(saml.SubjectConfirmationData, text, **kwargs)
    
def kd_subject_confirmation(text="", **kwargs):
    return klassdict(saml.SubjectConfirmation, text, **kwargs)        
    
def kd_subject(text="", **kwargs):
    return klassdict(saml.Subject, text, **kwargs)        

def kd_authn_statement(text="", **kwargs):
    return klassdict(saml.Subject, text, **kwargs)        
    
def kd_assertion(text="", **kwargs):
    kwargs.update({
        "version": VERSION,
        "id" : sid(),
        "issue_instant" : instant(),
    })
    return klassdict(saml.Assertion, text, **kwargs)        
    
def kd_response(signature=False, encrypt=False, **kwargs):
    kwargs.update({
        "id" : sid(),
        "version": VERSION,
        "issue_instant" : instant(),
    })
    if signature:
        kwargs["signature"] = sigver.pre_signature_part(kwargs["id"])
    if encrypt:
        pass
    return kwargs

def do_attributes(identity):
    attrs = []
    for key, val in identity.items():
        dic = {}
        if isinstance(val, basestring):
            attrval = [kd_attribute_value(val)]
        elif isinstance(val, list):
            attrval = [kd_attribute_value(v) for v in val]
        elif val == None:
            attrval = None
        else:
            raise OtherError("strange value type on: %s" % val)
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
        attrs.append(kd_attribute(**dic))
    return attrs
    
def do_attribute_statement(identity):
    """
    :param identity: A dictionary with fiendly names as keys
    :return:
    """
    return kd_attribute_statement(attribute=do_attributes(identity))

def kd_issuer(text, **kwargs):
    return klassdict(saml.Issuer, text, **kwargs)        

