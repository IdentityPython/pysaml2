#!/usr/bin/env python

import time
import base64

try:
    from hashlib import md5
except ImportError:
    from md5 import md5
import zlib

import zlib
import base64

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
    """
    sid = md5()
    sid.update(repr(time.time()))
    if seed:
        sid.update(seed)
    return sid.hexdigest()

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
    ci = None
    #print "_make_val: %s %s (%s)" % (prop,val,klass)
    if isinstance(val, bool):
        ci = klass(text="%s" % val)
    elif isinstance(val, int):
        ci = klass(text="%d" % val)
    elif isinstance(val, basestring):
        ci = klass(text=val)
    elif val == None:
        ci = klass()
    elif isinstance(val, dict):
        ci = make_instance(klass, val)
    elif not part:
        cis = [make_vals(sval, klass, klass_inst, prop, True) for sval in val]
        setattr(klass_inst, prop, cis)
    else:
        raise ValueError("strange instance type: %s on %s" % (type(val),val))
        
    if part:
        return ci
    else:        
        if ci:
            cis = [ci]
        setattr(klass_inst, prop, cis)
    
def make_instance(klass, spec):
    """
    Constructs a class instance containing the specified information
    
    :param klass: The class
    :param spec: Information to be placed in the instance
    :return: The instance
    """
    klass_inst = klass()
    for prop in klass.c_attributes.values():
        if prop in spec:
            if isinstance(spec[prop],bool):
                setattr(klass_inst,prop,"%s" % spec[prop])
            elif isinstance(spec[prop], int):
                setattr(klass_inst,prop,"%d" % spec[prop])
            else:
                setattr(klass_inst,prop,spec[prop])
    if "text" in spec:
        setattr(klass_inst,"text",spec["text"])
        
    for prop, klass in klass.c_children.values():
        if prop in spec:
            if isinstance(klass, list): # means there can be a list of values
                make_vals(spec[prop], klass[0], klass_inst, prop)
            else:
                ci = make_vals(spec[prop], klass, klass_inst, prop, True)
                setattr(klass_inst, prop, ci)
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
    for attr,vals in ava.items():
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
