import calendar
import sys
import urlparse
import re
import time_util
import struct
import base64


class NotValid(Exception):
    pass

class OutsideCardinality(Exception):
    pass

# --------------------- validators -------------------------------------
# 
def valid_ncname(name):
    exp = re.compile("(?P<NCName>[a-zA-Z_](\w|[_.-])*)")
    match = exp.match(name)
    if not match:
        raise NotValid("NCName")
    return True
    
def valid_id(oid):
    valid_ncname(oid)
    
def valid_any_uri(item):
    """very simplistic, ..."""
    try:
        part = urlparse.urlparse(item)
    except Exception:
        raise NotValid("AnyURI")

    if part[0] == "urn" and part[1] == "": # A urn
        return True
    # elif part[1] == "localhost" or part[1] == "127.0.0.1":
    #     raise NotValid("AnyURI")

    return True
    
def valid_date_time(item):
    try:
        time_util.str_to_time(item)
    except Exception:
        raise NotValid("dateTime")
    return True
    
def valid_url(url):
    try:
        part = urlparse.urlparse(url)
    except Exception:
        raise NotValid("URL")
        
    # if part[1] == "localhost" or part[1] == "127.0.0.1":
    #     raise NotValid("URL")
    return True
    
def validate_on_or_after(not_on_or_after, slack):
    if not_on_or_after:
        now = time_util.utc_now()
        nooa = calendar.timegm(time_util.str_to_time(not_on_or_after))
        if now > nooa + slack:
            raise Exception("Can't use it, it's too old %d > %d" %
                            (nooa, now))
        return nooa
    else:
        return False

def validate_before(not_before, slack):
    if not_before:
        now = time_util.utc_now()
        nbefore = calendar.timegm(time_util.str_to_time(not_before))
        if nbefore > now + slack:
            raise Exception("Can't use it yet %d <= %d" % (nbefore, now))

    return True

def valid_address(address):
    if not (valid_ipv4(address) or valid_ipv6(address)):
        raise NotValid("address")
    return True
    
def valid_ipv4(address):
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        try:
            if not 0 <= int(item) <= 255:
                raise NotValid("ipv4")
        except ValueError:
            return False
    return True
    
# 
IPV6_PATTERN = re.compile(r"""
    ^
    \s*                         # Leading whitespace
    (?!.*::.*::)                # Only a single wildcard allowed
    (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
    (?:                         # Repeat 6 times:
        [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
        (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
    ){6}                        #
    (?:                         # Either
        [0-9a-f]{0,4}           #   Another group
        (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
        [0-9a-f]{0,4}           #   Last group
        (?: (?<=::)             #   Colon iff preceeded by exacly one colon
         |  (?<!:)              #
         |  (?<=:) (?<!::) :    #
         )                      # OR
     |                          #   A v4 address with NO leading zeros 
        (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
        (?: \.
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
        ){3}
    )
    \s*                         # Trailing whitespace
    $
""", re.VERBOSE | re.IGNORECASE | re.DOTALL)
    
def valid_ipv6(address):
    """Validates IPv6 addresses. """
    return IPV6_PATTERN.match(address) is not None

def valid_boolean(val):
    vall = val.lower()
    if vall in ["true", "false", "0", "1"]:
        return True
    else:
        raise NotValid("boolean")
        
def valid_duration(val):
    try:
        time_util.parse_duration(val)
    except Exception:
        raise NotValid("duration")
    return True

def valid_string(val):
    """ Expects unicode 
    Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | 
                    [#x10000-#x10FFFF]
    """
    for char in val:
        try:
            char = ord(char)
        except TypeError:
            raise NotValid("string")
        if char == 0x09 or char == 0x0A or char == 0x0D:
            continue
        elif char >= 0x20 and char <= 0xD7FF:
            continue
        elif char >= 0xE000 and char <= 0xFFFD:
            continue
        elif char >= 0x10000 and char <= 0x10FFFF:
            continue
        else:
            raise NotValid("string")
    return True
    
def valid_unsigned_short(val):
    try:
        struct.pack("H", int(val))
    except struct.error:
        raise NotValid("unsigned short")
    except ValueError:
        raise NotValid("unsigned short")
        
    return True
    
def valid_non_negative_integer(val):
    try:
        integer = int(val)
    except ValueError:
        raise NotValid("non negative integer")
        
    if integer < 0:
        raise NotValid("non negative integer")
    return True

def valid_integer(val):
    try:
        int(val)
    except ValueError:
        raise NotValid("integer")
    return True
    
def valid_base64(val):
    try:
        base64.b64decode(val)
    except Exception:
        raise NotValid("base64")
    return True

def valid_qname(val):
    """ A qname is either 
        NCName or 
        NCName ':' NCName
    """
    
    try:
        (prefix, localpart) = val.split(":")
        return valid_ncname(prefix) and valid_ncname(localpart)
    except ValueError:
        return valid_ncname(val)

def valid_anytype(val):
    """ Goes through all known type validators 
    
    :param val: The value to validate
    :return: True is value is valid otherwise an exception is raised
    """
    for validator in VALIDATOR.values():
        try:
            if validator(val):
                return True
        except NotValid:
            pass
    
    if isinstance(val, type):
        return True
        
    raise NotValid("AnyType")
    
# -----------------------------------------------------------------------------

VALIDATOR = {
    "ID": valid_id,
    "NCName": valid_ncname,
    "dateTime": valid_date_time,
    "anyURI": valid_any_uri,
    "nonNegativeInteger": valid_non_negative_integer,
    "boolean": valid_boolean,
    "unsignedShort": valid_unsigned_short,
    "duration": valid_duration,
    "base64Binary": valid_base64,
    "integer": valid_integer,
    "QName": valid_qname,
    "anyType": valid_anytype,
    "string": valid_string,
}

# -----------------------------------------------------------------------------

def validate_value_type(value, spec):
    """
    c_value_type = {'base': 'string', 'enumeration': ['Permit', 'Deny', 'Indeterminate']}
        {'member': 'anyURI', 'base': 'list'}
        {'base': 'anyURI'}
        {'base': 'NCName'}
        {'base': 'string'}
    """
    if "maxlen" in spec:
        return len(value) <= spec["maxlen"]
        
    if spec["base"] == "string":
        if "enumeration" in spec:
            if value not in spec["enumeration"]:
                raise NotValid("value not in enumeration")
        else:
            return valid_string(value)
    elif spec["base"] == "list": #comma separated list of values
        for val in [v.strip() for v in value.split(",")]:
            valid(spec["member"], val)
    else:
        return valid(spec["base"], value)
        
    return True

def valid(typ, value):
    try:
        return VALIDATOR[typ](value)
    except KeyError:
        try:
            (_namespace, typ) = typ.split(":")
        except ValueError:
            if typ == "":
                typ = "string"
        return VALIDATOR[typ](value)

def _valid_instance(instance, val):
    try:
        valid_instance(val)
    except NotValid, exc:
        raise NotValid("Class '%s' instance: %s" % \
                            (instance.__class__.__name__,
                            exc.args[0]))
    except OutsideCardinality, exc:
        raise NotValid(
                "Class '%s' instance cardinality error: %s" % \
                (instance.__class__.__name__, exc.args[0]))

ERROR_TEXT = "Wrong type of value '%s' on attribute '%s' expected it to be %s"

def valid_instance(instance):
    instclass = instance.__class__
    class_name = instclass.__name__
    try:
        if instclass.c_value_type and instance.text:
            try:
                validate_value_type(instance.text.strip(), 
                                        instclass.c_value_type)
            except NotValid, exc:
                raise NotValid("Class '%s' instance: %s" % (class_name, 
                                                            exc.args[0]))
    except AttributeError: # No c_value_type
        pass
        
    for (name, typ, required) in instclass.c_attributes.values():
        value = getattr(instance, name, '')
        if required and not value:
            txt = "Required value on property '%s' missing" % name
            raise NotValid("Class '%s' instance: %s" % (class_name, txt))
        
        if value:
            try:
                if isinstance(typ, type):
                    if typ.c_value_type:
                        spec = typ.c_value_type
                    else:
                        spec = {"base": "string"} # doI need a default
              
                    validate_value_type(value, spec)
                else:
                    valid(typ, value)
            except NotValid, exc:
                txt = ERROR_TEXT % (value, name, exc.args[0])
                raise NotValid(
                            "Class '%s' instance: %s" % (class_name, txt))
        
    for (name, _spec) in instclass.c_children.values():
        value = getattr(instance, name, '')
        
        if value:
            if name in instclass.c_cardinality:
                try:
                    vlen = len(value)
                except TypeError:
                    vlen = 1
                    
                if "min" in instclass.c_cardinality[name] and \
                    instclass.c_cardinality[name]["min"] > vlen:
                    raise NotValid(
                            "Class '%s' instance cardinality error: %s" % \
                            (class_name, "less then min (%s<%s)" % \
                                (vlen, instclass.c_cardinality[name]["min"])))
                if "max" in instclass.c_cardinality[name] and \
                    instclass.c_cardinality[name]["max"] < vlen:
                    raise NotValid(
                            "Class '%s' instance cardinality error: %s" % \
                            (class_name, "more then max (%s>%s)" % \
                                (vlen, instclass.c_cardinality[name]["max"])))
            
            if isinstance(value, list):
                for val in value:
                    # That it is the right class is handled elsewhere
                    _valid_instance(instance, val)
            else:
                _valid_instance(instance, value)
        else:
            try:
                min = instclass.c_cardinality[name]["min"]
                if min:
                    print >> sys.stderr, \
                                "Min cardinality for '%s': %s" % (name, min) 
                    raise NotValid(
                        "Class '%s' instance cardinality error: %s" % \
                        (class_name, "too few values on %s" % name))
            except KeyError:
                pass
    
    return True
