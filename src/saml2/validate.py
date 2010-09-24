import urlparse
import re
import time_util
import struct
import base64
import time

def valid_ncname(name):
    """
    """
    exp = re.compile("(?P<NCName>[a-zA-Z_](\w|[_.-])*)")
    match = exp.match(name)
    if not match:
        return False
        
    return True

def valid_id(oid):
    return valid_ncname(oid)
    
def valid_any_uri(item):
    """very simplistic, ..."""
    try:
        part = urlparse.urlparse(item)
    except Exception:
        return False

    if part[0] == "urn" and part[1] == "": # A urn
        return True
    elif part[1] == "localhost" or part[1] == "127.0.0.1":
        return False
        
    return True
    
def valid_date_time(item):
    try:
        time_util.str_to_time(item)
        return True
    except Exception:
        return False
    
def valid_url(url):
    try:
        part = urlparse.urlparse(url)
    except Exception:
        return False
        
    if part[1] == "localhost" or part[1] == "127.0.0.1":
        return False
        
    return True
    
def validate_on_or_after(not_on_or_after, slack):
    if not_on_or_after:
        now = time_util.daylight_corrected_now()
        nooa = time.mktime(time_util.str_to_time(not_on_or_after))
        high = nooa+slack
        if now > high:
            raise Exception("Too old can't use it! %d" % (now-high,))
        return nooa
    else:
        return 0

def validate_before(not_before, slack):
    if not_before:
        now = time_util.daylight_corrected_now()
        nbefore = time.mktime(time_util.str_to_time(not_before))
        if nbefore > now + slack:
            raise Exception("Can't use it yet %s <= %s" % (nbefore, now))    
        return True
    else:
        return True

def valid_address(address):
    return valid_ipv4(address) or valid_ipv6(address)
    
def valid_ipv4(address):
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        try:
            if not 0 <= int(item) <= 255:
                return False
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
    if vall == "true" or vall == "false":
        return True
    else:
        return False

def valid_duration(val):
    try:
        time_util.parse_duration(val)
        return True
    except Exception:
        return False

def valid_string(val):
    """ Expects unicode 
    Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | 
                    [#x10000-#x10FFFF]
    """
    for char in val:
        try:
            char = ord(char)
        except TypeError:
            return False
        if char == 0x09 or char == 0x0A or char == 0x0D:
            continue
        elif char >= 0x20 and char <= 0xD7FF:
            continue
        elif char >= 0xE000 and char <= 0xFFFD:
            continue
        elif char >= 0x10000 and char <= 0x10FFFF:
            continue
        else:
            return False
    return True
    
def valid_unsigned_short(val):
    try:
        struct.pack("H", int(val))
        return True
    except struct.error:
        return False
    
def valid_non_negative_integer(val):
    try:
        integer = int(val)
        if integer > 0 and isinstance(integer, int):
            return True
        else:
            return False
    except Exception:
        return False

def valid_integer(val):
    try:
        integer = int(val)
        if isinstance(integer, int):
            return True
        else:
            return False
    except Exception:
        return False
        
def valid_base64(val):
    try:
        base64.b64decode(val)
        return True
    except Exception:
        return False

def valid_qname(val):
    """ either 
        NCName or 
        NCName ':' NCName
    """
    
    try:
        (prefix, localpart) = val.split(":")
        return valid_ncname(prefix) and valid_ncname(localpart)
    except ValueError:
        return valid_ncname(val)

def valid_anytype(val):
    # Should I go through and check all known types ???
    for validator in VALIDATOR.values():
        if validator(val):
            return True
    
    if isinstance(val, type):
        return True
        
    return False
    
# -----------------------------------------------------------------------------

VALIDATOR = {
    "ID": valid_id,
    "NCName": valid_ncname,
    "dateTime": valid_date_time,
    "anyURI": valid_any_uri,
    "string": valid_string,
    "nonNegativeInteger": valid_non_negative_integer,
    "boolean": valid_boolean,
    "unsignedShort": valid_unsigned_short,
    "duration": valid_duration,
    "base64Binary": valid_base64,
    "integer": valid_integer,
    "QName": valid_qname,
    "anyType": valid_anytype,
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
                return False
        else:
            return valid_string(value)
    elif spec["base"] == "list": #comma separated list of values
        for val in [v.strip() for v in value.split(",")]:
            if not valid(spec["member"], val):
                return False
    else:
        return valid(spec["base"], value)
        
    return True

def valid(typ, value):
    try:
        return VALIDATOR[typ](value)
    except KeyError:
        (_namespace, typ) = typ.split(":")
        return VALIDATOR[typ](value)
    
def valid_instance(instance):
    instclass = instance.__class__
    try:
        if instclass.c_value_type and instance.text:
            assert validate_value_type(instance.text.strip(), 
                                        instclass.c_value_type)
    except AttributeError: # No c_value_type
        pass
        
    for (name, typ, required) in instclass.c_attributes.values():
        value = getattr(instance, name, '')
        if required and not value:
            return False
        
        if value:
            if isinstance(typ, type):
                if not valid_instance(typ):
                    return False
            if not valid(typ, value):
                return False
        
    for (name, _spec) in instclass.c_children.values():
        value = getattr(instance, name, '')
        
        if value:
            if name in instclass.c_cardinality:
                if "min" in instclass.c_cardinality[name] and \
                    instclass.c_cardinality[name]["min"] > len(value):
                    return False
                if "max" in instclass.c_cardinality[name] and \
                    instclass.c_cardinality[name]["max"] < len(value):
                    return False
                    
            for val in value:
                # That it is the right class is handled elsewhere
                if not valid_instance(val):
                    return False
        elif name in instclass.c_cardinality and \
                "min" in instclass.c_cardinality[name] and \
                instclass.c_cardinality[name]["min"] > 0:
            return False
    
    return True
