XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'
XS_NAMESPACE = 'http://www.w3.org/2001/XMLSchema'

XSI_TYPE = '{%s}type' % XSI_NAMESPACE

NAMEID_FORMAT_EMAILADDRESS = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
NAMEID_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
NAMEID_FORMAT_ENCRYPTED = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")
NAMEID_FORMAT_PERSISTENT = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
NAMEID_FORMAT_TRANSIENT = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
NAMEID_FORMAT_ENTITY = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")

PROFILE_ATTRIBUTE_BASIC = (
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic")

AUTHN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
AUTHN_PASSWORD_PROTECTED = \
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        
NAME_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

CONSENT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"

# -----------------------------------------------------------------------------
XSD = "xs:"
NS_SOAP_ENC = "http://schemas.xmlsoap.org/soap/encoding/"

def _decode_attribute_value(typ, text):

    if typ == XSD + "string":
        return text or ""
    if typ == XSD + "integer" or typ == XSD + "int":
        return str(int(text))
    if typ == XSD + "float" or typ == XSD + "double":
        return str(float(text))
    if typ == XSD + "boolean":
        return "%s" % (text == "true" or text == "True")
    if typ == XSD + "base64Binary":
        import base64
        return base64.decodestring(text)
    raise ValueError("type %s not supported" % type)

def _verify_value_type(typ, val):
    #print "verify value type: %s, %s" % (typ, val)
    if typ == XSD + "string":
        try:
            return str(val)
        except UnicodeEncodeError:
            return unicode(val)
    if typ == XSD + "integer" or typ == XSD + "int":
        return int(val)
    if typ == XSD + "float" or typ == XSD + "double":
        return float(val)
    if typ == XSD + "boolean":
        if val.lower() == "true" or val.lower() == "false":
            pass
        else:
            raise ValueError("Faulty boolean value")
    if typ == XSD + "base64Binary":
        import base64
        return base64.decodestring(val)

TYPE_EXTENSION = '{%s}type' % XSI_NAMESPACE

class AttributeValueBase(SamlBase):

    def set_type(self, typ):
        self.extension_attributes[TYPE_EXTENSION] = typ

    def get_type(self):
        try:
            return self.extension_attributes[TYPE_EXTENSION]
        except KeyError:
            return ""
        
    def set_text(self, val, base64encode=False):
        typ = self.get_type()
        if base64encode:
            import base64
            val = base64.encodestring(val)
            self.set_type("xs:base64Binary")
        else:
            if isinstance(val, basestring):
                if not typ:
                    self.set_type("xs:string")
            elif isinstance(val, bool):
                if val:
                    val = "true"
                else:
                    val = "false"
                if not typ:
                    self.set_type("xs:boolean")
            elif isinstance(val, int):
                val = str(val)
                if not typ:
                    self.set_type("xs:integer")
            elif isinstance(val, float):
                val = str(val)
                if not typ:
                    self.set_type("xs:float")
            elif val is None:
                val = ""
            else:
                raise ValueError
                
        setattr(self, "text", val)
        return self

    def harvest_element_tree(self, tree):
        # Fill in the instance members from the contents of the XML tree.
        for child in tree:
            self._convert_element_tree_to_member(child)
        for attribute, value in tree.attrib.iteritems():
            self._convert_element_attribute_to_member(attribute, value)
        if tree.text:
            #print "set_text:", tree.text
            self.set_text(tree.text)
            try:
                typ = self.extension_attributes[TYPE_EXTENSION]
                _x = _verify_value_type(typ, getattr(self,"text"))
            except KeyError:
                pass
            #print _x