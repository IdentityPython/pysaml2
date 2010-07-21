#!/usr/bin/env python

import re
import time
import getopt
import imp
import sys
import types

__version__ = 0.3

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        from elementtree import ElementTree

INDENT = 4*" "
DEBUG = False

XMLSCHEMA = "http://www.w3.org/2001/XMLSchema"
CLASS_PROP = [("c_children", ".copy()"), ("c_attributes", ".copy()"),
                ("c_child_order", "[:]")]
BASE_ELEMENT = ["text", "extension_elements", "extension_attributes"]
    
class MISSING_PREREQUISITE(Exception):
    pass
            
# ------------------------------------------------------------------------

def def_init(imports, attributes):
    indent = INDENT+INDENT
    indent3 = INDENT+INDENT+INDENT
    line = []

    line.append("%sdef __init__(self," % INDENT)
    for elem in attributes:
        line.append("%s%s=%s," % (indent3,elem[0], elem[2]))
    for _,elems in imports.items():
        for elem in elems:
            line.append("%s%s=None," % (indent3,elem))
    line.append("%stext=None," % indent3)
    line.append("%sextension_elements=None," % indent3)
    line.append("%sextension_attributes=None," % indent3)
    line.append("%s):" % indent)
    return line
    
def base_init(imports):
    line = []
    indent4 = INDENT+INDENT+INDENT+INDENT
    if not imports:
        line.append("%sSamlBase.__init__(self, " % (INDENT+INDENT))
        for attr in BASE_ELEMENT:
            line.append("%s%s=%s," % (indent4, attr, attr))
        line.append("%s)" % (indent4))
    else:
        # TODO have to keep apart which properties comes from which superior
        for sup, elems in imports.items():
            line.append("%s%s.__init__(self, " % (INDENT+INDENT, sup))
            lattr = elems[:]
            lattr.extend(BASE_ELEMENT)
            for attr in lattr:
                line.append("%s%s=%s," % (indent4, attr, attr))
            line.append("%s)" % (indent4))
    return line
    
def initialize(attributes):
    indent = INDENT+INDENT
    line = []
    for prop, val, default in attributes:
        line.append("%sself.%s=%s" % (indent, prop, val))
    return line

def _mod_typ(prop):
    try:
        (mod, typ) = prop.type
    except ValueError:
        typ = prop.type
        mod = None
    except TypeError: # No type property
        try:
            (mod, typ) = prop.ref
        except ValueError:
            typ = prop.ref
            mod = None
    
    return (mod,typ)

class PyObj(object):
    def __init__(self, name=None, pyname=None, root=None):
        self.name = name
        self.done = False
        self.local = False
        self.root = root
        
        if pyname:
            self.pyname = pyname
        elif name:
            self.pyname = pyify(name)
        else:
            self.pyname = name

        self.type = None
            
    def _child_spec(self, targetNamespace, prop, mod, typ, lista):
        if mod:
            namespace = external_namespace(self.root.modul[mod])
            key = '{%s}%s' % (namespace, prop.name)
            typ = "%s.%s" % (mod,typ)
        else:
            key = '{%s}%s' % (targetNamespace, prop.name)

        if lista:
            return "c_children['%s'] = ('%s', [%s])" % (
                        key, prop.pyname, typ)
        else:
            return "c_children['%s'] = ('%s', %s)" % (
                        key, prop.pyname, typ)
        
    def class_definition(self, targetNamespace, cdict={}, ignore=[]):
        line = []
        args = []
        child = []
        imps = {}

        try:
            superior = self.superior
            for sup in superior:
                imps[sup] = [c.pyname for c in cdict[sup].properties[0] if c.pyname]
        except AttributeError:
            superior = []

        if not superior:
            line.append("class %s(SamlBase):" % (self.name,))
        else:
            line.append("class %s(%s):" % (self.name, ",".join(superior)))

        line.append("%s\"\"\"The %s:%s element \"\"\"" % (INDENT, targetNamespace,
                                                        self.name))
        line.append("")
        line.append("%sc_tag = '%s'" % (INDENT, self.name))
        line.append("%sc_namespace = NAMESPACE" % (INDENT,))
        try:
            if self.value_type:
                if isinstance(self.value_type, basestring):
                    line.append("%sc_value_type = '%s'" % (INDENT, 
                                                            self.value_type))
                else:
                    line.append("%sc_value_type = %s" % (INDENT, 
                                                        self.value_type))
        except AttributeError:
            pass

        if not superior:
            for var,cps in CLASS_PROP:
                line.append("%s%s = SamlBase.%s%s" % (INDENT, var, var, cps))
        else:
            for sup in self.superior:
                for var, cps in CLASS_PROP:
                    line.append("%s%s = %s.%s%s" % (INDENT, var, sup, var, cps))
        
        try:
            (own, inh) = self.properties
        except AttributeError:
            (own, inh) = ([], [])
            
        for prop in own:
            if isinstance(prop, PyAttribute):
                line.append("%sc_attributes['%s'] = %s" % (INDENT, 
                                                    prop.name, prop.spec()))
                if hasattr(prop,'fixed'):
                    args.append((prop.pyname, prop.fixed, None))
                else:
                    if hasattr(prop,'default'):
                        args.append((prop.pyname, prop.pyname, prop.default))
                    else:
                        args.append((prop.pyname, prop.pyname, None))
                        
            elif isinstance(prop, PyElement):
                    
                (mod, typ) = _mod_typ(prop)
                    
                if prop.max == "unbounded":
                    lista = True
                else:
                    lista = False
                    
                if prop.name in ignore:
                    pass
                else:
                    line.append("%s%s" % (INDENT, self._child_spec(
                                                        targetNamespace, prop, 
                                                        mod, typ, lista)))
                    
                child.append(prop.pyname)
                if lista:
                    args.append((prop.pyname, "%s or []" % (prop.pyname,), None))
                else:
                    args.append((prop.pyname, prop.pyname, None))
        
        if child:
            line.append("%sc_child_order.extend([%s])" % (INDENT,
                            "'"+"', '".join(child)+"'"))
            
        if args:
            if inh:
                imps[self.superior[0]] = [c.pyname for c in inh if c.pyname]
            line.append("")
            line.extend(def_init(imps, args))
            line.extend(base_init(imps))
            line.extend(initialize(args))
        
        line.append("")
        line.append("def %s_from_string(xml_string):" % self.pyname)
        line.append("%sreturn saml2.create_class_from_xml_string(%s, xml_string)" % (
                            INDENT,self.name))
        
        self.done = True
        return "\n".join(line)
    
def prepend(add, orig):
    # return a list which is the lists concatenated with the second list first
    res = [add]
    if orig:
        res.extend(orig)
    return res
    
def pyobj_factory(name, value_type):
    po = PyObj(name, pyify(name))
    po.value_type = value_type
    return po
    
def rm_duplicates(properties):
    keys = []
    clist = []
    for prop in properties:
        if prop.name in keys:
            continue
        else:
            clist.append(prop)
            keys.append(prop.name)
    return clist
            
class PyElement(PyObj):
    def __init__(self, name=None, pyname=None, root=None):
        PyObj.__init__(self, name, pyname, root)
        self.ref = None
        self.min = 1
        self.max = 1
        self.definition = None
    
    # def prereq(self, prop):
    #     prtext = prop.text(targetNamespace, cdict)
    #     if prtext == None:
    #         return []
    #     else:
    #         prop.done = True
    #         return prtext
        
    def undefined(self, cdict):
        try:
            (mod, typ) = self.type
            if not mod:
                if not cdict[typ].done:
                    return ([cdict[typ]],[])
        except ValueError:
            pass
        except TypeError: # could be a ref then or a PyObj instance
            if isinstance(self.type, PyObj):
                pass
            elif isinstance(self.ref, tuple):
                pass
            else:
                if not cdict[self.ref].done:
                    return ([cdict[self.ref]],[])
        return ([], [])
            
    def text(self, targetNamespace, cdict={}, child=True, ignore=[]):
        if child:
            text = []
        else:
            text = None
        req = []
        try:
            (mod, typ) = self.type
            if not mod:
                if typ in cdict and not cdict[typ].done:
                    raise MISSING_PREREQUISITE(typ)
                else:
                    self.orig = {"type": self.type}
                    try:
                        self.orig["superior"] = self.superior
                    except AttributeError:
                        self.orig["superior"] = []
                    self.superior = [typ]
                    req = self.class_definition(targetNamespace, cdict)
                    if not child:
                        req = [req]
                    cdict[self.name] = self
                    cdict[self.name].done = True
                    if child:
                        cdict[self.name].local = True
                    self.type = (None, self.name)
            else:
                imp_name = "%s.%s" % (mod, typ)
                if imp_name not in cdict:
                    # create import object so I can get the properties from it later
                    impo = pyobj_factory(imp_name, None)
                    impo.properties = [_import_attrs(self.root.modul[mod], typ, 
                                                    self.root),[]]
                    cdict[imp_name] = impo
                    impo.done = True
                    if child:
                        impo.local = True
                # and now for this object
                self.superior = [imp_name]
                text = self.class_definition(targetNamespace, cdict)                
        except ValueError, e: # Simple type element
            if self.type:
                po = pyobj_factory(self.name, self.type)
                self.type = self.name
                cdict[self.name] = po
                text = po.class_definition(targetNamespace, cdict)
                if child:
                    po.local = True
                po.done = True
                    
        except TypeError: # could be a ref then or a PyObj instance
            if isinstance(self.type, PyObj):
                po = self.type
                po.name = self.name
                po.pyname = self.pyname
                cdict[self.name] = po
                return po.text(targetNamespace, cdict)
            elif isinstance(self.ref, tuple):
                (mod, typ) = self.ref
                if mod:
                    #self.superior = ["%s.%s" % (mod, typ)]
                    if verify_import(self.root.modul[mod], typ):
                        return (req, text)
                    else:
                        raise Exception(
                            "Import attempted on %s from %s module failed - wasn't there" % (
                                typ,mod))
                elif not child:
                    self.superior = [typ]
                    text = self.class_definition(targetNamespace, cdict)
            else:
                if not cdict[self.ref].done:
                    raise MISSING_PREREQUISITE(self.ref)
                
        self.done = True
        return (req, text)
        
def _do(obj, targetNamespace, cdict, prep):
    try:
        (req, text) = obj.text(targetNamespace, cdict)
    except MISSING_PREREQUISITE:
        return ([], None)
        
    if text == None:
        if req:
            #prep = prepend(req, prep)
            prep.append(req)
        return (prep, None)
    else:
        obj.done = True
        if req:
            if isinstance(req, basestring):
                prep.append(req)
            else:
                prep.extend(req)
        if text:
            #prep = prepend(text, prep)
            prep.append(text)
    return prep

def reqursive_superior(supc, cdict):
    properties = supc.properties[0]
    for sup in supc.superior:
        rsup = cdict[sup]
        if rsup.properties[1]:
            properties.extend(rsup.properties[1])
        else:
            properties.extend(reqursive_superior(rsup, cdict))
    return properties
    
class PyType(PyObj):
    def __init__(self, name=None, pyname=None, root=None, superior=None, 
                internal=True, ns=None):
        PyObj.__init__(self, name, pyname, root)
        self.properties = ([], [])
        if superior:
            self.superior = [superior]
        else:
            self.superior = []
        self.value_type = None
        self.internal = internal
        self.ns = ns

    def text(self, targetNamespace, cdict={}, child=True, ignore=[]):
        if not self.properties and not self.type \
                and not self.superior:
            self.done = True
            return ([], self.class_definition(targetNamespace, cdict))
        
        req=[]
        inherited_properties=[]
        for sup in self.superior:
            try:
                supc = cdict[sup]
            except KeyError:
                (mod, typ) = sup.split('.')
                supc = pyobj_factory(sup, None)
                supc.properties = [_import_attrs(self.root.modul[mod], typ, 
                                                self.root),[]]
                cdict[sup] = supc
                supc.done = True
                
            if not supc.done:
                res = _do(supc, targetNamespace, cdict, req)
                if isinstance(res, tuple):
                    return res
            
            if self.properties[1] == []:
                inherited_properties = reqursive_superior(supc, cdict)
        
        if inherited_properties:
            self.properties = (self.properties[0], 
                                rm_duplicates(inherited_properties))
            
        (own, inh) = self.properties
        own = rm_duplicates(own)
        self.properties = (own, inh)
        for prop in own:
            if not prop.name: # Ignore
                continue 
            if not prop.done:
                if prop.name in ignore:
                    continue
                res = _do(prop, targetNamespace, cdict, req)
                if res == ([], None):
                    # Cleaning up
                    for prp in own:
                        if prp == prop:
                            break
                        try:
                            if cdict[prp.name].local:
                                del cdict[prp.name]
                                if hasattr(prp, "orig"):
                                    for key, val in prp.orig.items():
                                        setattr(prp,key,val)
                                prp.done = False
                                prp.local = False
                        except KeyError:
                            pass
                if isinstance(res, tuple):
                    return res
        
        return (req, self.class_definition(targetNamespace, cdict, ignore))
    
    def undefined(self, cdict):
        undef = ([], [])

        for sup in self.superior:
            supc = cdict[sup]
            if not supc.done:
                undef[0].append(supc)

        (own, inh) = self.properties
        for prop in own:
            if not prop.name: # Ignore
                continue 
            if not prop.done:
                undef[1].append(prop)
        return undef

class PyAttribute(PyObj):
    def __init__(self, name=None, pyname=None, root=None, external=False, 
                    ns="", required=False, typ=""):
        PyObj.__init__(self, name, pyname, root)

        self.required = required
        self.external = external
        self.ns = ns
        self.base = None
        self.type = typ

    def text(self, targetNamespace, cdict={}, child=True):
        return ([], []) # Means this elements definition is empty
        
    def spec(self):
        return "('%s', '%s', %s)" % (self.pyname, self.type, self.required)
       
class PyAny(PyObj):
    def __init__(self, name=None, pyname=None, external=False, ns=""):
        PyObj.__init__(self, name, pyname)
        self.done = True

class PyAttributeGroup(object):
    def __init__(self, name, root):
        self.name = name
        self.root = root

# -----------------------------------------------------------------------------
def verify_import(modul, tag):
    try:
        obj = modul.factory(tag)
        return True
    except:
        return False
    
def external_namespace(modul):
    return modul.NAMESPACE

def _import_attrs(modul, tag, top):
    obj = modul.factory(tag)
    properties = [PyAttribute(key, val[0], top, True, obj.c_namespace, val[2],
                                 val[1]) for key,val in obj.c_attributes.items()]
    for c in obj.c_child_order:
        for key,val in obj.c_children.items():
            (pyn, mul) = val
            max = 1
            if isinstance(mul,list):
                mul = mul[0]
                max = "unbounded"
            if pyn == c:
                cpy = PyElement(name=mul.c_tag, pyname=pyn, root=top) 
    #                            internal=False, ns=obj.c_namespace)
                cpy.max = max
                properties.append(cpy)

    return properties

# ------------------------------------------------------------------------

def _spec(elem):
    try:
        name = elem.name
    except AttributeError:
        name = "anonymous"
    txt = "%s" % name
    try:
        txt += " ref: %s" % elem.ref
    except AttributeError:
        try:
            txt += " type: %s" % elem.type
        except AttributeError:
            pass

    return txt
        
def _klass(elem, NS, sup, top):
    if elem.name in top.py_elements:
        return None
    else:
        kl = PyType(elem.name, root=top)
        top.py_elements[elem.name] = kl
        if sup != "SamlBase":
            kl.superior.append(sup)
        return kl
        
def _do_from_string(name):
    print
    print "def %s_from_string(xml_string):" % pyify(name)
    print "%sreturn saml2.create_class_from_xml_string(%s, xml_string)" % (
                INDENT, name)


# -----------------------------------------------------------------------------

class Simple(object):
    def __init__(self, elem):
        self._repr = []
        for attribute, value in elem.attrib.iteritems():            
            self.__setattr__(attribute, value)

    def collect(self, top, sup, argv=None):
        try:
            return ([self.repr(top, sup, argv)],[])
        except AttributeError:
            return ([], [])

    def elements(self, top):
        return []

        
class Any(Simple):
    
    def repr(self, top, sup, argv=None):
        return PyAny()
        
class AnyAttribute(Simple):

    def repr(self, top, sup, argv=None):
        return PyAny()

class Attribute(Simple):
    def repr(self, top=None, sup=None, argv=None):
        # default, fixed, use, type
                    
        if (DEBUG):
            print "#ATTR",self.__dict__

        external=False
        try:
            (ns,tag) = self.ref.split(":")
            if ns in self.xmlns_map:
                if self.xmlns_map[ns] == top.targetNamespace:
                    ref = {"name": tag}
                else :
                    external = True
                    ref = {"name": tag, "namespace":self.xmlns_map[ns]}
            else:
                if ns == "xml":
                    ref = {"namespace": 'http:#www.w3.org/XML/1998/namespace',
                            "name": tag}
            pyname = name = tag
        except AttributeError:
            name = self.name
            pyname = pyify(name)
            ref = None
                    
        objekt = PyAttribute(name, pyname, external=external, root=top)
        
        # Initial declaration
        if not ref:
            try:
                (ns, klass) = self.type.split(":")
                if self.xmlns_map[ns] == top.targetNamespace:
                    ct = get_type_def(klass, top._part)
                    if not ct._repr:
                        ct.repr(top, sup)
                    objekt.type = klass
                elif self.xmlns_map[ns] == XMLSCHEMA:
                    objekt.type = klass
                else:
                    objekt.type = self.type
            except ValueError:
                objekt.type = self.type
        
        try:
            if self.use == "required":
                objekt.required = True
        except AttributeError:
            pass
            
        # in init
        try:
            objekt.default = self.default
        except AttributeError:
            pass
                
        # attr def
        try:
            objekt.fixed = self.fixed
        except AttributeError:
            pass
        
        if (DEBUG):
            print "#--ATTR py_attr:%s" % (objekt,)
            
        return objekt
        
class Enumeration(Simple):
    pass
    
class Union(Simple):
    pass
    
class Import(Simple):
    pass
    
class Documentation(Simple):
    pass
    
class MaxLength(Simple):
    pass

class Length(Simple):
    pass
    
class MinInclusive(Simple):
    pass
    
class MaxInclusive(Simple):
    pass

class MinExclusive(Simple):
    pass

class MaxExclusive(Simple):
    pass
    
class List(Simple):
    pass
    
# -----------------------------------------------------------------------------

def _do_typ(kl, top, sup, obj):
    ct = get_type_def(kl, top._part)

    if (DEBUG):
        print "# _do_typ '%s' (repr:%s)" % (ct.name, ct._repr)
        
    if not ct._repr:
        ct.repr(top, sup)

    if obj.name not in top.py_elements:
        sup = top.py_elements[ct.name]        
        top.py_element = PyClass(obj.name, root=top)

# -----------------------------------------------------------------------------

def sequence(elem):
    return [evaluate(child.tag, child) for child in elem]

def name_or_ref(elem, top):
    try:
        (ns,name) = elem.ref.split(":")
        if ns and elem.xmlns_map[ns] == top.targetNamespace:
            return name
        else:
            return elem.ref
    except AttributeError:
        return elem.name

class Complex(object):
    def __init__(self, elem):
        self.value_of = ""
        self._part = []
        self._own = []
        self._inherited = []
        self._repr = False
        self._generated = False
        self._class = None
        
        for attribute, value in elem.attrib.iteritems():
            self.__setattr__(attribute, value)

        try:
            if elem.text.strip():
                self.value_of = elem.text.strip()
        except AttributeError:
            pass

        self.do_child(elem)
        
        try:
            self.name = self.name.replace("-","_")
        except AttributeError:
            pass

    def collect(self, top, sup, argv=None):
        if self._own or self._inherited:
            return (self._own, self._inherited)
            
        if (DEBUG):
            print self.__dict__
            print "#-- %d parts" % len(self._part)
            
        for part in self._part:
            (own, inh) = part.collect(top, sup, argv)
            self._own.extend(own)
            self._inherited.extend(inh)

        return (self._own, self._inherited)
        
    def do_child(self, elem):
        for child in elem:
            self._part.append(evaluate(child.tag, child))

    def elements(self, top):
        res = []
        # try:
        #     string = "== %s (%s)" % (self.name,self.__class__)
        # except AttributeError:
        #     string = "== (%s)" % (self.__class__,)
        # print string
        for part in self._part:
            if isinstance(part, Element):
                res.append(name_or_ref(part, top))
            else:
                if isinstance(part, Extension):
                    res.append(part.base)
                res.extend(part.elements(top))

        return res

    def repr(self, top=None, sup=None, argv=None, child=True):
        return None
                
class Element(Complex):
    def __str__(self):
        return "%s" % (self.__dict__,)

    def _class(self, top):
        xns = None
        ct = None
        ref = False
        try:
            (ns,name) = self.ref.split(":")
            ref = True
        except AttributeError:
            try:
                (ns,name) = self.type.split(":")
            except ValueError:
                ns = None
                name = self.type
            except AttributeError, e:
                ns = name = None

        if ns:
            if self.xmlns_map[ns] == top.targetNamespace:
                ct = get_type_def(name, top._part)
            else:
                xns = ns

        return (ns, name, ct, xns, ref)

    def collect(self, top, sup, argv=None):
        """ means this element is part of a larger object, hence a property of 
        that object """
        
        try:
            return ([self.repr(top, sup, argv)],[])
        except AttributeError, e:
            print "!!!!", e
            return ([], [])

    def elements(self, top):            
        (ns, name, ct, xns, ref) = self._class(top)
        if ct:
            return ct.elements(top)
        elif xns:
            return ["%s.%s" % (xns,name)]
        else:
            return []

    def repr(self, top=None, sup=None, argv=None, child=True):
        #<element ref='xenc:ReferenceList' ...
        #<element name='Transforms' type='xenc:TransformsType' ...
        #<element name='CarriedKeyName' type='string' ...
        #<element name="RecipientKeyInfo" type="ds:KeyInfoType" ...
        #<element name='ReferenceList'>

        xns = ns = ct = None
        name = ""
        try:
            myname = self.name
        except AttributeError:
            myname = ""

        if DEBUG:
            print "#Element.repr '%s' (child=%s) [%s/%s]" % (myname, child, 
                                                    self._repr, self._generated)

        objekt = PyElement(myname,root=top)
        
        try:
            objekt.max = self.maxOccurs
        except AttributeError:
            try:
                objekt.max = argv["maxOccurs"]
            except (TypeError,KeyError):
                pass

        try:
            objekt.min = self.minOccurs
        except AttributeError:
            try:
                objekt.min = argv["minOccurs"]
            except (TypeError,KeyError):
                pass
                
        try:
            (ns, superkl) = self.ref.split(":")
            # internal or external reference
            if not myname:
                objekt.name = superkl
                objekt.pyname = pyify(superkl)
            if self.xmlns_map[ns] == top.targetNamespace:
                objekt.ref = superkl 
            else:
                objekt.ref = (ns, superkl)                
        except AttributeError, e:
            if (DEBUG):
                print "#===>", e
            try:
                typ = self.type

                try:
                    (ns, kl) = typ.split(":")
                    if self.xmlns_map[ns] == top.targetNamespace:
                        objekt.type = (None, kl)
                    else:
                        objekt.type = (ns, kl)
                except ValueError:
                    objekt.type = typ
            except AttributeError, e:
                if hasattr(self, "_part") and len(self._part) == 1:
                    if isinstance(self._part[0], ComplexType):
                        objekt.type = self._part[0].repr(top, sup)
                else:
                    if (DEBUG):
                        print "$",self
                    raise Exception()
        
        return objekt

class SimpleType(Complex):
    def repr(self, top=None, sup=None, argv=None, child=True):
        obj = PyType(self.name, root=top)
        try:
            if len(self._part) == 1:
                part = self._part[0]
                if isinstance(part, Restriction):
                    if part._part:
                        if isinstance(part._part[0], Enumeration):
                            lista = [p.value for p in part._part]
                            obj.value_type = {"base":part.base,
                                                "enumeration":lista}
                        elif isinstance(part._part[0],MaxLength):
                            obj.value_type = {"base":part.base,
                                                "maxlen":part._part[0].value}
                        elif isinstance(part._part[0],Length):
                            obj.value_type = {"base":part.base,
                                                "len":part._part[0].value}
                    else:
                        obj.value_type = {"base":part.base}
                elif isinstance(part, List):
                    if part.itemType:
                        obj.value_type = {"base":"list", "member":part.itemType}
        except ValueError:
            pass
            
        return obj
        
class Sequence(Complex):
    def collect(self, top, sup, argv={}):
        if not argv:
            argv={}
        for key, val in self.__dict__.items():
            if key not in ['xmlns_map'] and not key.startswith("_"):
                argv[key] = val
    
        if DEBUG:
            print "#Sequence: %s" % argv
        return Complex.collect(self, top, sup, argv)

class SimpleContent(Complex):
    pass

class ComplexContent(Complex):
    pass
    
class Extension(Complex):
    def collect(self, top, sup, argv={}):
        if self._own or self._inherited:
            return (self._own, self._inherited)
        
        if (DEBUG):
            print "#!!!",self.__dict__

        try:
            base = self.base
            (ns, tag) = base.split(":")
            if self.xmlns_map[ns] == top.targetNamespace:
                ct = get_type_def(tag, top._part)
                if not ct._repr:
                    ct.repr(top, sup)
                #print "#EXT..",ct._collection
                self._inherited = ct._collection
            else:
                ia = _import_attrs(top.modul[ns], tag, top)
                #print "#EXT..-", ia
                self._inherited = ia
        except (AttributeError, ValueError):
            pass
            
        for part in self._part:
            #print "### ", part
            (own, inh) = part.collect(top, sup, argv)
            if own:
                if len(own) == 1 and isinstance(own[0], PyAttribute):
                    own[0].base = base
                self._own.extend(own)
            self._inherited.extend(inh)

        #print "#EXT C", self._own
        return (self._own, self._inherited)

class Choice(Complex):
    def collect(self, top, sup, argv={}):
        if not argv:
            argv={}
        for key, val in self.__dict__.items():
            if key not in ['xmlns_map'] and not key.startswith("_"):
                argv[key] = val
        
        if DEBUG:
            print "#Choice: %s" % argv
        return Complex.collect(self, top, sup, argv)

class Restriction(Complex):
    def repr(self, top=None, sup=None, argv=None, child=True):
        if isinstance(self._part[0], Enumeration):
            values = [enum.value for enum in self._part]

class ComplexType(Complex):
    def repr(self, top=None, sup=None, argv=None, child=True):
        if (DEBUG):
            print "# -- repr on %s [%s/%s]" % (self.name, self._repr, self._generated)
        if self._repr:
            return
            
        self._repr = True
        
        # looking for a pattern here
        if len(self._part) == 1:
            if isinstance(self._part[0], ComplexContent):
                cc = self._part[0]
                if len(cc._part) == 1:
                    if isinstance(cc._part[0], Extension):
                        ext = cc._part[0]
                        (ns,name) = ext.base.split(":")
                        if ns and ext.xmlns_map[ns] == top.targetNamespace:
                            new_sup = name
                        elif ns and ext.xmlns_map[ns] == XMLSCHEMA:
                            new_sup = None
                        else:
                            new_sup = ext.base
                        if ":" in new_sup:
                            new_sup = ".".join(new_sup.split(":"))
                        else:
                            ct = get_type_def(new_sup, top._part)
                            if ct and not ct._repr:
                                ct.repr(top, sup)
                            
                        #print "#Superior: %s" % new_sup
                        if new_sup:
                            sup = new_sup
            else:
                #print "#>>", self._part[0].__class__
                pass
                
        try:
            self._class = PyType(self.name, superior=sup, 
                                    ns=top.targetNamespace, root=top)
        except AttributeError: # No name 
            self._class = PyType("", superior=sup, 
                                    ns=top.targetNamespace, root=top)

        try:
            self._class.properties = self.collect(top, sup)
        except ValueError:
            pass
            
        return self._class 
        
class Annotation(Complex):
    pass

class Group(Complex):
    pass

class Unique(Complex):
    pass

class Selector(Complex):
    pass

class Field(Complex):
    pass

class AttributeGroup(Complex):
    def collect(self, top, sup, argv=None):
        try:
            (ns, typ) = self.ref.split(":")
            ci = get_type_def(typ, top._part)
            return ci.collect(top, sup)
        except AttributeError:
            if self._own or self._inherited:
                return (self._own, self._inherited)
                
            for p in self._part:
                if isinstance(p, Attribute):
                    #print "== %s ==" % p.name
                    self._own.append(p.repr(top, sup, argv))
            #print "$$", res
            return (self._own, self._inherited)

    def repr(self, top=None, sup=None, argv=None, child=True):
        self._class = PyAttributeGroup(self.name, root=top)

        try:
            self._class.properties = self.collect(top, sup)
        except ValueError:
            pass
            
        return self._class 

def pyify_0(name):
    res = ""
    m = re.match(r"^(([A-Z])[a-z]+)(([A-Z])[a-z]+)?(([A-Z])[a-z]+)?(([A-Z])[a-z]+)?",name)
    res += m.group(1).lower()
    for n in range(3,len(m.groups()),2):
        try:
            res += "_"+m.group(n+1).lower()+m.group(n)[1:]
        except AttributeError:
            break
    return res

def pyify(name):
    # AssertionIDRef
    res = []
    
    uc = []
    lc = []
    pre = ""
    for c in name:
        if c >= "A" and c <= "Z":
            uc.append(c)
        else:
            if uc:
                if len(uc) == 1:
                    res.append(pre+uc[0].lower())
                else:
                    if pre:
                        res.append(pre)
                    for u in uc[:-1]:
                        res.append(u.lower())
                    res.append("_"+uc[-1].lower())
                        
                uc = []
            res.append(c)
            pre = "_"
    if uc:
        if len(uc) == len(name):
            return name.lower()
        else:
            res.append("_"+("".join(uc).lower()))
        
    return "".join(res)

def get_type_def( typ, defs):
    for ct in defs:
        try:
            if ct.name == typ:
                return ct
        except AttributeError:
            pass
    return None
    

def sort_elements(els):
    res = []
    
    diff = False
    for key, val in els.items():
        if not val:
            res.append(key)
            del els[key]
            diff = True
    
    res.sort()
    while diff:
        diff = False
        for key, val in els.items():
            r = [v for v in val if v not in res and ':' not in v]
            els[key] = r
            if r != val:
                diff = True

        #print els
        partres = []
        for key, val in els.items():
            if not val:
                partres.append(key)
                del els[key]
                diff = True
        partres.sort()
        res.extend(partres)
        
    return (res, els)

def output(elem, targetNamespace, eldict, ignore=[]):
    done = 0
    try:
        (preps, text) = elem.text(targetNamespace, eldict, False, ignore)
    except TypeError:
        return done
    except MISSING_PREREQUISITE:
        return done
    
    for prep in preps:
        if prep:
            done = 1
            print prep
            print 

    if text:
        done = 1
        elem.done = True
        print text
        print
    
    return done
    
def intro():
    print """#!/usr/bin/env python

#
# Generated %s by parse_xsd.py version %s.
#

import saml2
from saml2 import SamlBase
""" % (time.ctime(),__version__)

    NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'
    
class Schema(Complex):

    def __init__(self, elem, imp, add, modul, defs):
        Complex.__init__(self, elem)
        self.imp = imp
        self.add = add
        self.modul = modul
        self.py_elements = {}
        self.py_attributes = {}
        self.elems = []
        self.attrgrp = []
        self.defs = []
        for def_file in defs:
            self.defs.append(open(def_file).read())

    def adjust(self, eldict):
        udict = {}
        for elem in self.elems:
            if not elem.done:
                udict[elem] = elem.undefined(eldict)

        keys = [k.name for k in udict.keys()]
        print "#", keys
        res = None
        for key, (sup, elems) in udict.items():
            if sup:
                continue
            else:
                signif = []
                for elem in elems:
                    if elem.name in keys:
                        signif.append(elem)
                if len(signif) == 1:
                    # AdviceType.c_children['{%s}Assertion' % NAMESPACE] = ('assertion', [Assertion])
                    prop = signif[0]
                    (mod, typ) = _mod_typ(prop)

                    if prop.max == "unbounded":
                        lista = True
                    else:
                        lista = False
                    spec = key._child_spec(self.targetNamespace, prop, mod, typ, lista)
                    lines = ["%s.%s" % (key.name, spec)]
                    res = (key, prop, lines)
                    break
        if res:
            ref = res[0].name
            for key, (sups, elems) in udict.items():
                if sups:
                    for sup in sups:
                        if sup.name == ref:
                            lines.append("%s.%s" % (key.name, spec))
                            break
                else:
                    pass

        return res

    def _do(self, eldict):
        not_done = 1
        while not_done:
            not_done = 0
            undone = 0
            for elem in self.elems:
                if elem.done:
                    continue
                undone += 1
                not_done += output(elem, self.targetNamespace, eldict)
        return undone
        
    def out(self):
        for part in self._part:
            if isinstance(part, Import):
                continue

            elem = part.repr(self, "", child=False)
            if elem:
                if isinstance(elem, PyAttributeGroup):
                    self.attrgrp.append(elem)
                else:
                    self.elems.append(elem)
        
        eldict = {}
        for elem in self.elems:
            eldict[elem.name] = elem

        #print eldict.keys()
        
        intro()
        for a in self.add:
            print "from %s import *" % a
        for mod,namn in self.imp.items():
            print "import %s as %s" % (mod, namn)
        print        
        print "NAMESPACE = '%s'" % self.targetNamespace
        print

        for defs in self.defs:
            print defs
            print
        
        exceptions = []
        while self._do(eldict):
            print "#.................."
            (objekt, prop, lines) = self.adjust(eldict)
            output(objekt, self.targetNamespace, eldict, [prop.name])
            exceptions.extend(lines)

        if exceptions:
            print "#", 70*'+'
            for line in exceptions:
                print line
            print "#", 70*'+'
            print
                
        print "ELEMENT_FROM_STRING = {"
        for elem in self.elems:
            print "%s%s.c_tag: %s_from_string," % (INDENT, elem.name, elem.pyname)

        print "}"
        print
        print "ELEMENT_BY_TAG = {"
        for elem in self.elems:
            print "%s'%s': %s," % (INDENT, elem.name, elem.name)
        print "}"
        print
        print "def factory(tag, **kwargs):"
        print "    return ELEMENT_BY_TAG[tag](**kwargs)"
        print
        # for elem in self.elems:
        #     if elem.done:
        #         continue
        #     else:
        #         print elem.name
        # 
        # # And lastly the elements
        # print eldict.keys()
        # print self.elems
        
        
# -----------------------------------------------------------------------------

ELEMENTFUNCTION = {
    "{http://www.w3.org/2001/XMLSchema}element": Element,
    "{http://www.w3.org/2001/XMLSchema}complexType": ComplexType,
    "{http://www.w3.org/2001/XMLSchema}sequence": Sequence,
    "{http://www.w3.org/2001/XMLSchema}any": Any,
    "{http://www.w3.org/2001/XMLSchema}anyAttribute": AnyAttribute,
    "{http://www.w3.org/2001/XMLSchema}simpleContent": SimpleContent,
    "{http://www.w3.org/2001/XMLSchema}extension": Extension,
    "{http://www.w3.org/2001/XMLSchema}union": Union,
    "{http://www.w3.org/2001/XMLSchema}restriction": Restriction,
    "{http://www.w3.org/2001/XMLSchema}enumeration": Enumeration,
    "{http://www.w3.org/2001/XMLSchema}import": Import,
    "{http://www.w3.org/2001/XMLSchema}annotation": Annotation,
    "{http://www.w3.org/2001/XMLSchema}attributeGroup":AttributeGroup,
    "{http://www.w3.org/2001/XMLSchema}attribute":Attribute,
    "{http://www.w3.org/2001/XMLSchema}choice": Choice,
    "{http://www.w3.org/2001/XMLSchema}complexContent": ComplexContent,
    "{http://www.w3.org/2001/XMLSchema}documentation": Documentation,
    "{http://www.w3.org/2001/XMLSchema}simpleType": SimpleType,
    "{http://www.w3.org/2001/XMLSchema}maxLength": MaxLength,
    "{http://www.w3.org/2001/XMLSchema}list": List,
    "{http://www.w3.org/2000/10/XMLSchema}element": Element,
    "{http://www.w3.org/2000/10/XMLSchema}complexType": ComplexType,
    "{http://www.w3.org/2000/10/XMLSchema}sequence": Sequence,
    "{http://www.w3.org/2000/10/XMLSchema}any": Any,
    "{http://www.w3.org/2000/10/XMLSchema}anyAttribute": AnyAttribute,
    "{http://www.w3.org/2000/10/XMLSchema}simpleContent": SimpleContent,
    "{http://www.w3.org/2000/10/XMLSchema}extension": Extension,
    "{http://www.w3.org/2000/10/XMLSchema}union": Union,
    "{http://www.w3.org/2000/10/XMLSchema}restriction": Restriction,
    "{http://www.w3.org/2000/10/XMLSchema}enumeration": Enumeration,
    "{http://www.w3.org/2000/10/XMLSchema}import": Import,
    "{http://www.w3.org/2000/10/XMLSchema}annotation": Annotation,
    "{http://www.w3.org/2000/10/XMLSchema}attributeGroup":AttributeGroup,
    "{http://www.w3.org/2000/10/XMLSchema}attribute":Attribute,
    "{http://www.w3.org/2000/10/XMLSchema}choice": Choice,
    "{http://www.w3.org/2000/10/XMLSchema}complexContent": ComplexContent,
    "{http://www.w3.org/2000/10/XMLSchema}documentation": Documentation,
    "{http://www.w3.org/2000/10/XMLSchema}simpleType": SimpleType,
    "{http://www.w3.org/2000/10/XMLSchema}maxLength": MaxLength,
    "{http://www.w3.org/2000/10/XMLSchema}list": List,
    "{http://www.w3.org/2000/10/XMLSchema}unique": Unique,
    "{http://www.w3.org/2000/10/XMLSchema}group": Group,
    "{http://www.w3.org/2000/10/XMLSchema}selector": Selector,
    "{http://www.w3.org/2000/10/XMLSchema}field": Field,
    }
    
def evaluate(typ, elem):
    try:
        return ELEMENTFUNCTION[typ](elem)
    except KeyError:
        print "Unknown type", typ
        
    
NS_MAP = "xmlns_map"

def parse_nsmap(fil):

    events = "start", "start-ns", "end-ns"

    root = None
    ns_map = []

    for event, elem in ElementTree.iterparse(fil, events):
        if event == "start-ns":
            ns_map.append(elem)
        elif event == "end-ns":
            ns_map.pop()
        elif event == "start":
            if root is None:
                root = elem
            elem.set(NS_MAP, dict(ns_map))

    return ElementTree.ElementTree(root)

def usage():
    print "Usage: parse_xsd [-i <module:as>] xsd.file > module.py"
    
def recursive_find_module(name, path=None):
    parts = name.split(".")

    for part in parts:
        #print "$$", part, path
        try:
            (fil, pathname, desc) = imp.find_module(part, path)
        except ImportError:
            raise 

        mod_a = imp.load_module(name, fil, pathname, desc)
        sys.modules[name] = mod_a
        path = mod_a.__path__

    return mod_a

def get_mod(name, path=None):
    try:
        mod_a = sys.modules[name]
        if not isinstance(mod_a, types.ModuleType):
            raise KeyError
    except KeyError:
        try:
            (fil, pathname, desc) = imp.find_module(name, path)
            mod_a = imp.load_module(name, fil, pathname, desc)
        except ImportError:
            if "." in name:
                mod_a = recursive_find_module(name, path)
            else:
                raise
        sys.modules[name] = mod_a
    return mod_a
        
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "a:d:hi:v", ["add=", "help", "import=", "defs="])
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    verbose = False
    add = []
    defs = []
    imp = {}
    modul = {}

    for o, a in opts:
        if o == "-v":
            verbose = True
        elif o in ("-a", "--add"):
            add.append(a)
        elif o in ("-d", "--defs"):
            defs.append(a)
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-i", "--import"):
            (mod,name) = a.split(":")
            imp[mod] = name
            modul[name] = get_mod(mod, ['.'])
            # print modul[name]
            # print modul[mod].FOO
        else:
            assert False, "unhandled option"

    if not args:
        print "No XSD-file specified"
        usage()
        sys.exit(2)
        
    tree = parse_nsmap(args[0])

    schema = Schema(tree._root, imp, add, modul, defs)

    #print schema.__dict__
    schema.out()

if __name__ == "__main__":
    import sys
    
    main(sys.argv[1:])
    
    