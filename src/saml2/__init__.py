#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Google Inc.
# Copyright (C) 2009 Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains base classes representing SAML elements.

    These codes were originally written by Jeffrey Scudder for
    representing Saml elements. Takashi Matsuo had added some codes, and
    changed some. Roland Hedberg changed and added some more.

    Module objective: provide data classes for SAML constructs. These
    classes hide the XML-ness of SAML and provide a set of native Python
    classes to interact with.

    Conversions to and from XML should only be necessary when the SAML classes
    "touch the wire" and are sent over HTTP. For this reason this module 
    provides methods and functions to convert SAML classes to and from strings.
"""

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        from elementtree import ElementTree

NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'
#TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:assertion}%s'
#XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'

NAMEID_FORMAT_EMAILADDRESS = (
    "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")
URN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
NAME_FORMAT_UNSPECIFIED = (
    "urn:oasis:names:tc:SAML:2.0:attrnam-format:unspecified")
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrnam-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrnam-format:basic"
SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

VERSION = "2.0"

BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'
BINDING_PAOS = 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS'
BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
BINDING_HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'
BINDING_URI = 'urn:oasis:names:tc:SAML:2.0:bindings:URI'

def class_name(instance):
    return "%s:%s" % (instance.c_namespace, instance.c_tag)

def create_class_from_xml_string(target_class, xml_string):
    """Creates an instance of the target class from a string.
    
    :param target_class: The class which will be instantiated and populated
        with the contents of the XML. This class must have a c_tag and a
        c_namespace class variable.
    :param xml_string: A string which contains valid XML. The root element
        of the XML string should match the tag and namespace of the desired
        class.

    :return: An instance of the target class with members assigned according to
        the contents of the XML - or None if the root XML tag and namespace did 
        not match those of the target class.
    """
    tree = ElementTree.fromstring(xml_string)
    return _create_class_from_element_tree(target_class, tree)


def _create_class_from_element_tree(target_class, tree, namespace=None, 
                                    tag=None):
    """Instantiates the class and populates members according to the tree.

    Note: Only use this function with classes that have c_namespace and c_tag
    class members.

    :param target_class: The class which will be instantiated and populated
        with the contents of the XML.
    :param tree: An element tree whose contents will be converted into
        members of the new target_class instance.
    :param namespace: The namespace which the XML tree's root node must
        match. If omitted, the namespace defaults to the c_namespace of the 
        target class.
    :param tag: The tag which the XML tree's root node must match. If
        omitted, the tag defaults to the c_tag class member of the target 
        class.

    :return: An instance of the target class - or None if the tag and namespace
        of the XML tree's root node did not match the desired namespace and tag.
    """
    if namespace is None:
        namespace = target_class.c_namespace
    if tag is None:
        tag = target_class.c_tag
    if tree.tag == '{%s}%s' % (namespace, tag):
        target = target_class()
        target.harvest_element_tree(tree)
        return target
    else:
        return None

class Error(Exception):
    """Exception class thrown by this module."""
    pass

class ExtensionElement(object):
    """XML which is not part of the SAML specification,
    these are called extension elements. If a classes parser
    encounters an unexpected XML construct, it is translated into an
    ExtensionElement instance. ExtensionElement is designed to fully
    capture the information in the XML. Child nodes in an XML
    extension are turned into ExtensionElements as well.
    """
    
    def __init__(self, tag, namespace=None, attributes=None, 
            children=None, text=None):
        """Constructor for ExtensionElement

        :param namespace: The XML namespace for this element.
        :param tag: The tag (without the namespace qualifier) for
            this element. To reconstruct the full qualified name of the 
            element, combine this tag with the namespace.
        :param attributes: The attribute value string pairs for the XML 
            attributes of this element.
        :param children: list (optional) A list of ExtensionElements which
            represent the XML child nodes of this element.
        """

        self.namespace = namespace
        self.tag = tag
        self.attributes = attributes or {}
        self.children = children or []
        self.text = text
        
    def to_string(self):
        """ Serialize the object into a XML string """
        element_tree = self.transfer_to_element_tree()
        return ElementTree.tostring(element_tree, encoding="UTF-8")
        
    def transfer_to_element_tree(self):
        if self.tag is None:
            return None
            
        element_tree = ElementTree.Element('')

        if self.namespace is not None:
            element_tree.tag = '{%s}%s' % (self.namespace, self.tag)
        else:
            element_tree.tag = self.tag
            
        for key, value in self.attributes.iteritems():
            element_tree.attrib[key] = value
            
        for child in self.children:
            child.become_child_element_of(element_tree)
            
        element_tree.text = self.text
            
        return element_tree

    def become_child_element_of(self, element_tree):
        """Converts this object into an etree element and adds it as a child 
        node in an etree element.

        Adds self to the ElementTree. This method is required to avoid verbose 
        XML which constantly redefines the namespace.

        :param element_tree: ElementTree._Element The element to which this 
            object's XML will be added.
        """
        new_element = self.transfer_to_element_tree()
        element_tree.append(new_element)

    def find_children(self, tag=None, namespace=None):
        """Searches child nodes for objects with the desired tag/namespace.

        Returns a list of extension elements within this object whose tag
        and/or namespace match those passed in. To find all children in
        a particular namespace, specify the namespace but not the tag name.
        If you specify only the tag, the result list may contain extension
        elements in multiple namespaces.

        Args:
            tag: str (optional) The desired tag
            namespace: str (optional) The desired namespace

        Returns:
            A list of elements whose tag and/or namespace match the parameters
            values
        """

        results = []

        if tag and namespace:
            for element in self.children:
                if element.tag == tag and element.namespace == namespace:
                    results.append(element)
        elif tag and not namespace:
            for element in self.children:
                if element.tag == tag:
                    results.append(element)
        elif namespace and not tag:
            for element in self.children:
                if element.namespace == namespace:
                    results.append(element)
        else:
            for element in self.children:
                results.append(element)

        return results
 
        
def extension_element_from_string(xml_string):
    element_tree = ElementTree.fromstring(xml_string)
    return _extension_element_from_element_tree(element_tree)


def _extension_element_from_element_tree(element_tree):
    elementc_tag = element_tree.tag
    if '}' in elementc_tag:
        namespace = elementc_tag[1:elementc_tag.index('}')]
        tag = elementc_tag[elementc_tag.index('}')+1:]
    else: 
        namespace = None
        tag = elementc_tag
    extension = ExtensionElement(namespace=namespace, tag=tag)
    for key, value in element_tree.attrib.iteritems():
        extension.attributes[key] = value
    for child in element_tree:
        extension.children.append(_extension_element_from_element_tree(child))
    extension.text = element_tree.text
    return extension


class ExtensionContainer(object):
    
    c_tag = ""
    c_namespace = ""
    
    def __init__(self, text=None, extension_elements=None, 
                    extension_attributes=None):

        self.text = text
        self.extension_elements = extension_elements or []
        self.extension_attributes = extension_attributes or {}
 
    # Three methods to create an object from an ElementTree
    def harvest_element_tree(self, tree):
        # Fill in the instance members from the contents of the XML tree.
        for child in tree:
            self._convert_element_tree_to_member(child)
        for attribute, value in tree.attrib.iteritems():
            self._convert_element_attribute_to_member(attribute, value)
        self.text = tree.text
        
    def _convert_element_tree_to_member(self, child_tree):
        self.extension_elements.append(_extension_element_from_element_tree(
                child_tree))

    def _convert_element_attribute_to_member(self, attribute, value):
        self.extension_attributes[attribute] = value

    # One method to create an ElementTree from an object
    def _add_members_to_element_tree(self, tree):
        for child in self.extension_elements:
            child.become_child_element_of(tree)
        for attribute, value in self.extension_attributes.iteritems():
            tree.attrib[attribute] = value
        tree.text = self.text

    def find_extensions(self, tag=None, namespace=None):
        """Searches extension elements for child nodes with the desired name.

        Returns a list of extension elements within this object whose tag
        and/or namespace match those passed in. To find all extensions in
        a particular namespace, specify the namespace but not the tag name.
        If you specify only the tag, the result list may contain extension
        elements in multiple namespaces.

        :param tag: str (optional) The desired tag
        :param namespace: str (optional) The desired namespace

        :Return: A list of elements whose tag and/or namespace match the 
            parameters values
        """

        results = []

        if tag and namespace:
            for element in self.extension_elements:
                if element.tag == tag and element.namespace == namespace:
                    results.append(element)
        elif tag and not namespace:
            for element in self.extension_elements:
                if element.tag == tag:
                    results.append(element)
        elif namespace and not tag:
            for element in self.extension_elements:
                if element.namespace == namespace:
                    results.append(element)
        else:
            for element in self.extension_elements:
                results.append(element)

        return results
    

class SamlBase(ExtensionContainer):
    """A foundation class on which SAML classes are built. It 
    handles the parsing of attributes and children which are common to all
    SAML classes. By default, the SamlBase class translates all XML child 
    nodes into ExtensionElements.
    """
    
    c_children = {}
    c_attributes = {}
    c_child_order = []
    
    def _get_all_c_children_with_order(self):
        if len(self.c_child_order) > 0:
            for child in self.c_child_order:
                yield child
        else:
            for _, values in self.__class__.c_children.iteritems():
                yield values[0]
        
    def _convert_element_tree_to_member(self, child_tree):
        # Find the element's tag in this class's list of child members
        if self.__class__.c_children.has_key(child_tree.tag):
            member_name = self.__class__.c_children[child_tree.tag][0]
            member_class = self.__class__.c_children[child_tree.tag][1]
            # If the class member is supposed to contain a list, make sure the
            # matching member is set to a list, then append the new member
            # instance to the list.
            if isinstance(member_class, list):
                if getattr(self, member_name) is None:
                    setattr(self, member_name, [])
                getattr(self, member_name).append(
                        _create_class_from_element_tree(
                            member_class[0], child_tree))
            else:
                setattr(self, member_name, 
                            _create_class_from_element_tree(member_class, 
                                                            child_tree))
        else:
            ExtensionContainer._convert_element_tree_to_member(self, 
                                                                child_tree)

    def _convert_element_attribute_to_member(self, attribute, value):
        # Find the attribute in this class's list of attributes. 
        if self.__class__.c_attributes.has_key(attribute):
            # Find the member of this class which corresponds to the XML 
            # attribute(lookup in current_class.c_attributes) and set this 
            # member to the desired value (using self.__dict__).
            setattr(self, self.__class__.c_attributes[attribute], value)
        else:
            # If it doesn't appear in the attribute list it's an extension
            ExtensionContainer._convert_element_attribute_to_member(self, 
                                                            attribute, value)

    # Three methods to create an ElementTree from an object
    def _add_members_to_element_tree(self, tree):
        # Convert the members of this class which are XML child nodes. 
        # This uses the class's c_children dictionary to find the members which
        # should become XML child nodes.
        for member_name in self._get_all_c_children_with_order():
            member = getattr(self, member_name)
            if member is None:
                pass
            elif isinstance(member, list):
                for instance in member:
                    instance.become_child_element_of(tree)
            else:
                member.become_child_element_of(tree)
        # Convert the members of this class which are XML attributes.
        for xml_attribute, member_name in \
                    self.__class__.c_attributes.iteritems():
            member = getattr(self, member_name)
            if member is not None:
                tree.attrib[xml_attribute] = member
        # Lastly, call the ExtensionContainers's _add_members_to_element_tree 
        # to convert any extension attributes.
        ExtensionContainer._add_members_to_element_tree(self, tree)
        
    
    def become_child_element_of(self, tree):
        """

        Note: Only for use with classes that have a c_tag and c_namespace class 
        member. It is in SamlBase so that it can be inherited but it should
        not be called on instances of SamlBase.
        
        """
        new_child = self._to_element_tree()
        tree.append(new_child)

    def _to_element_tree(self):
        """

        Note, this method is designed to be used only with classes that have a 
        c_tag and c_namespace. It is placed in SamlBase for inheritance but 
        should not be called on in this class.

        """
        new_tree = ElementTree.Element('{%s}%s' % (self.__class__.c_namespace,
                                                    self.__class__.c_tag))
        self._add_members_to_element_tree(new_tree)
        return new_tree

    def to_string(self):
        """Converts the Saml object to a string containing XML."""
        return ElementTree.tostring(self._to_element_tree(), encoding="UTF-8")

    def __str__(self):
        return self.to_string()

    def _init_attribute(self, extension_attribute_id,
                extension_attribute_name, value=None):
                
        self.c_attributes[extension_attribute_id] = extension_attribute_name
        if value:
            self.__dict__[extension_attribute_name] = value
                    
    def keyswv(self):
        return [key for key, val in self.__dict__.items() if val]

    def keys(self):
        keys = ['text']
        keys.extend(self.c_attributes.values())
        keys.extend([v[1] for v in self.c_children.values()])
        return keys
        
    def children_with_values(self):
        childs = []
        for _, values in self.__class__.c_children.iteritems():
            member = getattr(self, values[0])
            if member is None or member == []:
                pass
            elif isinstance(member, list):
                for instance in member:
                    childs.append(instance)
            else:
                childs.append(member)
        return childs
        
def extension_element_to_element(extension_element, translation_function,
                                    namespace=None):
    """ """
    element_namespace = extension_element.namespace
    if element_namespace == namespace:
        try:
            ets = translation_function[extension_element.tag]
            return ets(extension_element.to_string())
        except KeyError:
            pass
            
    return None
        