#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) s2010-2011 Umeå University
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

import os
import sys
from importlib import import_module

from saml2.s_utils import factory, do_ava
from saml2 import saml
from saml2.saml import NAME_FORMAT_URI

class UnknownNameFormat(Exception):
    pass

def load_maps(dirspec):
    """ load the attribute maps

    :param dirspec: a directory specification
    :return: a dictionary with the name of the map as key and the
        map as value. The map itself is a dictionary with two keys:
        "to" and "fro". The values for those keys are the actual mapping.
    """
    map = {}
    if dirspec not in sys.path:
        sys.path.insert(0, dirspec)

    for fil in os.listdir(dirspec):
        if fil.endswith(".py"):
            mod = import_module(fil[:-3])
            for key, item in mod.__dict__.items():
                if key.startswith("__"):
                    continue
                if isinstance(item, dict) and "to" in item and "fro" in item:
                    map[item["identifier"]] = item

    return map

def ac_factory(path=""):
    """Attribute Converter factory

    :param path: The path to a directory where the attribute maps are expected
        to reside.
    :return: A AttributeConverter instance
    """
    acs = []

    if path:
        if path not in sys.path:
            sys.path.insert(0, path)

        for fil in os.listdir(path):
            if fil.endswith(".py"):
                mod = import_module(fil[:-3])
                for key, item in mod.__dict__.items():
                    if key.startswith("__"):
                        continue
                    if isinstance(item, dict) and "to" in item and "fro" in item:
                        atco = AttributeConverter(item["identifier"])
                        atco.from_dict(item)
                        acs.append(atco)
    else:
        for map in ["basic", "saml_uri", "shibboleth_uri"]:
            mod = import_module(".%s" % map, "saml2.attributemaps")
            for key, item in mod.__dict__.items():
                if key.startswith("__"):
                    continue
                if isinstance(item, dict) and "to" in item and "fro" in item:
                    atco = AttributeConverter(item["identifier"])
                    atco.from_dict(item)
                    acs.append(atco)

    return acs

def ac_factory_II(path):
    return ac_factory(path)

#def ac_factory_old(path):
#    acs = []
#
#    for dir_name, directories, files in os.walk(path):
#        for d in list(directories):
#            if d.startswith('.'):
#                directories.remove(d)
#
#        if files:
#            atco = AttributeConverter(os.path.basename(dir_name))
#            for name in files:
#                fname = os.path.join(dir_name, name)
#                if name.endswith(".py"):
#                    name = name[:-3]
#                atco.set(name, fname)
#            atco.adjust()
#            acs.append(atco)
#    return acs
    
def ava_fro(acs, statement):
    """  Translates attributes according to their name_formats into the local
     names.

    :param acs: AttributeConverter instances
    :param statement: A SAML statement
    :return: A dictionary with attribute names replaced with local names.
    """
    if not statement:
        return {}
        
    acsdic = dict([(ac.name_format, ac) for ac in acs])
    acsdic[None] = acsdic[NAME_FORMAT_URI]    
    return dict([acsdic[a.name_format].ava_from(a) for a in statement])

def to_local(acs, statement):
    """ Replaces the attribute names in a attribute value assertion with the
    equivalent name from a local name format.

    """
    if not acs:
        acs = [AttributeConverter()]
        
    ava = []
    for aconv in acs:
        try:
            ava = aconv.fro(statement)
            break
        except UnknownNameFormat:
            pass
    return ava

def from_local(acs, ava, name_format):
    for aconv in acs:
        #print ac.format, name_format
        if aconv.name_format == name_format:
            #print "Found a name_form converter"
            return aconv.to_(ava)
            
    return None
    
def from_local_name(acs, attr, name_format):
    """
    :param acs: List of AttributeConverter instances
    :param attr: attribute name as string
    :param name_format: Which name-format it should be translated to
    :return: An Attribute instance
    """
    for aconv in acs:
        #print ac.format, name_format
        if aconv.name_format == name_format:
            #print "Found a name_form converter"
            return aconv.to_format(attr)
    return attr
    
def to_local_name(acs, attr):
    """
    :param acs: List of AttributeConverter instances
    :param attr: an Attribute instance
    :return: The local attribute name
    """
    for aconv in acs:
        lattr = aconv.from_format(attr)
        if lattr:
            return lattr

    return attr.friendly_name
    
class AttributeConverter(object):
    """ Converts from an attribute statement to a key,value dictionary and
        vice-versa """
        
    def __init__(self, name_format=""):
        self.name_format = name_format
        self._to = None
        self._fro = None
        
#    def set(self, name, filename):
#        if name == "to":
#            self.set_to(filename)
#        elif name == "fro":
#            self.set_fro(filename)
#        # else ignore
#
#    def set_fro(self, filename):
#        self._fro = eval(open(filename).read())
#
#    def set_to(self, filename):
#        self._to = eval(open(filename).read())
#
    def adjust(self):
        """ If one of the transformations is not defined it is expected to
        be the mirror image of the other.
        """
        
        if self._fro is None and self._to is not None:
            self._fro = dict([(value, key) for key, value in self._to.items()])
        if self._to is None and self.fro is not None:
            self._to = dict([(value, key) for key, value in self._fro.items()])

    def from_dict(self, mapdict):
        """ Import the attribute map from  a dictionary

        :param mapdict: The dictionary
        """

        self.name_format = mapdict["identifier"]
        try:
            self._fro = mapdict["fro"]
        except KeyError:
            pass
        try:
            self._to = mapdict["to"]
        except KeyError:
            pass

        if self._fro is None and self._to is None:
            raise Exception("Missing specifications")

        if self._fro is None or self._to is None:
            self.adjust()

        
    def fail_safe_fro(self, statement):
        """ In case there is not formats defined """
        result = {}
        for attribute in statement.attribute:
            try:
                name = attribute.friendly_name.strip()
            except AttributeError:
                name = attribute.name.strip()

            result[name] = []
            for value in attribute.attribute_value:
                if not value.text:
                    result[name].append('')
                else:
                    result[name].append(value.text.strip())    
        return result
        
    def ava_from(self, attribute):
        try:
            attr = self._fro[attribute.name.strip()]
        except (AttributeError, KeyError):
            try:
                attr = attribute.friendly_name.strip()
            except AttributeError:
                attr = attribute.name.strip()

        val = []
        for value in attribute.attribute_value:
            if not value.text:
                val.append('')
            else:
                val.append(value.text.strip())

        return attr, val
        
    def fro(self, statement):
        """ Get the attributes and the attribute values 
        
        :param statement: The AttributeStatement.
        :return: A dictionary containing attributes and values
        """
        
        if not self.name_format:
            return self.fail_safe_fro(statement)
            
        result = {}
        for attribute in statement.attribute:
            if attribute.name_format and self.name_format and \
                attribute.name_format != self.name_format:
                raise UnknownNameFormat
                
            (key, val) = self.ava_from(attribute)
            result[key] = val
            
        if not result:
            return self.fail_safe_fro(statement) 
        else:
            return result
        
    def to_format(self, attr):
        """ Creates an Attribute instance with name, name_format and
        friendly_name

        :param attr: The local name of the attribute
        :return: An Attribute instance
        """
        try:
            return factory(saml.Attribute,
                            name=self._to[attr], 
                            name_format=self.name_format,
                            friendly_name=attr)
        except KeyError:
            return factory(saml.Attribute, name=attr)
    
    def from_format(self, attr):
        """ Find out the local name of an attribute
         
        :param attr: An saml.Attribute instance
        :return: The local attribute name or "" if no mapping could be made
        """
        if attr.name_format:
            if self.name_format == attr.name_format:
                try:
                    return self._fro[attr.name]
                except KeyError:
                    pass
        else: #don't know the name format so try all I have
            try:
                return self._fro[attr.name]
            except KeyError:
                pass

        return ""
        
    def to_(self, attrvals):
        """ Create a list of Attribute instances.

        :param attrvals: A dictionary of attributes and values
        :return: A list of Attribute instances
        """
        attributes = []
        for key, value in attrvals.items():
            try:
                attributes.append(factory(saml.Attribute,
                                            name=self._to[key],
                                            name_format=self.name_format,
                                            friendly_name=key,
                                            attribute_value=do_ava(value)))
            except KeyError:
                attributes.append(factory(saml.Attribute,
                                            name=key,
                                            attribute_value=do_ava(value)))
        
        return attributes
