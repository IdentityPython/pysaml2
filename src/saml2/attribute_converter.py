#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Umeå University
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
from saml2.s_utils import factory, do_ava
from saml2 import saml
from saml2.saml import NAME_FORMAT_URI

class UnknownNameFormat(Exception):
    pass

def ac_factory(path):
    acs = []

    for tup in os.walk(path):
        if tup[2]:
            atco = AttributeConverter(os.path.basename(tup[0]))
            for name in tup[2]:
                fname = os.path.join(tup[0], name)
                if name.endswith(".py"):
                    name = name[:-3]
                atco.set(name, fname)
            atco.adjust()
            acs.append(atco)
    return acs
    
def ava_fro(acs, statement):
    """ translates attributes according to their name_formats """
    if statement == []:
        return {}
        
    acsdic = dict([(ac.name_format, ac) for ac in acs])
    acsdic[None] = acsdic[NAME_FORMAT_URI]    
    return dict([acsdic[a.name_format].ava_fro(a) for a in statement])

def to_local(acs, statement):
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
        
    def set(self, name, filename):
        if name == "to":
            self.set_to(filename)
        elif name == "fro":
            self.set_fro(filename)
        # else ignore
        
    def set_fro(self, filename):
        self._fro = eval(open(filename).read())

    def set_to(self, filename):
        self._to = eval(open(filename).read())

    def adjust(self):
        if self._fro == None and self._to != None:
            self._fro = dict([(value, key) for key, value in self._to.items()])
        if self._to == None and self.fro != None:
            self._to = dict([(value, key) for key, value in self._fro.items()])
    
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
        
    def ava_fro(self, attribute):
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

        return (attr, val)
        
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
                
            (key, val) = self.ava_fro(attribute)
            result[key] = val
            
        if not result:
            return self.fail_safe_fro(statement) 
        else:
            return result
        
    def to_format(self, attr):
        try:
            return factory(saml.Attribute,
                            name=self._to[attr], 
                            name_format=self.name_format)
                            # friendly_name=attr)
        except KeyError:
            return factory(saml.Attribute, name=attr)
    
    def from_format(self, attr):
        """
        :param attr: An saml.Attribute instance
        :return: The local attribute name or "" if no mapping could be made
        """
        if self.name_format == attr.name_format:
            try:
                return self._fro[attr.name]
            except KeyError:
                pass
        return ""
        
    def to_(self, attrvals):
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