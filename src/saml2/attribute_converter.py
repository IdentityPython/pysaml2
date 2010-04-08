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
from saml2.utils import args2dict

class UnknownNameFormat(Exception):
    pass

def ac_factory(path):
    acs = []

    for tup in os.walk(path):
        if tup[2]:
            ac = AttributeConverter(os.path.basename(tup[0]))
            for name in tup[2]:
                fname = os.path.join(tup[0], name)
                if name.endswith(".py"):
                    name = name[:-3]
                ac.set(name,fname)
            ac.adjust()
            acs.append(ac)
    return acs
    
def to_local(acs, statement):
    ava = []
    for ac in acs:
        try:
            ava = ac.fro(statement)
            break
        except UnknownNameFormat:
            pass
    return ava

def from_local(acs, ava, name_format):
    for ac in acs:
        #print ac.format, name_format
        if ac.format == name_format:
            #print "Found a name_form converter"
            return ac.to(ava)
            
    return None
    
class AttributeConverter(object):
    """ Converts from an attribute statement to a key,value dictionary and
        vice-versa """
        
    def __init__(self, format=""):
        self.format = format
        
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
        if self._fro == None and self.to != None:
            self._fro = dict([(value, key) for key, value in self._to.items()])
        if self._to == None and self.fro != None:
            self._to = dict([(value, key) for key, value in self._fro.items()])
    
    def fro(self, statement):
        """ Get the attributes and the attribute values 
        
        :param statement: The AttributeStatement.
        :return: A dictionary containing attributes and values
        """
        
        result = {}
        for attribute in statement.attribute:
            if self.format and attribute.name_format != self.format:
                raise UnknownNameFormat
                
            try:
                name = self._fro[attribute.name.strip()]
            except (AttributeError, KeyError):
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
        
    def to(self, ava):
        attributes = []
        for key, value in ava.items():
            try:
                attributes.append(args2dict(name=self._to[key],
                                            name_format=self.format,
                                            friendly_name=key,
                                            attribute_value=value))
            except KeyError:
                # TODO
                # Should this be made different ???
                attributes.append(args2dict(name=key,
                                            attribute_value=value))
        
        return {"attribute": attributes}