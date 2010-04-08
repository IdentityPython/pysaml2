#!/usr/bin/python
# -*- coding: utf-8 -*-
#
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

import re
import sys

from saml2 import saml

from saml2.time_util import instant, in_a_while
from saml2.attribute_converter import from_local

from saml2.utils import sid, MissingValue
from saml2.utils import args2dict
from saml2.utils import assertion_factory

def _filter_values(vals, required=None, optional=None):
    """ Removes values from *val* that does not appear in *attributes*.
    
    :param val: The values that are to be filtered
    :param required: The required values
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
            a = set(rvals)
            raise MissingValue("Required attribute value missing")
    else:
        return valo
    
def _combine(required=None, optional=None):
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
    comb = _combine(required, optional)
    for attr, vals in comb.items():
        if attr[0] in ava:
            res[attr[0]] = _filter_values(ava[attr[0]], vals[0], vals[1])
        elif attr[1] in ava:
            res[attr[1]] = _filter_values(ava[attr[1]], vals[0], vals[1])
        else:
            print >> sys.stderr, ava.keys()
            raise MissingValue("Required attribute missing: '%s'" % (attr,))
    
    return res

def filter_attribute_value_assertions(ava, attribute_restrictions=None):
    """ Will weed out attribute values and values according to the 
    rules defined in the attribute restrictions. If filtering results in 
    an attribute without values, then the attribute is removed from the
    assertion.
    
    :param ava: The incoming attribute value assertion
    :param attribute_restrictions: The rules that govern which attributes
        and values that are allowed.
    :return: The modified attribute value assertion
    """
    if not attribute_restrictions:
        return ava
        
    for attr, vals in ava.items():
        if attr in attribute_restrictions:
            if attribute_restrictions[attr]:
                rvals = []
                for restr in attribute_restrictions[attr]:
                    for val in vals:
                        if restr.match(val):
                            rvals.append(val)
                
                if rvals:
                    ava[attr] = list(set(rvals))
                else:
                    del ava[attr]
        else:
            del ava[attr]
    return ava
    
class Policy(object):
    """ handles restrictions on assertions """
    
    def __init__(self, restrictions=None):
        if restrictions:
            self.compile(restrictions)
        else:
            self._restrictions = None
            
    def compile(self, restrictions):
        """ This is only for IdPs or AAs, and it's about limiting what
        is returned to the SP. 
        In the configuration file, restrictions on which values that 
        can be returned are specified with the help of regular expressions.
        This function goes through and pre-compiles the regular expressions.
        
        :param restrictions:
        :return: The assertion with the string specification replaced with
            a compiled regular expression.
        """
        
        self._restrictions = restrictions.copy()
        
        for _, spec in self._restrictions.items():
            if spec == None:
                continue
                
            try:
                restr = spec["attribute_restrictions"]
            except KeyError:
                continue
                
            if restr == None:
                continue
                
            for key, values in restr.items():
                if not values:
                    spec["attribute_restrictions"][key] = None
                    continue
                                    
                spec["attribute_restrictions"][key] = \
                        [re.compile(value) for value in values]
        
        return self._restrictions

    def get_nameid_format(self, sp_entity_id):
        try:
            form = self._restrictions[sp_entity_id]["nameid_format"]
        except KeyError:
            try:
                form = self._restrictions["default"]["nameid_format"]
            except KeyError:
                form = saml.NAMEID_FORMAT_TRANSIENT
                
        return form
    
    def get_name_form(self, sp_entity_id):
        form = ""
        
        try:
            form = self._restrictions[sp_entity_id]["name_form"]
        except KeyError:
            try:
                form = self._restrictions["default"]["name_form"]
            except KeyError:
                pass
                
        return form
    
    def get_lifetime(self, sp_entity_id):
        # default is a hour
        spec = {"hours":1}
        if not self._restrictions:
            return spec
            
        try:
            spec = self._restrictions[sp_entity_id]["lifetime"]
        except KeyError:
            try:
                spec = self._restrictions["default"]["lifetime"]
            except KeyError:
                pass
                
        return spec
        
    def get_attribute_restriction(self, sp_entity_id):
        if not self._restrictions:
            return None
            
        try:
            try:
                restrictions = self._restrictions[sp_entity_id][
                                                "attribute_restrictions"]
            except KeyError:
                try:
                    restrictions = self._restrictions["default"][
                                                "attribute_restrictions"]
                except KeyError:
                    restrictions = None
        except KeyError:
            restrictions = None

        return restrictions
        
    def _not_on_or_after(self, sp_entity_id):
        """ When the assertion stops being valid, should not be
        used after this time.
        
        :return: String representation of the time
        """
        
        return in_a_while(**self.get_lifetime(sp_entity_id))

    def filter(self, ava, sp_entity_id, required=None, optional=None):
        """ What attribute and attribute values returns depends on what
        the SP has said it wants in the request or in the metadata file and
        what the IdP/AA wants to release. An assumption is that what the SP
        asks for overrides whatever is in the metadata. But of course the 
        IdP never releases anything it doesn't want to.    
        
        :param ava: The information about the subject as a dictionary
        :param sp_entity_id: The entity ID of the SP
        :param required: Attributes that the SP requires in the assertion
        :param optional: Attributes that the SP thinks is optional
        :return: A possibly modified AVA
        """

                                
        ava = filter_attribute_value_assertions(ava, 
                                    self.get_attribute_restriction(sp_entity_id))

        if required or optional:
            ava = filter_on_attributes(ava, required, optional)
            
        return ava

    def restrict(self, ava, sp_entity_id, metadata=None):
        """ Identity attribute names are expected to be expressed in 
        the local lingo (== friendlyName)
        
        :return: A filtered ava according to the IdPs/AAs rules and
            the list of required/optional attributes according to the SP.
            If the requirements can't be met an exception is raised.
        """
        if metadata:
            (required, optional) = metadata.attribute_consumer(sp_entity_id)
        else:
            required = optional = None
            
        return self.filter(ava, sp_entity_id, required, optional)
    
    def conditions(self, sp_entity_id):
        return args2dict(
                        not_before=instant(), 
                        # How long might depend on who's getting it
                        not_on_or_after=self._not_on_or_after(sp_entity_id), 
                        audience_restriction=args2dict(
                                audience=args2dict(sp_entity_id)))

class Assertion(dict):
    """ Handles assertions about subjects """
    
    def __init__(self, dic=None):
        dict.__init__(self, dic)
        
    def _authn_statement(self):
        return args2dict(authn_instant=instant(), session_index=sid())

    def construct(self, sp_entity_id, in_response_to, name_id, attrconvs, 
                    policy, issuer):
    
        attr_statement = from_local(attrconvs, self,
                                    policy.get_name_form(sp_entity_id))

        # start using now and for a hour
        conds = policy.conditions(sp_entity_id)
        
        return assertion_factory(
            issuer=issuer,
            attribute_statement = attr_statement,
            authn_statement = self._authn_statement(),
            conditions = conds,
            subject=args2dict(
                name_id=name_id,
                method=saml.SUBJECT_CONFIRMATION_METHOD_BEARER,
                subject_confirmation=args2dict(
                    subject_confirmation_data = \
                        args2dict(in_response_to=in_response_to))),
            )
                    
    def apply_policy(self, sp_entity_id, policy, metadata=None):
        return policy.restrict(self, sp_entity_id, metadata)
