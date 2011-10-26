#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2011 Umeå University
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
import xmlenc

from saml2 import saml

from saml2.time_util import instant, in_a_while
from saml2.attribute_converter import from_local

from saml2.s_utils import sid, MissingValue
from saml2.s_utils import factory
from saml2.s_utils import assertion_factory


def _filter_values(vals, vlist=None, must=False):
    """ Removes values from *vals* that does not appear in vlist
    
    :param vals: The values that are to be filtered
    :param vlist: required or optional value
    :param must: Whether the allowed values must appear
    :return: The set of values after filtering
    """
    
    if not vlist: # No value specified equals any value
        return vals
    
    if isinstance(vlist, basestring):
        vlist = [vlist]
        
    res = []
    
    for val in vlist:
        if val in vals:
            res.append(val)
    
    if must:
        if res:
            return res
        else:
            raise MissingValue("Required attribute value missing")
    else:
        return res


def filter_on_attributes(ava, required=None, optional=None):
    """ Filter
    
    :param ava: An attribute value assertion as a dictionary
    :param required: list of RequestedAttribute instances defined to be 
        required
    :param optional: list of     RequestedAttribute instances defined to be 
        optional
    :return: The modified attribute value assertion
    """
    res = {}
    
    if required is None:
        required = []
        
    for attr in required:
        if attr.friendly_name in ava:
            values = [av.text for av in attr.attribute_value]
            res[attr.friendly_name] = _filter_values(ava[attr.friendly_name], values, True)
        elif attr.name in ava:
            values = [av.text for av in attr.attribute_value]
            res[attr.name] = _filter_values(ava[attr.name], values, True)
        else:
            print >> sys.stderr, ava.keys()
            raise MissingValue("Required attribute missing: '%s'" % (attr.friendly_name,))

    if optional is None:
        optional = []
        
    for attr in optional:
        if attr.friendly_name in ava:
            values = [av.text for av in attr.attribute_value]
            try:
                res[attr.friendly_name].extend(_filter_values(ava[attr.friendly_name], values))
            except KeyError:
                res[attr.friendly_name] = _filter_values(ava[attr.friendly_name], values)
        elif attr.name in ava:
            values = [av.text for av in attr.attribute_value]
            try:
                res[attr.name].extend(_filter_values(ava[attr.name], values))
            except KeyError:
                res[attr.name] = _filter_values(ava[attr.name], values)
    
    return res

def filter_on_demands(ava, required=None, optional=None):
    """ Never return more than is needed. Filters out everything
    the server is prepared to return but the receiver doesn't ask for
    
    :param ava: Attribute value assertion as a dictionary
    :param required: Required attributes
    :param optional: Optional attributes
    :return: The possibly reduced assertion
    """
    
    # Is all what's required there:
    if required is None:
        required = {}
        
    for attr, vals in required.items():
        if attr in ava:
            if vals:
                for val in vals:
                    if val not in ava[attr]:
                        raise MissingValue(
                            "Required attribute value missing: %s,%s" % (attr,
                                                                        val))
        else:
            raise MissingValue("Required attribute missing: %s" % (attr,))

    if optional is None:
        optional = {}
        
    # OK, so I can imaging releasing values that are not absolutely necessary
    # but not attributes
    for attr, vals in ava.items():
        if attr not in required and attr not in optional:
            del ava[attr]
    
    return ava

def filter_on_wire_representation(ava, acs, required=None, optional=None):
    """
    :param ava: A dictionary with attributes and values
    :param required: A list of saml.Attributes
    :param optional: A list of saml.Attributes
    :return: Dictionary of expected/wanted attributes and values
    """
    acsdic = dict([(ac.name_format, ac) for ac in acs])

    if required is None:
        required = []
    if optional is None:
        optional = []

    res = {}
    for attr, val in ava.items():
        done = False
        for req in required:
            try:
                _name = acsdic[req.name_format]._to[attr]
                if _name == req.name:
                    res[attr] = val
                    done = True
            except KeyError:
                pass
        if done:
            continue
        for opt in optional:
            try:
                _name = acsdic[opt.name_format]._to[attr]
                if _name == opt.name:
                    res[attr] = val
                    break
            except KeyError:
                pass

    return res

def filter_attribute_value_assertions(ava, attribute_restrictions=None):
    """ Will weed out attribute values and values according to the
    rules defined in the attribute restrictions. If filtering results in
    an attribute without values, then the attribute is removed from the
    assertion.
    
    :param ava: The incoming attribute value assertion (dictionary)
    :param attribute_restrictions: The rules that govern which attributes
        and values that are allowed. (dictionary)
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
            if spec is None:
                continue
            
            try:
                restr = spec["attribute_restrictions"]
            except KeyError:
                continue
            
            if restr is None:
                continue
            
            for key, values in restr.items():
                if not values:
                    spec["attribute_restrictions"][key] = None
                    continue
                
                spec["attribute_restrictions"][key] = \
                        [re.compile(value) for value in values]
        
        return self._restrictions
    
    def get_nameid_format(self, sp_entity_id):
        """ Get the NameIDFormat to used for the entity id 
        :param: The SP entity ID
        :retur: The format
        """
        try:
            form = self._restrictions[sp_entity_id]["nameid_format"]
        except KeyError:
            try:
                form = self._restrictions["default"]["nameid_format"]
            except KeyError:
                form = saml.NAMEID_FORMAT_TRANSIENT
        
        return form
    
    def get_name_form(self, sp_entity_id):
        """ Get the NameFormat to used for the entity id 
        :param: The SP entity ID
        :retur: The format
        """
        form = ""
        
        try:
            form = self._restrictions[sp_entity_id]["name_form"]
        except TypeError:
            pass
        except KeyError:
            try:
                form = self._restrictions["default"]["name_form"]
            except KeyError:
                pass
        
        return form
    
    def get_lifetime(self, sp_entity_id):
        """ The lifetime of the assertion 
        :param sp_entity_id: The SP entity ID
        :param: lifetime as a dictionary 
        """
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
        """ Return the attribute restriction for SP that want the information
        
        :param sp_entity_id: The SP entity ID
        :return: The restrictions
        """
        
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
    
    def not_on_or_after(self, sp_entity_id):
        """ When the assertion stops being valid, should not be
        used after this time.
        
        :param sp_entity_id: The SP entity ID
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
        :param optional: Attributes that the SP regards as optional
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
            #(required, optional) = metadata.wants(sp_entity_id)
        else:
            required = optional = None
        
        return self.filter(ava, sp_entity_id, required, optional)
    
    def conditions(self, sp_entity_id):
        """ Return a saml.Condition instance
        
        :param sp_entity_id: The SP entity ID
        :return: A saml.Condition instance
        """
        return factory( saml.Conditions,
                        not_before=instant(),
                        # How long might depend on who's getting it
                        not_on_or_after=self.not_on_or_after(sp_entity_id),
                        audience_restriction=[factory( saml.AudienceRestriction,
                                audience=factory(saml.Audience, 
                                                text=sp_entity_id))])

class Assertion(dict):
    """ Handles assertions about subjects """
    
    def __init__(self, dic=None):
        dict.__init__(self, dic)
    
    def _authn_context_decl_ref(self, authn_class):
        # authn_class: saml.AUTHN_PASSWORD
        return factory(saml.AuthnContext, 
                        authn_context_decl_ref=factory(
                                saml.AuthnContextDeclRef, text=authn_class))

    def _authn_context_class_ref(self, authn_class, authn_auth=None):
        # authn_class: saml.AUTHN_PASSWORD
        cntx_class = factory(saml.AuthnContextClassRef, text=authn_class)
        if authn_auth:
            return factory(saml.AuthnContext, 
                            authn_context_class_ref=cntx_class,
                            authenticating_authority=factory(
                                                saml.AuthenticatingAuthority,
                                                text=authn_auth))
        else:
            return factory(saml.AuthnContext, 
                            authn_context_class_ref=cntx_class)
        
    def _authn_statement(self, authn_class=None, authn_auth=None, 
                            authn_decl=None):
        if authn_class:
            return factory(saml.AuthnStatement, 
                        authn_instant=instant(), 
                        session_index=sid(),
                        authn_context=self._authn_context_class_ref(
                                                    authn_class, authn_auth))
        elif authn_decl:
            return factory(saml.AuthnStatement, 
                        authn_instant=instant(), 
                        session_index=sid(),
                        authn_context=self._authn_context_decl_ref(authn_decl))
        else:
            return factory(saml.AuthnStatement,
                        authn_instant=instant(), 
                        session_index=sid())

    def construct(self, sp_entity_id, in_response_to, consumer_url,
                    name_id, attrconvs, policy, issuer, authn_class=None, 
                    authn_auth=None, authn_decl=None, encrypt=None,
                    sec_context=None):
        """ Construct the Assertion 
        
        :param sp_entity_id: The entityid of the SP
        :param in_response_to: An identifier of the message, this message is 
            a response to
        :param consumer_url: The intended consumer of the assertion
        :param name_id: An NameID instance
        :param attrconvs: AttributeConverters
        :param policy: The policy that should be adhered to when replying
        :param issuer: Who is issuing the statement
        :param authn_class: The authentication class
        :param authn_auth: The authentication instance
        :param encrypt: Whether to encrypt parts or all of the Assertion
        :param sec_context: The security context used when encrypting
        :return: An Assertion instance
        """
        attr_statement = saml.AttributeStatement(attribute=from_local(
                                attrconvs, self, 
                                policy.get_name_form(sp_entity_id)))

        if encrypt == "attributes":
            for attr in attr_statement.attribute:
                enc = sec_context.encrypt(text="%s" % attr)

                encd = xmlenc.encrypted_data_from_string(enc)
                encattr = saml.EncryptedAttribute(encrypted_data=encd)
                attr_statement.encrypted_attribute.append(encattr)

            attr_statement.attribute = []

        # start using now and for some time
        conds = policy.conditions(sp_entity_id)
        
        return assertion_factory(
            issuer=issuer,
            attribute_statement = attr_statement,
            authn_statement = self._authn_statement(authn_class, authn_auth, 
                                                    authn_decl),
            conditions = conds,
            subject=factory( saml.Subject,
                name_id=name_id,
                subject_confirmation=factory( saml.SubjectConfirmation,
                                method=saml.SUBJECT_CONFIRMATION_METHOD_BEARER,
                                subject_confirmation_data=factory(
                                    saml.SubjectConfirmationData,
                                    in_response_to=in_response_to,
                                    recipient=consumer_url,
                                    not_on_or_after=policy.not_on_or_after(
                                                            sp_entity_id)))),
            )
    
    def apply_policy(self, sp_entity_id, policy, metadata=None):
        """ Apply policy to the assertion I'm representing 
        
        :param sp_entity_id: The SP entity ID
        :param policy: The policy
        :param metadata: Metadata to use
        :return: The resulting AVA after the policy is applied
        """
        return policy.restrict(self, sp_entity_id, metadata)
