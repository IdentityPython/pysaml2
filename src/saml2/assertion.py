#!/usr/bin/env python
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
import importlib
import logging

import re
from saml2.saml import NAME_FORMAT_URI
import xmlenc

from saml2 import saml

from saml2.time_util import instant, in_a_while
from saml2.attribute_converter import from_local
from saml2.s_utils import sid, MissingValue
from saml2.s_utils import factory
from saml2.s_utils import assertion_factory


logger = logging.getLogger(__name__)


def _filter_values(vals, vlist=None, must=False):
    """ Removes values from *vals* that does not appear in vlist
    
    :param vals: The values that are to be filtered
    :param vlist: required or optional value
    :param must: Whether the allowed values must appear
    :return: The set of values after filtering
    """
    
    if not vlist:  # No value specified equals any value
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


def _match(attr, ava):
    if attr in ava:
        return attr

    _la = attr.lower()
    if _la in ava:
        return _la

    for _at in ava.keys():
        if _at.lower() == _la:
            return _at

    return None


def filter_on_attributes(ava, required=None, optional=None):
    """ Filter
    
    :param ava: An attribute value assertion as a dictionary
    :param required: list of RequestedAttribute instances defined to be 
        required
    :param optional: list of RequestedAttribute instances defined to be
        optional
    :return: The modified attribute value assertion
    """
    res = {}
    
    if required is None:
        required = []

    for attr in required:
        found = False
        nform = ""
        for nform in ["friendly_name", "name"]:
            try:
                _fn = _match(attr[nform], ava)
            except KeyError:
                pass
            else:
                if _fn:
                    try:
                        values = [av["text"] for av in attr["attribute_value"]]
                    except KeyError:
                        values = []
                    res[_fn] = _filter_values(ava[_fn], values, True)
                    found = True
                    break

        if not found:
            raise MissingValue("Required attribute missing: '%s'" % (
                attr[nform],))

    if optional is None:
        optional = []

    for attr in optional:
        for nform in ["friendly_name", "name"]:
            if nform in attr:
                _fn = _match(attr[nform], ava)
                if _fn:
                    try:
                        values = [av["text"] for av in attr["attribute_value"]]
                    except KeyError:
                        values = []
                    try:
                        res[_fn].extend(_filter_values(ava[_fn], values))
                    except KeyError:
                        res[_fn] = _filter_values(ava[_fn], values)
    
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

    lava = dict([(k.lower(), k) for k in ava.keys()])

    for attr, vals in required.items():
        attr = attr.lower()
        if attr in lava:
            if vals:
                for val in vals:
                    if val not in ava[lava[attr]]:
                        raise MissingValue(
                            "Required attribute value missing: %s,%s" % (attr,
                                                                         val))
        else:
            raise MissingValue("Required attribute missing: %s" % (attr,))

    if optional is None:
        optional = {}

    oka = [k.lower() for k in required.keys()]
    oka.extend([k.lower() for k in optional.keys()])

    # OK, so I can imaging releasing values that are not absolutely necessary
    # but not attributes that are not asked for.
    for attr in lava.keys():
        if attr not in oka:
            del ava[lava[attr]]
    
    return ava


def filter_on_wire_representation(ava, acs, required=None, optional=None):
    """
    :param ava: A dictionary with attributes and values
    :param acs: List of tuples (Attribute Converter name,
        Attribute Converter instance)
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
        _attr = attr.lower()
        try:
            _rests = attribute_restrictions[_attr]
        except KeyError:
            del ava[attr]
        else:
            if _rests is None:
                continue
            if isinstance(vals, basestring):
                vals = [vals]
            rvals = []
            for restr in _rests:
                for val in vals:
                    if restr.match(val):
                        rvals.append(val)

            if rvals:
                ava[attr] = list(set(rvals))
            else:
                del ava[attr]
    return ava


def restriction_from_attribute_spec(attributes):
    restr = {}
    for attribute in attributes:
        restr[attribute.name] = {}
        for val in attribute.attribute_value:
            if not val.text:
                restr[attribute.name] = None
                break
            else:
                restr[attribute.name] = re.compile(val.text)
    return restr


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
        
        for who, spec in self._restrictions.items():
            if spec is None:
                continue
            try:
                items = spec["entity_categories"]
            except KeyError:
                pass
            else:
                ecs = []
                for cat in items:
                    _mod = importlib.import_module(
                        "saml2.entity_category.%s" % cat)
                    _ec = {}
                    for key, items in _mod.RELEASE.items():
                        _ec[key] = [k.lower() for k in items]
                    ecs.append(_ec)
                spec["entity_categories"] = ecs
            try:
                restr = spec["attribute_restrictions"]
            except KeyError:
                continue

            if restr is None:
                continue

            _are = {}
            for key, values in restr.items():
                if not values:
                    _are[key.lower()] = None
                    continue

                _are[key.lower()] = [re.compile(value) for value in values]
            spec["attribute_restrictions"] = _are
        logger.debug("policy restrictions: %s" % self._restrictions)

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
        form = NAME_FORMAT_URI
        
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
        spec = {"hours": 1}
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

    def entity_category_attributes(self, ec):
        if not self._restrictions:
            return None

        ec_maps = self._restrictions["default"]["entity_categories"]
        for ec_map in ec_maps:
            try:
                return ec_map[ec]
            except KeyError:
                pass
        return []

    def get_entity_categories_restriction(self, sp_entity_id, mds):
        if not self._restrictions:
            return None

        restrictions = {}
        ec_maps = []
        try:
            try:
                ec_maps = self._restrictions[sp_entity_id]["entity_categories"]
            except KeyError:
                try:
                    ec_maps = self._restrictions["default"]["entity_categories"]
                except KeyError:
                    pass
        except KeyError:
            pass

        if ec_maps:
            # always released
            for ec_map in ec_maps:
                try:
                    attrs = ec_map[""]
                except KeyError:
                    pass
                else:
                    for attr in attrs:
                        restrictions[attr] = None

            if mds:
                try:
                    ecs = mds.entity_categories(sp_entity_id)
                except KeyError:
                    pass
                else:
                    for ec in ecs:
                        for ec_map in ec_maps:
                            try:
                                attrs = ec_map[ec]
                            except KeyError:
                                pass
                            else:
                                for attr in attrs:
                                    restrictions[attr] = None

        return restrictions

    def not_on_or_after(self, sp_entity_id):
        """ When the assertion stops being valid, should not be
        used after this time.
        
        :param sp_entity_id: The SP entity ID
        :return: String representation of the time
        """
        
        return in_a_while(**self.get_lifetime(sp_entity_id))
    
    def filter(self, ava, sp_entity_id, mdstore, required=None, optional=None):
        """ What attribute and attribute values returns depends on what
        the SP has said it wants in the request or in the metadata file and
        what the IdP/AA wants to release. An assumption is that what the SP
        asks for overrides whatever is in the metadata. But of course the
        IdP never releases anything it doesn't want to.
        
        :param ava: The information about the subject as a dictionary
        :param sp_entity_id: The entity ID of the SP
        :param mdstore: A Metadata store
        :param required: Attributes that the SP requires in the assertion
        :param optional: Attributes that the SP regards as optional
        :return: A possibly modified AVA
        """

        _rest = self.get_attribute_restriction(sp_entity_id)
        if _rest is None:
            _rest = self.get_entity_categories_restriction(sp_entity_id,
                                                           mdstore)
        logger.debug("filter based on: %s" % _rest)
        ava = filter_attribute_value_assertions(ava, _rest)
        
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
            spec = metadata.attribute_requirement(sp_entity_id)
            if spec:
                ava = self.filter(ava, sp_entity_id, metadata,
                                  spec["required"], spec["optional"])

        return self.filter(ava, sp_entity_id, metadata, [], [])

    def conditions(self, sp_entity_id):
        """ Return a saml.Condition instance
        
        :param sp_entity_id: The SP entity ID
        :return: A saml.Condition instance
        """
        return factory(saml.Conditions,
                       not_before=instant(),
                       # How long might depend on who's getting it
                       not_on_or_after=self.not_on_or_after(sp_entity_id),
                       audience_restriction=[factory(
                           saml.AudienceRestriction,
                           audience=factory(saml.Audience,
                                            text=sp_entity_id))])


class EntityCategories(object):
    pass


class Assertion(dict):
    """ Handles assertions about subjects """
    
    def __init__(self, dic=None):
        dict.__init__(self, dic)
    
    def _authn_context_decl(self, decl, authn_auth=None):
        """
        Construct the authn context with a authn context declaration
        :param decl: The authn context declaration
        :param authn_auth: Authenticating Authority
        :return: An AuthnContext instance
        """
        return factory(saml.AuthnContext,
                       authn_context_decl=decl,
                       authenticating_authority=factory(
                           saml.AuthenticatingAuthority, text=authn_auth))

    def _authn_context_decl_ref(self, decl_ref, authn_auth=None):
        """
        Construct the authn context with a authn context declaration reference
        :param decl_ref: The authn context declaration reference
        :param authn_auth: Authenticating Authority
        :return: An AuthnContext instance
        """
        return factory(saml.AuthnContext,
                       authn_context_decl_ref=decl_ref,
                       authenticating_authority=factory(
                           saml.AuthenticatingAuthority, text=authn_auth))

    def _authn_context_class_ref(self, authn_class, authn_auth=None):
        """
        Construct the authn context with a authn context class reference
        :param authn_class: The authn context class reference
        :param authn_auth: Authenticating Authority
        :return: An AuthnContext instance
        """
        cntx_class = factory(saml.AuthnContextClassRef, text=authn_class)
        if authn_auth:
            return factory(saml.AuthnContext, 
                           authn_context_class_ref=cntx_class,
                           authenticating_authority=factory(
                               saml.AuthenticatingAuthority, text=authn_auth))
        else:
            return factory(saml.AuthnContext,
                           authn_context_class_ref=cntx_class)
        
    def _authn_statement(self, authn_class=None, authn_auth=None,
                         authn_decl=None, authn_decl_ref=None):
        """
        Construct the AuthnStatement
        :param authn_class: Authentication Context Class reference
        :param authn_auth: Authenticating Authority
        :param authn_decl: Authentication Context Declaration
        :param authn_decl_ref: Authentication Context Declaration reference
        :return: An AuthnContext instance
        """
        if authn_class:
            return factory(
                saml.AuthnStatement,
                authn_instant=instant(),
                session_index=sid(),
                authn_context=self._authn_context_class_ref(
                    authn_class, authn_auth))
        elif authn_decl:
            return factory(
                saml.AuthnStatement,
                authn_instant=instant(),
                session_index=sid(),
                authn_context=self._authn_context_decl(authn_decl, authn_auth))
        elif authn_decl_ref:
            return factory(
                saml.AuthnStatement,
                authn_instant=instant(),
                session_index=sid(),
                authn_context=self._authn_context_decl_ref(authn_decl_ref,
                                                           authn_auth))
        else:
            return factory(
                saml.AuthnStatement,
                authn_instant=instant(),
                session_index=sid())

    def construct(self, sp_entity_id, in_response_to, consumer_url,
                  name_id, attrconvs, policy, issuer, authn_class=None,
                  authn_auth=None, authn_decl=None, encrypt=None,
                  sec_context=None, authn_decl_ref=None):
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
        :param authn_decl: An Authentication Context declaration
        :param encrypt: Whether to encrypt parts or all of the Assertion
        :param sec_context: The security context used when encrypting
        :param authn_decl_ref: An Authentication Context declaration reference
        :return: An Assertion instance
        """

        if policy:
            _name_format = policy.get_name_form(sp_entity_id)
        else:
            _name_format = NAME_FORMAT_URI

        attr_statement = saml.AttributeStatement(attribute=from_local(
            attrconvs, self, _name_format))

        if encrypt == "attributes":
            for attr in attr_statement.attribute:
                enc = sec_context.encrypt(text="%s" % attr)

                encd = xmlenc.encrypted_data_from_string(enc)
                encattr = saml.EncryptedAttribute(encrypted_data=encd)
                attr_statement.encrypted_attribute.append(encattr)

            attr_statement.attribute = []

        # start using now and for some time
        conds = policy.conditions(sp_entity_id)

        if authn_auth or authn_class or authn_decl or authn_decl_ref:
            _authn_statement = self._authn_statement(authn_class, authn_auth,
                                                     authn_decl, authn_decl_ref)
        else:
            _authn_statement = None

        return assertion_factory(
            issuer=issuer,
            attribute_statement=attr_statement,
            authn_statement=_authn_statement,
            conditions=conds,
            subject=factory(
                saml.Subject,
                name_id=name_id,
                subject_confirmation=[factory(
                    saml.SubjectConfirmation,
                    method=saml.SCM_BEARER,
                    subject_confirmation_data=factory(
                        saml.SubjectConfirmationData,
                        in_response_to=in_response_to,
                        recipient=consumer_url,
                        not_on_or_after=policy.not_on_or_after(sp_entity_id)))]
            ),
        )
    
    def apply_policy(self, sp_entity_id, policy, metadata=None):
        """ Apply policy to the assertion I'm representing 
        
        :param sp_entity_id: The SP entity ID
        :param policy: The policy
        :param metadata: Metadata to use
        :return: The resulting AVA after the policy is applied
        """
        ava = policy.restrict(self, sp_entity_id, metadata)
        self.update(ava)
        return ava