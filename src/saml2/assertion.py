#!/usr/bin/env python
from __future__ import annotations

import copy
import importlib
import logging
import re
from warnings import warn as _warn

from typing import Any
from typing import Dict
from typing import List
from typing import Literal
from typing import Mapping
from typing import Optional
from typing import Type
from typing import TypedDict
from typing import TypeVar
from typing import Union
from warnings import warn as _warn

from pydantic import BaseModel
from pydantic import ValidationError
from pydantic import validator

from saml2 import saml
from saml2 import xmlenc
from saml2.attribute_converter import AttributeConverter
from saml2.attribute_converter import ac_factory
from saml2.attribute_converter import from_local
from saml2.attribute_converter import get_local_name
from saml2.mdstore import MetadataStore
from saml2.s_utils import MissingValue
from saml2.s_utils import assertion_factory
from saml2.s_utils import factory
from saml2.s_utils import sid
from saml2.saml import NAME_FORMAT_URI
from saml2.time_util import in_a_while
from saml2.time_util import instant
from saml2.typing import AttributeAsDict
from saml2.typing import AttributeValues
from saml2.typing import AttributeValuesStrict


logger = logging.getLogger(__name__)
extra_logger = logger.getChild("extra")


class EntityCategoryMatcher(BaseModel):
    """
    Part of EntityCategoryRule.

    Decides, based on a list of entity categories for an SP, if this rule applies to the SP or not.
    """

    required: List[str]  # List of entity category URIs that must be present in the SP's entity categories
    conflicts: List[str] = []  # List of entity category URIs that must not be present in the SP's entity categories

    def matches(self, sp_ecs: List[str]) -> bool:
        """Return True if all our entity categories is present in the list of SP entity categories"""
        _conflicts = self._conflicts(sp_ecs)
        if _conflicts:
            extra_logger.debug(f"Not matching, SP entity categories in conflict with {self.conflicts}")
            return False
        if self.required == [""]:
            # A rule with this matching criteria results in attributes always being released
            return True
        return all([x in sp_ecs for x in self.required])

    def _conflicts(self, sp_ecs: List[str]) -> bool:
        """Return True if any of the SP's entity categories are present in `conflicts'."""
        return any([x in sp_ecs for x in self.conflicts])


class EntityCategoryRule(BaseModel):
    """A rule to decide whether or not to add a list of attributes for release to an SP."""

    match: EntityCategoryMatcher
    attributes: List[str]  # attributes to release if this rule matches (friendly names)
    only_required: bool = False  # If this rule matches, only include the required attributes for the SP

    @validator("attributes")
    def lowercase_attribute_names(cls, v: List[str]):
        """Make sure all attribute names are lower case, for easier comparison later."""
        return [x.lower() for x in v]


# The regexps are an optional "allow-list" for values. If regexps are provided, one of them has to
# match a value for it to be released.
AllowedAttributeValue = re.Pattern[str]
AttributeRestrictions = dict[str, Optional[list[AllowedAttributeValue]]]


def _filter_values(values: list[str], allowed_values: list[str], must: bool = False) -> list[str]:
    """Removes values from *values* that does not appear in allowed_values.

    :param vals: The values that are to be filtered
    :param allowed_values: required or optional values
    :param must: Whether the allowed values must appear
    :return: The set of values after filtering
    """

    if not allowed_values:  # No value specified equals any value
        return values

    res = [x for x in values if x in allowed_values]

    if must and not res:
        raise MissingValue("Required attribute value missing")
    return res


def _match(attr: str, ava: AttributeValues) -> Optional[str]:
    if attr in ava:
        return attr

    _la = attr.lower()
    if _la in ava:
        return _la

    for _at in ava.keys():
        if _at.lower() == _la:
            return _at

    return None


AttributesAsDicts = list[AttributeAsDict]


def filter_on_attributes(
    ava: AttributeValues,
    required: Optional[AttributesAsDicts] = None,
    optional: Optional[AttributesAsDicts] = None,
    acs: Optional[list[AttributeConverter]] = None,
    fail_on_unfulfilled_requirements: bool = True,
) -> AttributeValues:
    """Filter attributes in `ava', returning a new instance of AttributeValues.

    * Ensure that all the values in the attribute value assertion are allowed
    * Ensure that all the required attributes are present (else raise MissingValue)

    :param ava: An attribute value assertion as a dictionary
    :param required: list of attributes defined to be required
    :param optional: list of attributes defined to be optional
    :param fail_on_unfulfilled_requirements: If required attributes
        are missing fail or fail not depending on this parameter.
    :return: The modified attribute value assertion
    """

    def _filter_value_or_values(
        val: Union[list[str], str], allowed_values: list[str], must: bool = False
    ) -> Union[str, list[str]]:
        """Convert single value to list of values before calling _filter_values."""
        values: list[str]
        if isinstance(val, str):
            values = [val]
        else:
            values = val
        res = _filter_values(values, allowed_values, must)
        return res

    def _identify_attribute(attr: AttributeAsDict, ava: AttributeValues) -> Optional[str]:
        """Find and identify `attr' in `ava'.

        The attribute we want to work with might be identified by its name, name_format,
        friendly_name or it's URI. This function tries to find the attribute in `ava' and
        returns the friendly_name of the attribute in `ava'.
        """
        name = attr["name"].lower()
        name_format = attr.get("name_format")
        friendly_name = attr.get("friendly_name")
        local_name = get_local_name(acs, name, name_format) or friendly_name or ""
        _fn = (
            _match(local_name, ava)
            # In the unlikely case that someone has provided us with URIs as attribute names
            or _match(name, ava)
        )
        return _fn

    def _apply_attr_value_restrictions(
        friendly_name: str, attr: AttributeAsDict, res: AttributeValuesStrict, must: bool = False
    ):
        """Add the attribute `friendly_name` to `res`, filtering its values if necessary."""
        _av_list = attr.get("attribute_value", [])
        assert _av_list is not None  # please mypy, the get() above defaults to empty list
        allowed_values = [av["text"] for av in _av_list]

        _values = _filter_value_or_values(ava[friendly_name], allowed_values, must)
        if not _values:
            return  # nothing to add

        if friendly_name not in res:
            res[friendly_name] = []

        res[friendly_name].extend(_values)

    new_ava = AttributeValuesStrict({})
    if required is None:
        required = []

    for attr in required:
        _fn = _identify_attribute(attr, ava)

        if _fn:
            _apply_attr_value_restrictions(_fn, attr, new_ava, True)
        elif fail_on_unfulfilled_requirements:
            raise MissingValue(f"Required attribute missing: '{attr['name']}'")

    if optional is None:
        optional = []

    for attr in optional:
        _fn = _identify_attribute(attr, ava)
        if _fn:
            _apply_attr_value_restrictions(_fn, attr, new_ava, False)

    # TODO: Kludge to turn lists-of-strings back into strings if the data was given
    #       as a string in `ava`. This is needed to make the tests pass, but maybe it
    #       would be preferable to declare ava to only have lists of strings?
    res = AttributeValues({})
    for this in new_ava.keys():
        if isinstance(ava[this], str):
            res[this] = new_ava[this][0]
        else:
            res[this] = new_ava[this]

    return res


def filter_on_demands(ava, required=None, optional=None):
    """Never return more than is needed. Filters out everything
    the server is prepared to return but the receiver doesn't ask for

    :param ava: Attribute value assertion as a dictionary
    :param required: Required attributes
    :param optional: Optional attributes
    :return: The possibly reduced assertion
    """

    # Is all what's required there:
    if required is None:
        required = {}

    lava = {k.lower(): k for k in ava.keys()}

    for attr, vals in required.items():
        attr = attr.lower()
        if attr in lava:
            if vals:
                for val in vals:
                    if val not in ava[lava[attr]]:
                        raise MissingValue(f"Required attribute value missing: {attr},{val}")
        else:
            raise MissingValue(f"Required attribute missing: {attr}")

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
    acsdic = {ac.name_format: ac for ac in acs}

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


def filter_attribute_value_assertions(
    ava: AttributeValues, attribute_restrictions: Optional[AttributeRestrictions] = None
) -> AttributeValues:
    """Will weed out attribute values and values according to the
    rules defined in the attribute restrictions. If filtering results in
    an attribute without values, then the attribute is removed from the
    assertion.

    :param ava: The incoming attribute value assertion (dictionary)
    :param attribute_restrictions: The rules that govern which attributes
        and values that are allowed. (dictionary)
    :return: The modified attribute value assertion
    """
    if not attribute_restrictions:
        # If there are no restrictions, release everything we have
        return ava

    for attr, vals in list(ava.items()):
        _attr = attr.lower()  # TODO: check if needed
        try:
            _rests = attribute_restrictions[_attr]
        except KeyError:
            del ava[attr]
        else:
            if _rests is None:
                continue
            if isinstance(vals, str):
                vals = [vals]
            rvals: list[str] = []
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


class EntityCategoryPolicy(BaseModel):
    """Holder of rule sets for entity categories.

    `categories' keys are category names (currently also module names from where the rules are loaded)
    `categories' values are lists of rules for that category.
    """

    categories: dict[str, list[EntityCategoryRule]]

    def __str__(self) -> str:
        return f"<{self.__class__.__name__}: {self.categories.keys()}>"

    @classmethod
    def from_module_names(cls: Type["EntityCategoryPolicy"], entity_categories: List[str]) -> "EntityCategoryPolicy":
        """Load a list of rules for a category.

        In the current implementation, the rules are loaded from a module - one module per category.

        The old format was to have the rules in the module's RELEASE dictionary, and the ONLY_REQUIRED dictionary.

        The new format is to load a list of rules from the RESTRICTIONS in the module, and use pydantic to validate
        and convert the rules to EntityCategoryRule objects.
        """
        res: dict[str, list[EntityCategoryRule]] = {}
        for category in entity_categories:
            try:
                _mod = importlib.import_module(category)
            except ImportError:
                _mod = importlib.import_module(f"saml2.entity_category.{category}")

            # `rules' is the list of rules loaded from this module
            rules: list[EntityCategoryRule] = []

            # Old format, load rules from RELEASE and ONLY_REQUIRED (two dictionaries)
            for key, items in _mod.RELEASE.items():
                alist = [k.lower() for k in items]
                _only_required = getattr(_mod, "ONLY_REQUIRED", {}).get(key, False)

                # Convert tuples to a list of strings, and a single string to a list of one string
                _key_as_list: List[str]
                if isinstance(key, str):
                    _key_as_list = [key]
                else:
                    _key_as_list = list(key)

                rules.append(
                    EntityCategoryRule(
                        match=EntityCategoryMatcher(required=_key_as_list, conflicts=[]),
                        attributes=alist,
                        only_required=_only_required,
                    )
                )

            # New format, load rules from RESTRICTIONS (a list)
            if hasattr(_mod, "RESTRICTIONS") and isinstance(_mod.RESTRICTIONS, list):
                for this in _mod.RESTRICTIONS:
                    try:
                        rules.append(EntityCategoryRule.parse_obj(this))
                    except ValidationError:
                        logger.warning(f"Invalid entity category rule: {this}")
                        raise

            res[category] = rules
        return cls(categories=res)

    def attribute_restrictions_for_sp(
        self,
        acs: List[AttributeConverter],
        sp_entity_id: Optional[str] = None,
        mds: Optional[MetadataStore] = None,  # TODO: Possibly a 'MetaData' instance (parent of MetadataStore)
        required: Optional[List[AttributeAsDict]] = None,
    ) -> AttributeRestrictions:
        """
        Compile the attribute restrictions for a given SP.

        Attribute restrictions are expressed as a dict with attribute names as keys
        and optionally a list of regular expressions as values.

        If the value is a list of regular expressions, then the value of the attribute must match
        one of the regular expressions. Otherwise the attribute is not allowed (meaning will not be released).

        If the value is None, then all values are allowed (think of it as "no restrictions apply").
        """
        restrictions: AttributeRestrictions = {}

        required_friendly_names: List[str] = []
        if required is not None:
            for d in required:
                # The dicts in 'required' can have a 'friendly_name', or a 'name' and a 'name_format'.
                # See the documentation of the RequiredAttribute type.
                _friendly_name: Optional[str] = d.get("friendly_name")
                if not _friendly_name:
                    _friendly_name = get_local_name(acs=acs, attr=d["name"], name_format=d["name_format"])
                assert isinstance(_friendly_name, str)
                required_friendly_names.append(_friendly_name.lower())

        if not mds:
            return restrictions

        sp_categories: List[str] = mds.entity_categories(sp_entity_id)

        extra_logger.debug(
            f"Compiling attributes to release based on SP {sp_entity_id} entity categories: {sp_categories}"
        )
        extra_logger.debug(f"Required attributes for this SP: {required_friendly_names}")

        for rule_set in self.categories.values():
            for this_rule in rule_set:
                _matches = this_rule.match.matches(sp_categories)
                extra_logger.debug(f"Rule {this_rule.match}, matches: {_matches}")
                if _matches:
                    if this_rule.only_required:
                        attrs = [a for a in this_rule.attributes if a in required_friendly_names]
                        _not_adding = [a for a in this_rule.attributes if a not in required_friendly_names]
                        extra_logger.debug(f"Adding only required attributes: {attrs}, not adding: {_not_adding}")
                    else:
                        attrs = this_rule.attributes
                        extra_logger.debug(f"Adding attributes: {attrs}")

                    for attr in attrs:
                        restrictions[attr] = None

        if not restrictions:
            restrictions[""] = None

        logger.debug(f"Compiled attribute restrictions: {restrictions}")
        return restrictions


PolicyConfigKey = Union[str, Literal["default"]]


class PolicyConfigValue(BaseModel):
    lifetime: Optional[Any]
    attribute_restrictions: Optional[AttributeRestrictions]
    name_form: Optional[str]
    nameid_format: Optional[str]
    entity_categories: EntityCategoryPolicy
    sign: Optional[Union[Literal["response"], Literal["assertion"], Literal["on_demand"]]]
    fail_on_missing_requested: Optional[bool]

    class Config:
        arbitrary_types_allowed = True  # allow re.Pattern as type in AttributeRestrictions


PolicyConfig = dict[PolicyConfigKey, PolicyConfigValue]


class Policy:
    """Handles restrictions on assertions."""

    def __init__(self, restrictions: Optional[Mapping[str, Any]] = None, mds: Optional[MetadataStore] = None):
        self.metadata_store = mds
        self._restrictions = self.setup_restrictions(restrictions)
        logger.debug("policy restrictions: %s", self._restrictions)
        self.acs: list[AttributeConverter] = []

    def setup_restrictions(self, restrictions: Optional[Mapping[str, Any]] = None) -> Optional[PolicyConfig]:
        if restrictions is None:
            return None

        restrictions = copy.deepcopy(restrictions)
        restrictions = self._compile_restrictions(restrictions)
        return restrictions

    @staticmethod
    def _compile_restrictions(restrictions: Mapping[str, Any]) -> PolicyConfig:
        """
        Pre-compile regular expressions in rules in `restrictions'.

        This is only for IdPs or AAs, and it's about limiting what
        is returned to the SP.
        In the configuration file, restrictions on which values that
        can be returned are specified with the help of regular expressions.
        This function goes through and pre-compiles the regular expressions.

        :param restrictions: policy configuration
        :return: The assertion with the string specification replaced with
            a compiled regular expression.
        """
        config: PolicyConfig = {}
        for who, spec in restrictions.items():
            if spec is None:
                spec = {}

            entity_categories: list[str] = spec.get("entity_categories", [])
            _new_entity_categories = EntityCategoryPolicy.from_module_names(entity_categories)

            attribute_restrictions: Mapping[str, list[str]] = spec.get("attribute_restrictions") or {}
            _attribute_restrictions: AttributeRestrictions = {}
            for key, values in attribute_restrictions.items():
                lkey = key.lower()
                values = [] if not values else values
                _attribute_restrictions[lkey] = [re.compile(value) for value in values] or None
            _new_attribute_restrictions = _attribute_restrictions or None

            config[who] = PolicyConfigValue(
                lifetime=spec.get("lifetime"),
                attribute_restrictions=_new_attribute_restrictions,
                name_form=spec.get("name_form"),
                nameid_format=spec.get("nameid_format"),
                entity_categories=_new_entity_categories,
                sign=spec.get("sign"),
                fail_on_missing_requested=spec.get("fail_on_missing_requested"),
            )

        return config

    def get(self, attribute: str, sp_entity_id: str, default: Any = None) -> Any:
        """

        :param attribute:
        :param sp_entity_id:
        :param default:
        :return:
        """
        if not self._restrictions:
            return default

        ra_info: Mapping[str, Any] = {}
        if self.metadata_store is not None:
            ra_info = self.metadata_store.registration_info(sp_entity_id) or {}
        ra_entity_id: str = ra_info.get("registration_authority")  # type: ignore[assignment]

        sp_restrictions = self._restrictions.get(sp_entity_id)
        ra_restrictions = self._restrictions.get(ra_entity_id)
        default_restrictions = self._restrictions.get("default") or self._restrictions.get("")
        restrictions: Optional[PolicyConfigValue] = (
            sp_restrictions
            if sp_restrictions is not None
            else ra_restrictions
            if ra_restrictions is not None
            else default_restrictions
            if default_restrictions is not None
            else None
        )

        attribute_restriction = getattr(restrictions, attribute, None)
        if attribute_restriction is None:
            return default
        return attribute_restriction

    def get_nameid_format(self, sp_entity_id: str):
        """Get the NameIDFormat to used for the entity id
        :param: The SP entity ID
        :return: The format
        """
        return self.get("nameid_format", sp_entity_id, saml.NAMEID_FORMAT_TRANSIENT)

    def get_name_form(self, sp_entity_id: str):
        """Get the NameFormat to used for the entity id
        :param: The SP entity ID
        :return: The format
        """

        return self.get("name_form", sp_entity_id, default=NAME_FORMAT_URI)

    def get_lifetime(self, sp_entity_id: str):
        """The lifetime of the assertion
        :param sp_entity_id: The SP entity ID
        :param: lifetime as a dictionary
        """
        # default is a hour
        return self.get("lifetime", sp_entity_id, {"hours": 1})

    def get_attribute_restrictions(self, sp_entity_id: str) -> Optional[AttributeRestrictions]:
        """Return the attribute restriction for SP that want the information

        :param sp_entity_id: The SP entity ID
        :return: The restrictions
        """

        return self.get("attribute_restrictions", sp_entity_id)

    def get_fail_on_missing_requested(self, sp_entity_id: str):
        """Return the whether the IdP should should fail if the SPs
        requested attributes could not be found.

        :param sp_entity_id: The SP entity ID
        :return: The restrictions
        """

        return self.get("fail_on_missing_requested", sp_entity_id, default=True)

    def get_sign(self, sp_entity_id: str):
        """
        Possible choices
        "sign": ["response", "assertion", "on_demand"]

        :param sp_entity_id:
        :return:
        """

        return self.get("sign", sp_entity_id, default=[])

    def _get_restrictions_for_entity_categories(
        self, sp_entity_id: str, mds: Optional[MetadataStore] = None, required: Optional[List[AttributeAsDict]] = None
    ) -> AttributeRestrictions:
        """

        :param sp_entity_id:
        :param required: required attributes
        :return: A dictionary with restrictions
        """

        if mds is not None:
            warn_msg = (
                "The mds parameter for saml2.assertion.Policy.get_entity_categories "
                "is deprecated; "
                "instead, initialize the Policy object setting the mds param."
            )
            logger.warning(warn_msg)
            _warn(warn_msg, DeprecationWarning)

        result1: Optional[EntityCategoryPolicy] = self.get("entity_categories", sp_entity_id)
        if result1 is None or not result1.categories:
            return {}

        assert isinstance(result1, EntityCategoryPolicy)

        return result1.attribute_restrictions_for_sp(
            acs=self.acs,
            sp_entity_id=sp_entity_id,
            mds=(mds or self.metadata_store),
            required=required,
        )

    def not_on_or_after(self, sp_entity_id: str):
        """When the assertion stops being valid, should not be
        used after this time.

        :param sp_entity_id: The SP entity ID
        :return: String representation of the time
        """

        return in_a_while(**self.get_lifetime(sp_entity_id))

    def filter(
        self,
        ava: AttributeValues,
        sp_entity_id: str,
        mdstore: Optional[MetadataStore] = None,
        required: Optional[list[AttributeAsDict]] = None,
        optional: Optional[list[AttributeAsDict]] = None,
    ) -> AttributeValues:
        """What attribute and attribute values returns depends on what
        the SP or the registration authority has said it wants in the request
        or in the metadata file and what the IdP/AA wants to release.
        An assumption is that what the SP or the registration authority
        asks for overrides whatever is in the metadata. But of course the
        IdP never releases anything it doesn't want to.

        :param ava: The information about the subject as a dictionary
        :param sp_entity_id: The entity ID of the SP
        :param required: Attributes that the SP requires in the assertion
        :param optional: Attributes that the SP regards as optional
        :return: A possibly modified AVA
        """

        if mdstore is not None:
            warn_msg = (
                "The mdstore parameter for saml2.assertion.Policy.filter "
                "is deprecated; "
                "instead, initialize the Policy object setting the mds param."
            )
            logger.warning(warn_msg)
            _warn(warn_msg, DeprecationWarning)

        # acs MUST have a value, fall back to default.
        if not self.acs:
            self.acs = ac_factory()

        subject_ava = ava.copy()

        # entity category restrictions
        _ent_rest = self._get_restrictions_for_entity_categories(sp_entity_id, mds=mdstore, required=required)
        if _ent_rest:
            subject_ava = filter_attribute_value_assertions(subject_ava, _ent_rest)
        elif required or optional:
            logger.debug("required: %s, optional: %s", required, optional)
            subject_ava = filter_on_attributes(
                subject_ava,
                required,
                optional,
                self.acs,
                self.get_fail_on_missing_requested(sp_entity_id),
            )

        # attribute restrictions
        _attr_rest = self.get_attribute_restrictions(sp_entity_id)
        subject_ava = filter_attribute_value_assertions(subject_ava, _attr_rest)

        return subject_ava or {}

    def restrict(self, ava: AttributeValues, sp_entity_id: str, metadata: Optional[MetadataStore] = None):
        """Identity attribute names are expected to be expressed as FriendlyNames

        :return: A filtered ava according to the IdPs/AAs rules and
            the list of required/optional attributes according to the SP.
            If the requirements can't be met an exception is raised.
        """
        if metadata is not None:
            warn_msg = (
                "The metadata parameter for saml2.assertion.Policy.restrict "
                "is deprecated and ignored; "
                "instead, initialize the Policy object setting the mds param."
            )
            logger.warning(warn_msg)
            _warn(warn_msg, DeprecationWarning)

        metadata_store = metadata or self.metadata_store
        spec = metadata_store.attribute_requirement(sp_entity_id) or {} if metadata_store else {}
        required_attributes = spec.get("required") or []
        optional_attributes = spec.get("optional") or []
        requirements_subject_id = metadata_store.subject_id_requirement(sp_entity_id) if metadata_store else []
        for r in requirements_subject_id:
            if r not in required_attributes:
                required_attributes.append(r)
        return self.filter(
            ava,
            sp_entity_id,
            required=required_attributes or None,
            optional=optional_attributes or None,
        )

    def conditions(self, sp_entity_id):
        """Return a saml.Condition instance

        :param sp_entity_id: The SP entity ID
        :return: A saml.Condition instance
        """
        return factory(
            saml.Conditions,
            not_before=instant(),
            # How long might depend on who's getting it
            not_on_or_after=self.not_on_or_after(sp_entity_id),
            audience_restriction=[
                factory(
                    saml.AudienceRestriction,
                    audience=[factory(saml.Audience, text=sp_entity_id)],
                ),
            ],
        )


class EntityCategories:
    pass


def _authn_context_class_ref(authn_class, authn_auth=None):
    """
    Construct the authn context with a authn context class reference
    :param authn_class: The authn context class reference
    :param authn_auth: Authenticating Authority
    :return: An AuthnContext instance
    """
    cntx_class = factory(saml.AuthnContextClassRef, text=authn_class)
    if authn_auth:
        return factory(
            saml.AuthnContext,
            authn_context_class_ref=cntx_class,
            authenticating_authority=factory(saml.AuthenticatingAuthority, text=authn_auth),
        )
    else:
        return factory(saml.AuthnContext, authn_context_class_ref=cntx_class)


def _authn_context_decl(decl, authn_auth=None):
    """
    Construct the authn context with a authn context declaration
    :param decl: The authn context declaration
    :param authn_auth: Authenticating Authority
    :return: An AuthnContext instance
    """
    return factory(
        saml.AuthnContext,
        authn_context_decl=decl,
        authenticating_authority=factory(saml.AuthenticatingAuthority, text=authn_auth),
    )


def _authn_context_decl_ref(decl_ref, authn_auth=None):
    """
    Construct the authn context with a authn context declaration reference
    :param decl_ref: The authn context declaration reference
    :param authn_auth: Authenticating Authority
    :return: An AuthnContext instance
    """
    return factory(
        saml.AuthnContext,
        authn_context_decl_ref=decl_ref,
        authenticating_authority=factory(saml.AuthenticatingAuthority, text=authn_auth),
    )


def authn_statement(
    authn_class=None,
    authn_auth=None,
    authn_decl=None,
    authn_decl_ref=None,
    authn_instant="",
    subject_locality="",
    session_not_on_or_after=None,
):
    """
    Construct the AuthnStatement
    :param authn_class: Authentication Context Class reference
    :param authn_auth: Authenticating Authority
    :param authn_decl: Authentication Context Declaration
    :param authn_decl_ref: Authentication Context Declaration reference
    :param authn_instant: When the Authentication was performed.
        Assumed to be seconds since the Epoch.
    :param subject_locality: Specifies the DNS domain name and IP address
        for the system from which the assertion subject was apparently
        authenticated.
    :return: An AuthnContext instance
    """
    if authn_instant:
        _instant = instant(time_stamp=authn_instant)
    else:
        _instant = instant()

    if authn_class:
        res = factory(
            saml.AuthnStatement,
            authn_instant=_instant,
            session_index=sid(),
            session_not_on_or_after=session_not_on_or_after,
            authn_context=_authn_context_class_ref(authn_class, authn_auth),
        )
    elif authn_decl:
        res = factory(
            saml.AuthnStatement,
            authn_instant=_instant,
            session_index=sid(),
            session_not_on_or_after=session_not_on_or_after,
            authn_context=_authn_context_decl(authn_decl, authn_auth),
        )
    elif authn_decl_ref:
        res = factory(
            saml.AuthnStatement,
            authn_instant=_instant,
            session_index=sid(),
            session_not_on_or_after=session_not_on_or_after,
            authn_context=_authn_context_decl_ref(authn_decl_ref, authn_auth),
        )
    else:
        res = factory(
            saml.AuthnStatement,
            authn_instant=_instant,
            session_index=sid(),
            session_not_on_or_after=session_not_on_or_after,
        )

    if subject_locality:
        res.subject_locality = saml.SubjectLocality(text=subject_locality)

    return res


def do_subject_confirmation(not_on_or_after, key_info=None, **treeargs):
    """

    :param not_on_or_after: not_on_or_after policy
    :param subject_confirmation_method: How was the subject confirmed
    :param address: The network address/location from which an attesting entity
        can present the assertion.
    :param key_info: Information of the key used to confirm the subject
    :param in_response_to: The ID of a SAML protocol message in response to
        which an attesting entity can present the assertion.
    :param recipient: A URI specifying the entity or location to which an
        attesting entity can present the assertion.
    :param not_before: A time instant before which the subject cannot be
        confirmed. The time value MUST be encoded in UTC.
    :return:
    """

    _sc = factory(saml.SubjectConfirmation, **treeargs)

    _scd = _sc.subject_confirmation_data
    _scd.not_on_or_after = not_on_or_after

    if _sc.method == saml.SCM_HOLDER_OF_KEY:
        _scd.add_extension_element(key_info)

    return _sc


def do_subject(not_on_or_after, name_id, **farg):
    specs = farg["subject_confirmation"]

    if isinstance(specs, list):
        res = [do_subject_confirmation(not_on_or_after, **s) for s in specs]
    else:
        res = [do_subject_confirmation(not_on_or_after, **specs)]

    return factory(saml.Subject, name_id=name_id, subject_confirmation=res)


class Assertion(dict):
    """Handles assertions about subjects"""

    def __init__(self, dic=None):
        dict.__init__(self, dic)
        self.acs = []

    def construct(
        self,
        sp_entity_id,
        attrconvs,
        policy,
        issuer,
        farg,
        authn_class=None,
        authn_auth=None,
        authn_decl=None,
        encrypt=None,
        sec_context=None,
        authn_decl_ref=None,
        authn_instant="",
        subject_locality="",
        authn_statem=None,
        name_id=None,
        session_not_on_or_after=None,
    ):
        """Construct the Assertion

        :param sp_entity_id: The entityid of the SP
        :param in_response_to: An identifier of the message, this message is
            a response to
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
        :param authn_instant: When the Authentication was performed
        :param subject_locality: Specifies the DNS domain name and IP address
            for the system from which the assertion subject was apparently
            authenticated.
        :param authn_statem: A AuthnStatement instance
        :return: An Assertion instance
        """

        _name_format = policy.get_name_form(sp_entity_id)

        attr_statement = saml.AttributeStatement(attribute=from_local(attrconvs, self, _name_format))

        if encrypt == "attributes":
            for attr in attr_statement.attribute:
                enc = sec_context.encrypt(text=f"{attr}")

                encd = xmlenc.encrypted_data_from_string(enc)
                encattr = saml.EncryptedAttribute(encrypted_data=encd)
                attr_statement.encrypted_attribute.append(encattr)

            attr_statement.attribute = []

        # start using now and for some time
        conds = policy.conditions(sp_entity_id)

        if authn_statem:
            _authn_statement = authn_statem
        elif authn_auth or authn_class or authn_decl or authn_decl_ref:
            _authn_statement = authn_statement(
                authn_class,
                authn_auth,
                authn_decl,
                authn_decl_ref,
                authn_instant,
                subject_locality,
                session_not_on_or_after=session_not_on_or_after,
            )
        else:
            _authn_statement = None

        subject = do_subject(policy.not_on_or_after(sp_entity_id), name_id, **farg["subject"])
        _ass = assertion_factory(issuer=issuer, conditions=conds, subject=subject)

        if _authn_statement:
            _ass.authn_statement = [_authn_statement]

        if not attr_statement.empty():
            _ass.attribute_statement = [attr_statement]

        return _ass

    def apply_policy(self, sp_entity_id, policy):
        """Apply policy to the assertion I'm representing

        :param sp_entity_id: The SP entity ID
        :param policy: The policy
        :return: The resulting AVA after the policy is applied
        """

        policy.acs = self.acs
        ava = policy.restrict(self, sp_entity_id)

        for key, val in list(self.items()):
            if key in ava:
                self[key] = ava[key]
            else:
                del self[key]

        return ava


def compile(restrictions: Mapping[str, Any]) -> PolicyConfig:
    _warn("compile() is believe to be unused as an exported function and will be removed, use Policy() instead")
    return Policy._compile_restrictions(restrictions)
