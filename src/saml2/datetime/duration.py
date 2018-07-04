"""This module encapsulates the structures that define period objects."""

from datetime import timedelta as _timedelta

from aniso8601 import parse_duration as _duration_parser

import saml2.compat
from saml2.datetime import errors


def _str_duration_parser(period):
    is_negative = period[0] is '-'
    sign = -1 if is_negative else 1
    result = sign * _duration_parser(period[is_negative:])
    return result


def _unit_as_str(data):
    """Given a dictionary object return it with the keys as type str.

    The parameter `date` is expected to be of type: dict

    The object returned is of type: dict
    """
    return {str(k): v for k, v in data.items()}


def parse(data):
    """Return a duration object from the given data.

    The parameter `data` is expected to be of type:
    - datetime.timedelta: already a datetime.timedelta object
    - str: a string in ISO 8601 duration format
    - int: a number representing seconds
    - float: a number representing seconds with fractions
    - dict: an dictionary object with a single item where the key denotes the
      type of time unit and the value the amount of that time unit.

    The object returned is of type: datetime.timedelta
    """
    try:
        parse = _parsers[type(data)]
    except KeyError as e:
        saml2.compat.raise_from(errors.DurationFactoryError(data), e)

    try:
        value = parse(data)
    except (ValueError, TypeError, NotImplementedError) as e:
        saml2.compat.raise_from(errors.DurationParseError(data), e)

    return value


_parsers = {
    _timedelta: lambda x: x,
    str: _str_duration_parser,
    int: lambda n: _timedelta(seconds=n),
    float: lambda n: _timedelta(seconds=n),
    dict: lambda d: _timedelta(**_unit_as_str(d)),
}
