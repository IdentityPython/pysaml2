"""Datetime structures and operations.

This module encapsulates the structures that define datetime, time unit,
duration and timezone objects, their relation and the operations that can be
done upon them. Should these structures change all affected components should
be under this module.

There are three layers of specifications that define the structure and
behaviour of time constructs for SAML2:

- The SAML2-core specification - section 1.3.3 Time Values.
  Reference: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

- The W3C XML Schema Datatypes - section 3.2.7 dateTime.
  Reference: https://www.w3.org/TR/xmlschema-2/#dateTime

  [notable] W3C Date and Time Formats defines a profile of ISO 8601.
  Reference: https://www.w3.org/TR/NOTE-datetime

- The ISO 8601 standard upon which the dateTime datatype is based.
  Reference: https://en.wikipedia.org/wiki/ISO_8601

  [notable] Most systems implement rfc3339; a profile of ISO 8601.
  Reference: https://tools.ietf.org/html/rfc3339

Finally, further clarification was requested and in the following thread an
answer was given by a member of the SAML Technical Committee:
https://lists.oasis-open.org/archives/saml-dev/201310/msg00001.html

To comply with the specifications, the existing implementations and the
"unofficial errata" in the thread above, the following have been decided:

- all ISO 8601 formats that can be parsed are accepted and converted to UTC.

- if no timezone information is present, it is assumed that the other party is
  following the current wording of the SAML2-core specification - the time is
  assumed to be in UTC already, but "with no timezone component."

- the datetime object produced are always in UTC timezone, that can be
  represented as a string of ISO 8601 combined date and time format with
  extended notation, where the timezone component is always present and
  represented by the military timezone symbol 'Z'.
"""

import enum as _enum
from datetime import datetime as _datetime

from aniso8601 import parse_datetime as _datetime_parser

import saml2.compat
from saml2.datetime import duration
from saml2.datetime import errors
from saml2.datetime import timezone


def parse(data):
    """Return a datetime object in UTC timezone from the given data.

    If timezone information is available the datetime object will be converted
    to UTC timezone. If no timezone information is available, it will be
    assumed to be in UTC timezone and that information will be added.

    The parameter `data` is expected to be of type:
    - datetime.datetime: a datetime.datetime object
    - str: a string in ISO 8601 combined date and time format with extended
      notation
    - int: a number representing a POSIX timestamp
    - float: a number representing a POSIX timestamp

    The object returned is of type: datetime.datetime
    """
    try:
        parse = _parsers[type(data)]
    except KeyError as e:
        saml2.compat.raise_from(errors.DatetimeFactoryError(data), e)

    try:
        value = parse(data)
    except (ValueError, TypeError, NotImplementedError) as e:
        saml2.compat.raise_from(errors.DatetimeParseError(data), e)

    utc_timezone = timezone.UTC_TIMEZONE
    if value.tzinfo is None:
        value = value.replace(tzinfo=utc_timezone)
    if value.tzinfo is not utc_timezone:
        value = value.astimezone(utc_timezone)

    return value


def fromtimestamp(timestamp):
    """Return a datetime object in UTC timezone from the given POSIX timestamp.

    The parameter `timestamp` is expected to be of type: int|float

    The object returned is of type: datetime.datetime
    """
    return _datetime.fromtimestamp(timestamp, timezone.UTC_TIMEZONE)


def to_string(date_time_obj):
    """Return an ISO 8601 string representation of the datetime object.

    Return the given datetime object -as returned by the `parse` function-
    represented as a string of ISO 8601 combined date and time format with
    extended notation, where the timezone component is always present and
    represented by the military timezone symbol 'Z'.

    The parameter `date_time_obj` is expected to be of type: datetime.datetime

    The object returned is of type: str
    """
    return date_time_obj.isoformat().replace(
        timezone.UTC_OFFSET_SYMBOL,
        timezone.UTC_MILITARY_TIMEZONE_SYMBOL)


class unit(_enum.Enum):
    """Time unit representations and constructors.

    Available units are:
    - days
    - seconds
    - microseconds
    - milliseconds
    - minutes
    - hours
    - weeks

    Both plural and singular forms are available. Time units can be used to
    create objects that describe a period of time or signify the type of unit
    of a given amount.

    Usage example:

    * The difference between two datetime objects is a period of time:

    ```
    import saml2.datetime

    dt1 = saml2.datetime.parse('2018-01-25T08:45:00Z')
    dt2 = saml2.datetime.parse('2018-01-25T08:40:00Z')
    delta = dt1 - dt2
    period = saml2.datetime.unit.minute(5)

    assert period == delta
    ```

    * Signify the type of unit for an amount:

    ```
    import saml2.datetime
    from saml2.datetime import duration

    period = saml2.datetime.duration.parse({
        saml2.datetime.unit.seconds: 5
    })

    assert saml2.datetime.unit.seconds(5) == period
    ```

    The object returned is of type: datetime.timedelta
    """

    day = 'days'
    days = 'days'
    second = 'seconds'
    seconds = 'seconds'
    microsecond = 'microseconds'
    microseconds = 'microseconds'
    millisecond = 'milliseconds'
    milliseconds = 'milliseconds'
    minute = 'minutes'
    minutes = 'minutes'
    hour = 'hours'
    hours = 'hours'
    week = 'weeks'
    weeks = 'weeks'

    def __str__(self):
        """Return the string representation time unit types.

        The object returned is of type: str
        """
        return self.value

    def __call__(self, amount):
        """Return a period object of the specified time unit and amount.

        The parameter `amount` is expected to be of type: int|float

        The object returned is of type: datetime.timedelta
        """
        return duration.parse({self.value: amount})


_parsers = {
    _datetime: lambda x: x,
    str: _datetime_parser,
    int: fromtimestamp,
    float: fromtimestamp,
}
