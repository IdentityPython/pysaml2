"""This module is a collection of operations on datetime and period objects.

New datetime or period objects are computed from each operation.
"""

from datetime import datetime as _datetime

import saml2.compat
import saml2.datetime


def utcnow():
    """Return the current date and time in UTC timezone.

    The object returned is of type: datetime.datetime
    """
    date_time_now = _datetime.utcnow()
    date_time_now = saml2.datetime.parse(date_time_now)
    return date_time_now


def now():
    """Alias to function `utcnow`."""
    return utcnow()


def timestamp(date_time):
    """Return the POSIX timestamp from the datetime object.

    The parameter `date_time` is expected to be of type: datetime.timedelta

    The object returned is of type: float
    """
    return saml2.compat.timestamp(date_time)


def subtract_from_now(period):
    """Move backward in time from the current UTC time, by the given period.

    The parameter `period` is expected to be of type: datetime.timedelta

    The object returned is of type: datetime.datetime
    """
    now = utcnow()
    return subtract(now, period)


def add_to_now(period):
    """Move forwards in time from the current UTC time, by the given period.

    The parameter `period` is expected to be of type: datetime.timedelta

    The object returned is of type: datetime.datetime
    """
    now = utcnow()
    return add(now, period)


def subtract(date_time_or_period, period):
    """Return the difference of two datetime or period objects.

    Given a datetime object as the `date_time_or_period` parameter, move
    backward in time by the given period.
    Given a period object as the `date_time_or_period` parameter, decrease by
    the given period.

    The parameter `date_time_or_period` is expected to be of type:
    - datetime.datetime
    - datetime.timedelta
    The parameter `period` is expected to be of type: datetime.timedelta

    The object returned is of type: the same type of parameter
    `date_time_or_period`
    """
    return date_time_or_period - period


def add(date_time_or_period, period):
    """Return the addition of two datetime or period objects.

    Given a datetime object as the `date_time_or_period` parameter, move
    forward in time by the given period.
    Given a period object as the `date_time_or_period` parameter, increase by
    the given period.

    The parameter `date_time_or_period` is expected to be of type:
    - datetime.datetime
    - datetime.timedelta
    The parameter `period` is expected to be of type: datetime.timedelta

    The object returned is of type: the same type as parameter
    `date_time_or_period`
    """
    return date_time_or_period + period
