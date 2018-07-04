"""Functions to hide compatibility issues between python2 and python3.

This module encapsulates all compatibility issues between python2 and python3.
Many of the compatibility issues are solved by the python-future module. Any
other workarounds will be implemented under this module.
"""

import datetime as _datetime
import time as _time

from aniso8601.timezone import UTCOffset as _Timezone

import future.utils as _future_utils


def timestamp(date_time):
    """Return the POSIX timestamp from the datetime object.

    Python3 provides the `.timestamp()` method call on datetime.datetime
    objects, but python2 does not. For python2 we must compute the timestamp
    ourselves. The formula has been backported from python3.

    The parameter `date_time` is expected to be of type: datetime.timedelta

    The object returned is of type: float
    """
    if hasattr(date_time, 'timestamp'):
        timestamp = date_time.timestamp()
    else:
        timestamp = _time.mktime(date_time.timetuple())
        timestamp += date_time.microsecond / 1e6
    return timestamp


def _utc_timezone():
    """Return a UTC-timezone tzinfo instance.

    Python3 provides a UTC-timezone tzinfo instance through the
    datetime.timezone module. Python2 does not define any timezone instance; it
    only provides the tzinfo abstract base class. For python2 the instance is
    generated with the _Timezone class.
    """
    try:
        utc_timezone = _datetime.timezone.utc
    except AttributeError as e:
        utc_timezone = _Timezone(name='UTC', minutes=0)
    finally:
        return utc_timezone


UTC_TIMEZONE = _utc_timezone()
raise_from = _future_utils.raise_from
