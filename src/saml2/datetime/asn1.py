"""This module provides a parser for datetime strings in ANS.1 UTCTime format.

The parser produces datetime objects that can be used with the other datetime
modules.
"""

from datetime import datetime as _datetime

import saml2.datetime


_ASN1_UTCTime_FORMAT = '%Y%m%d%H%M%SZ'


def parse(data):
    """Return a datetime object from the given ASN.1 UTCTime formatted string.

    The datetime object will be in UTC timezone.

    The parameter `data` is expected to be of type: str

    The object returned is of type: datetime.datetime
    """
    value = _datetime.strptime(data, _ASN1_UTCTime_FORMAT)
    value = saml2.datetime.parse(value)
    return value
