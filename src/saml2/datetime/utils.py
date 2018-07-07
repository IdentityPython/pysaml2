"""This module contains additional handy datetime functions.

They built upon the other modules but do not belong in any other module.
Gradually, these may move away under more meaningful-proper modules.
"""

import saml2.datetime
from saml2.datetime import compute


def instant():
    """Return the current datetime object represented as a string.

    The datetime object will be in UTC timezone. The string representatino will
    be of ISO 8601 combined date and time format with extended notation, where
    the timezone component is always present and represented by the military
    timezone symbol 'Z'.

    The object returned is of type: str
    """
    now = compute.utcnow()
    instant = saml2.datetime.to_string(now)
    return instant
