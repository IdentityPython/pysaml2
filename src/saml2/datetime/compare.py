"""This module defines operations that compare datetime objects."""

from saml2.datetime import compute


def equal(dt1, dt2):
    """Return whether the two datetime objects are equal.

    Both parameters are expected to be of type: datetime.datetime

    The object returned is of type: bool
    """
    return dt1 == dt2


def before(dt1, dt2):
    """Return if dt1 is before dt2.

    Return whether the datetime object `dt1` is earlier than the datetime
    object `dt2`.

    Both parameters are expected to be of type: datetime.datetime

    The object returned is of type: bool
    """
    return dt1 < dt2


def before_now(dt1):
    """Return if dt1 is before the current datetime.

    Return whether the datetime object is earlier than the current UTC datetime
    object.

    The parameter `dt1` is expected to be of type: datetime.datetime

    The object returned is of type: bool
    """
    dt2 = compute.utcnow()
    return before(dt1, dt2)


def after(dt1, dt2):
    """Return if dt1 is after dt2.

    Return whether the datetime object `dt1` is later than the datetime
    object `dt2`.

    Both parameters are expected to be of type: datetime.datetime

    The object returned is of type: bool
    """
    return dt1 > dt2


def after_now(dt1):
    """Return if dt1 is after the current datetime.

    Return whether the datetime object is later than the current UTC datetime
    object.

    The parameter `dt1` is expected to be of type: datetime.datetime

    The object returned is of type: bool
    """
    dt2 = compute.utcnow()
    return after(dt1, dt2)


def within(dt1, dt2, dt):
    """Return if dt is equal to or after dt1 and before dt2.

    Return whether the datetime object `dt` is equal or later than the datetime
    object `dt1` and earlier than the datetime object `dt2`.

    All parameters are expected to be of type: datetime.datetime

    The object returned is of type: bool
    """
    return dt1 <= dt < dt2


def within_now(period, dt):
    """Return if dt is within period amount before and after the current datetime.

    Return whether the datetime object `dt` is equal or later than the current
    UTC datetime object decreased by the given perid object and earlier than
    the current UTC datetime object increased by the given period.

    All parameters are expected to be of type: datetime.datetime

    The object returned is of type: bool
    """
    now = compute.utcnow()
    lower = compute.subtract(now, period)
    upper = compute.add(now, period)
    return within(lower, upper, dt)


def earliest(dt1, dt2):
    """Return the earlier of the two datetime objects.

    Both parameters are expected to be of type: datetime.datetime

    The object returned is of type: datetime.datetime
    """
    return dt1 if before(dt1, dt2) else dt2


def latest(dt1, dt2):
    """Return the later of the two datetime objects.

    Both parameters are expected to be of type: datetime.datetime

    The object returned is of type: datetime.datetime
    """
    return dt1 if after(dt1, dt2) else dt2
