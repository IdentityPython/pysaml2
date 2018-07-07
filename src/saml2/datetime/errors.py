"""This module is a collection of errors for the saml2.datetime module."""

import saml2.errors


def _factoryErrorMsg(obj, data):
    """Produce a handler error message."""
    msg_tpl = 'No parser can construct {obj} object from {type}:{value}'
    msg = msg_tpl.format(obj=obj, type=type(data), value=data)
    return msg


def _parseErrorMsg(obj, data):
    """Produce a parser failure message."""
    msg_tpl = 'Parser failed to produce {obj} object from {type}:{value}'
    msg = msg_tpl.format(obj=obj, type=type(data), value=data)
    return msg


class DatetimeError(saml2.errors.Saml2Error):
    """Generic error during the handling of a datetime object."""


class DatetimeFactoryError(DatetimeError):
    """Error when no parser can handle the type of the given data."""

    def __init__(self, data):
        """Get the data that caused the error."""
        msg = _factoryErrorMsg('datetime', data)
        super(self.__class__, self).__init__(msg)


class DatetimeParseError(DatetimeError):
    """Error by the parrser while parsing the given data."""

    def __init__(self, data):
        """Get the data that caused the error."""
        msg = _parseErrorMsg('datetime', data)
        super(self.__class__, self).__init__(msg)


class DurationError(saml2.errors.Saml2Error):
    """Generic error during the handling of a duration object."""


class DurationFactoryError(DurationError):
    """Error when no parser can handle the type of the given data."""

    def __init__(self, data):
        """Get the data that caused the error."""
        msg = _factoryErrorMsg('duration', data)
        super(self.__class__, self).__init__(msg)


class DurationParseError(DurationError):
    """Error by the parrser while parsing the given data."""

    def __init__(self, data):
        """Get the data that caused the error."""
        msg = _parseErrorMsg('duration', data)
        super(self.__class__, self).__init__(msg)
