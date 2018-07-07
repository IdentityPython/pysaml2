"""Classes that represent errors for this package.

All errors are exceptions and must be a subclass of Saml2Error class. Error
classes should provide usefull error messages and request the needed context
data.
"""


class Saml2Error(Exception):
    """Top level class to signify an error from the pysaml2 package.

    All errors should inherit from this class or another more specific error
    class that is a subclass of Saml2Error. When needed error classes provide
    error messages given the right data to present.
    """
