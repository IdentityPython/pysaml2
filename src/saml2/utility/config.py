import logging


logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    pass


class RuleValidator(object):
    def __init__(self, element_name, element_value, validator, error_signal):
        """
        :param element_name: the name of the element that will be
        validated
        :param element_value: function to be called
        with config as parameter to fetch an element value
        :param validator: function to be called
        with a config element value as a parameter
        :param error_signal: function to be called
        with an element name and value to signal an error (can be a log
        function, raise an error etc)
        """
        self.element_name = element_name
        self.element_value = element_value
        self.validator = validator
        self.error_signal = error_signal

    def validate(self):
        if not self.validator(self.element_value):
            self.error_signal(self.element_name)


def should_warning(element_name, message):
    logger.warning("{element} SHOULD {message}".format(
        element=element_name, message=message))


def must_error(element_name, message):
    error = "{element} MUST {message}".format(
        element=element_name, message=message)
    logger.error(error)
    raise ConfigValidationError(error)
