from importlib.metadata import version as _resolve_package_version


def _parse_version():
    value = _resolve_package_version("jmsmtn-pysaml2")
    return value


version = _parse_version()
