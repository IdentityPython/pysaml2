import os.path

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def dotname(module):
    if not BASEDIR.endswith('tests'):
        return 'tests.' + module
    else:
        return module
