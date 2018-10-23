import sys

import saml2
assert saml2 == sys.modules['saml2']

sys.modules[__name__] = __import__('saml2')
