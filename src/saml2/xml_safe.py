from xml.etree.cElementTree import * # noqa

import defusedxml.cElementTree as defusedElementTree
from defusedxml.cElementTree import * # noqa


assert all( # noqa
    globals().get(attr_str) is getattr(defusedElementTree, attr_str)
    for attr_str in defusedElementTree.__all__), (
    "defusedxml is not loaded correctly or import order is wrong")
