# Type information for common pysaml2 data types, often found in configuration etc.
#

from typing import Literal
from typing import Mapping
from typing import Optional
from typing import TypedDict
from typing import Union


# Required attributes are specified as dicts, e.g.:
#
#   {
#       "friendly_name": "eduPersonScopedAffiliation",
#       "name": "1.3.6.1.4.1.5923.1.1.1.9",
#       "name_format": NAME_FORMAT_URI,
#       "is_required": "true",
#       "attribute_value": [{"text": Any, ...}]
#   }
class AttributeAsDict(TypedDict):
    friendly_name: Optional[str]
    name: str
    name_format: str
    is_required: Union[Literal["true"], Literal["false"]]
    attribute_value: Optional[list[Mapping[str, str]]]


# Type for the common 'ava' parameter.
AttributeValues = dict[str, Union[list[str], str]]
AttributeValuesStrict = dict[str, list[str]]
