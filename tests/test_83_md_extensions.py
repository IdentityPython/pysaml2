from saml2.config import Config
from saml2.metadata import entity_descriptor
from saml2.extension.sp_type import SPType

__author__ = 'roland'

fil = "sp_mdext_conf.py"

cnf = Config().load_file(fil, metadata_construction=True)
ed = entity_descriptor(cnf)

print(ed)

assert ed.spsso_descriptor.extensions
assert len(ed.spsso_descriptor.extensions.extension_elements) == 3

assert ed.extensions
assert len(ed.extensions.extension_elements) > 1

assert any(e.tag is SPType.c_tag for e in ed.extensions.extension_elements)

cnf.setattr('sp', 'sp_type_in_metadata', False)
ed = entity_descriptor(cnf)

print(ed)

assert all(e.tag is not SPType.c_tag for e in ed.extensions.extension_elements)
