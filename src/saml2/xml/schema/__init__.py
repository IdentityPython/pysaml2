from importlib_resources import path as _resource_path

from xmlschema import XMLSchema as _XMLSchema
from xmlschema.exceptions import XMLSchemaException as XMLSchemaError

import saml2.data.schemas as _data_schemas


def _create_xml_schema_validator(source, **kwargs):
    kwargs = {
        **kwargs,
        "validation": "strict",
        "locations": _locations,
        "base_url": source,
        "allow": "sandbox",
        "use_fallback": False,
    }
    return _XMLSchema(source, **kwargs)


with _resource_path(_data_schemas, "xml.xsd") as fp:
    _path_schema_xml = str(fp)
with _resource_path(_data_schemas, "envelope.xsd") as fp:
    _path_schema_envelope = str(fp)
with _resource_path(_data_schemas, "xenc-schema.xsd") as fp:
    _path_schema_xenc = str(fp)
with _resource_path(_data_schemas, "xmldsig-core-schema.xsd") as fp:
    _path_schema_xmldsig_core = str(fp)
with _resource_path(_data_schemas, "saml-schema-assertion-2.0.xsd") as fp:
    _path_schema_saml_assertion = str(fp)
with _resource_path(_data_schemas, "saml-schema-metadata-2.0.xsd") as fp:
    _path_schema_saml_metadata = str(fp)
with _resource_path(_data_schemas, "saml-schema-protocol-2.0.xsd") as fp:
    _path_schema_saml_protocol = str(fp)

_locations = {
    "http://www.w3.org/XML/1998/namespace": _path_schema_xml,
    "http://schemas.xmlsoap.org/soap/envelope/": _path_schema_envelope,
    "http://www.w3.org/2001/04/xmlenc#": _path_schema_xenc,
    "http://www.w3.org/2000/09/xmldsig#": _path_schema_xmldsig_core,
    "urn:oasis:names:tc:SAML:2.0:assertion": _path_schema_saml_assertion,
    "urn:oasis:names:tc:SAML:2.0:protocol": _path_schema_saml_protocol,
}

with _resource_path(_data_schemas, "saml-schema-assertion-2.0.xsd") as fp:
    schema_saml_assertion = _create_xml_schema_validator(str(fp))
with _resource_path(_data_schemas, "saml-schema-metadata-2.0.xsd") as fp:
    schema_saml_metadata = _create_xml_schema_validator(str(fp))
with _resource_path(_data_schemas, "saml-schema-protocol-2.0.xsd") as fp:
    schema_saml_protocol = _create_xml_schema_validator(str(fp))


node_to_schema = {
    # AssertionType
    "urn:oasis:names:tc:SAML:2.0:assertion:Assertion": schema_saml_assertion,
    # EntitiesDescriptorType
    "urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor": schema_saml_metadata,
    # EntityDescriptorType
    "urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor": schema_saml_metadata,
    # RequestAbstractType
    "urn:oasis:names:tc:SAML:2.0:protocol:AssertionIDRequest": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:SubjectQuery": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResolve": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:ManageNameIDRequest": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:LogoutRequest": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:NameIDMappingRequest": schema_saml_protocol,
    # StatusResponseType
    "urn:oasis:names:tc:SAML:2.0:protocol:Response": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:ManageNameIDResponse": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse": schema_saml_protocol,
    "urn:oasis:names:tc:SAML:2.0:protocol:NameIDMappingResponse": schema_saml_protocol,
}
