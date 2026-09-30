from pathutils import full_path

from saml2 import class_name
from saml2 import config
from saml2 import extension_elements_to_elements
from saml2 import saml
from saml2 import samlp
from saml2 import sigver
from saml2.mdstore import MetadataStore
from saml2.s_utils import do_attribute_statement
from saml2.s_utils import factory
from saml2.saml import EncryptedAssertion

SIGNED = full_path("saml_signed.xml")
UNSIGNED = full_path("saml_unsigned.xml")
SIMPLE_SAML_PHP_RESPONSE = full_path("simplesamlphp_authnresponse.xml")
OKTA_RESPONSE = full_path("okta_response.xml")
OKTA_ASSERTION = full_path("okta_assertion")

PUB_KEY = full_path("test.pem")
PRIV_KEY = full_path("test.key")

ENC_PUB_KEY = full_path("pki/test_1.crt")
ENC_PRIV_KEY = full_path("pki/test.key")

INVALID_KEY = full_path("non-existent.key")

IDP_EXAMPLE = full_path("idp_example.xml")
METADATA_CERT = full_path("metadata_cert.xml")

def make_sec(crypto_backend = None):
    conf = config.SPConfig()
    conf.load_file("server_conf")
    md = MetadataStore([saml, samlp], None, conf)
    md.load("local", IDP_EXAMPLE)

    conf.metadata = md
    conf.only_use_keys_in_metadata = False
    if crypto_backend is not None:
        conf.crypto_backend = crypto_backend
    return sigver.security_context(conf)

def make_assertion(sec):
    return factory(
        saml.Assertion,
        version="2.0",
        id="id-11111",
        issue_instant="2009-10-30T13:20:28Z",
        signature=sigver.pre_signature_part("id-11111", sec.my_cert, 1),
        attribute_statement=do_attribute_statement(
            {
                ("", "", "surName"): ("Foo", ""),
                ("", "", "givenName"): ("Bar", ""),
            }
        ),
    )

def sign_assertion(assertion, sec):
    sigass = sec.sign_statement(
        assertion,
        class_name(assertion),
        key_file=PRIV_KEY,
        node_id=assertion.id,
    )

    _ass0 = saml.assertion_from_string(sigass)
    encrypted_assertion = EncryptedAssertion()
    encrypted_assertion.add_extension_element(_ass0)

    return encrypted_assertion

def encrypt_assertion(signed_assertion, sec):
    template = str(sigver.pre_encryption_part(encrypted_key_id="EK_TEST", encrypted_data_id="ED_TEST"))
    tmp = sigver.make_temp(template.encode("utf-8"), decode=False)
    return sec.crypto.encrypt(
        str(signed_assertion),
        sec.cert_file,
        tmp.name,
        "des-192",
        '/*[local-name()="EncryptedAssertion"]/*[local-name()="Assertion"]',
    )

def decrypt_assertion(enctext, node_name, sec):
    decr_text = sec.decrypt(enctext, key_file=PRIV_KEY)
    _seass = saml.encrypted_assertion_from_string(decr_text)
    assers = extension_elements_to_elements(_seass.extension_elements, [saml, samlp])

    for ass in assers:
        _txt = sec.verify_signature(str(ass), PUB_KEY, node_name=node_name)
        if _txt:
            return ass

def test_libxmlsec():
    sec = make_sec()
    assertion = make_assertion(sec)
    signed_assertion = sign_assertion(assertion, sec)
    enctext = encrypt_assertion(signed_assertion, sec)
    decrypted_assertion = decrypt_assertion(enctext, class_name(assertion), sec)

    assert decrypted_assertion
    return decrypted_assertion

def test_pyxmlsec():
    sec = make_sec("XMLSecurity")
    assertion = make_assertion(sec)
    signed_assertion = sign_assertion(assertion, sec)
    enctext = encrypt_assertion(signed_assertion, sec)
    decrypted_assertion = decrypt_assertion(enctext, class_name(assertion), sec)

    assert decrypted_assertion
    return decrypted_assertion

def compare_tests():
    assert test_libxmlsec() == test_pyxmlsec()

if __name__ == "__main__":
    compare_tests()
