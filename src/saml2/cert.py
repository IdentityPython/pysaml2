__author__ = "haho0032"

import base64
import datetime
from os import remove
from os.path import join

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import dateutil.parser
import pytz

import saml2.cryptography.pki


class WrongInput(Exception):
    pass


class CertificateError(Exception):
    pass


class PayloadError(Exception):
    pass


class OpenSSLWrapper:
    def __init__(self):
        pass

    def create_certificate(
        self,
        cert_info,
        request=False,
        valid_from=0,
        valid_to=315360000,
        sn=1,
        key_length=1024,
        write_to_file=False,
        cert_dir="",
        cipher_passphrase=None,
    ):
        """
        Can create certificate requests, to be signed later by another
        certificate with the method
        create_cert_signed_certificate. If request is True.

        Can also create self signed root certificates if request is False.
        This is default behaviour.

        :param cert_info:         Contains information about the certificate.
                                  Is a dictionary that must contain the keys:
                                  cn                = Common name. This part
                                  must match the host being authenticated
                                  country_code      = Two letter description
                                  of the country.
                                  state             = State
                                  city              = City
                                  organization      = Organization, can be a
                                  company name.
                                  organization_unit = A unit at the
                                  organization, can be a department.
                                  Example:
                                                    cert_info_ca = {
                                                        "cn": "company.com",
                                                        "country_code": "se",
                                                        "state": "AC",
                                                        "city": "Dorotea",
                                                        "organization":
                                                        "Company",
                                                        "organization_unit":
                                                        "Sales"
                                                    }
        :param request:           True if this is a request for certificate,
                                  that should be signed.
                                  False if this is a self signed certificate,
                                  root certificate.
        :param valid_from:        When the certificate starts to be valid.
                                  Amount of seconds from when the
                                  certificate is generated.
        :param valid_to:          How long the certificate will be valid from
                                  when it is generated.
                                  The value is in seconds. Default is
                                  315360000 seconds, a.k.a 10 years.
        :param sn:                Serial number for the certificate. Default
                                  is 1.
        :param key_length:        Length of the key to be generated. Defaults
                                  to 1024.
        :param write_to_file:     True if you want to write the certificate
                                  to a file. The method will then return
                                  a tuple with path to certificate file and
                                  path to key file.
                                  False if you want to get the result as
                                  strings. The method will then return a tuple
                                  with the certificate string and the key as
                                  string.
                                  WILL OVERWRITE ALL EXISTING FILES WITHOUT
                                  ASKING!
        :param cert_dir:          Where to save the files if write_to_file is
                                  true.
        :param cipher_passphrase  A dictionary with cipher and passphrase.
        Example::
                {"cipher": "blowfish", "passphrase": "qwerty"}

        :return:                  string representation of certificate,
                                  string representation of private key
                                  if write_to_file parameter is False otherwise
                                  path to certificate file, path to private
                                  key file
        """
        cn = cert_info["cn"]

        c_f = None
        k_f = None

        if write_to_file:
            cert_file = f"{cn}.crt"
            key_file = f"{cn}.key"
            try:
                remove(cert_file)
            except Exception:
                pass
            try:
                remove(key_file)
            except Exception:
                pass
            c_f = join(cert_dir, cert_file)
            k_f = join(cert_dir, key_file)

        # create a key pair
        k = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_length,
        )

        # create a self-signed cert
        builder = x509.CertificateBuilder()

        if request:
            builder = x509.CertificateSigningRequestBuilder()

        if len(cert_info["country_code"]) != 2:
            raise WrongInput("Country code must be two letters!")
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,
                               cert_info["country_code"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                               cert_info["state"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME,
                               cert_info["city"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               cert_info["organization"]),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               cert_info["organization_unit"]),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
        builder = builder.subject_name(subject_name)
        if not request:
            now = datetime.datetime.now(datetime.UTC)
            builder = builder.serial_number(
                sn,
            ).not_valid_before(
                now + datetime.timedelta(seconds=valid_from),
            ).not_valid_after(
                now + datetime.timedelta(seconds=valid_to),
            ).issuer_name(
                subject_name,
            ).public_key(
                k.public_key(),
            )
        cert = builder.sign(k, hashes.SHA256())

        try:
            tmp_cert = cert.public_bytes(serialization.Encoding.PEM)
            key_encryption = None
            if cipher_passphrase is not None:
                passphrase = cipher_passphrase["passphrase"]
                if isinstance(cipher_passphrase["passphrase"], str):
                    passphrase = passphrase.encode("utf-8")
                key_encryption = serialization.BestAvailableEncryption(passphrase)
            else:
                key_encryption = serialization.NoEncryption()
            tmp_key = k.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=key_encryption,
            )
            if write_to_file:
                with open(c_f, "wb") as fc:
                    fc.write(tmp_cert)
                with open(k_f, "wb") as fk:
                    fk.write(tmp_key)
                return c_f, k_f
            return tmp_cert, tmp_key
        except Exception as ex:
            raise CertificateError("Certificate cannot be generated.", ex)

    def write_str_to_file(self, file, str_data):
        with open(file, "w") as f:
            f.write(str_data)

    def read_str_from_file(self, file, type="pem"):
        with open(file, "rb") as f:
            str_data = f.read()

        if type == "pem":
            return str_data

        if type in ["der", "cer", "crt"]:
            return base64.b64encode(str(str_data))

    def create_cert_signed_certificate(
        self,
        sign_cert_str,
        sign_key_str,
        request_cert_str,
        valid_from=0,
        valid_to=315360000,
        sn=1,
        passphrase=None,
    ):

        """
        Will sign a certificate request with a give certificate.
        :param sign_cert_str:     This certificate will be used to sign with.
                                  Must be a string representation of
                                  the certificate. If you only have a file
                                  use the method read_str_from_file to
                                  get a string representation.
        :param sign_key_str:        This is the key for the ca_cert_str
                                  represented as a string.
                                  If you only have a file use the method
                                  read_str_from_file to get a string
                                  representation.
        :param request_cert_str:  This is the prepared certificate to be
                                  signed. Must be a string representation of
                                  the requested certificate. If you only have
                                  a file use the method read_str_from_file
                                  to get a string representation.
        :param valid_from:        When the certificate starts to be valid.
                                  Amount of seconds from when the
                                  certificate is generated.
        :param valid_to:          How long the certificate will be valid from
                                  when it is generated.
                                  The value is in seconds. Default is
                                  315360000 seconds, a.k.a 10 years.
        :param sn:                Serial number for the certificate. Default
                                  is 1.
        :param passphrase:        Password for the private key in sign_key_str.
        :return:                  String representation of the signed
                                  certificate.
        """
        if isinstance(sign_cert_str, str):
            sign_cert_str = sign_cert_str.encode("utf-8")
        ca_cert = x509.load_pem_x509_certificate(sign_cert_str)
        ca_key = serialization.load_pem_private_key(
            sign_key_str, password=passphrase)
        req_cert = x509.load_pem_x509_csr(request_cert_str)

        now = datetime.datetime.now(datetime.UTC)
        cert = x509.CertificateBuilder().subject_name(
            req_cert.subject,
        ).serial_number(
            sn,
        ).not_valid_before(
            now + datetime.timedelta(seconds=valid_from),
        ).not_valid_after(
            now + datetime.timedelta(seconds=valid_to),
        ).issuer_name(
            ca_cert.subject,
        ).public_key(
            req_cert.public_key(),
        ).sign(ca_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def verify_chain(self, cert_chain_str_list, cert_str):
        """

        :param cert_chain_str_list: Must be a list of certificate strings,
        where the first certificate to be validate
        is in the beginning and the root certificate is last.
        :param cert_str: The certificate to be validated.
        :return:
        """
        for tmp_cert_str in cert_chain_str_list:
            valid, message = self.verify(tmp_cert_str, cert_str)
            if not valid:
                return False, message
            else:
                cert_str = tmp_cert_str
            return (True, "Signed certificate is valid and correctly signed by CA " "certificate.")

    def verify(self, signing_cert_str, cert_str):
        """
        Verifies if a certificate is valid and signed by a given certificate.

        :param signing_cert_str: This certificate will be used to verify the
                                  signature. Must be a string representation
                                 of the certificate. If you only have a file
                                 use the method read_str_from_file to
                                 get a string representation.
        :param cert_str:         This certificate will be verified if it is
                                  correct. Must be a string representation
                                 of the certificate. If you only have a file
                                 use the method read_str_from_file to
                                 get a string representation.
        :return:                 Valid, Message
                                 Valid = True if the certificate is valid,
                                 otherwise false.
                                 Message = Why the validation failed.
        """
        try:
            if isinstance(signing_cert_str, str):
                signing_cert_str = signing_cert_str.encode("utf-8")
            if isinstance(cert_str, str):
                cert_str = cert_str.encode("utf-8")
            ca_cert = x509.load_pem_x509_certificate(signing_cert_str)
            cert = x509.load_pem_x509_certificate(cert_str)
            now = datetime.datetime.now(datetime.UTC)

            if ca_cert.not_valid_before_utc >= now:
                return False, "CA certificate is not valid yet."

            if ca_cert.not_valid_after_utc < now:
                return False, "CA certificate is expired."

            if cert.not_valid_after_utc < now:
                return False, "The signed certificate is expired."

            if cert.not_valid_before_utc >= now:
                return False, "The signed certificate is not valid yet."

            if ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == \
               cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                return False, ("CN may not be equal for CA certificate and the " "signed certificate.")

            try:
                cert.verify_directly_issued_by(ca_cert)
                return True, "Signed certificate is valid and correctly signed by CA certificate."
            except (ValueError, TypeError, InvalidSignature) as e:
                return False, f"Certificate is incorrectly signed: {str(e)}"
        except Exception as e:
            return False, f"Certificate is not valid for an unknown reason. {str(e)}"


def read_cert_from_file(cert_file, cert_type="pem"):
    """Read a certificate from a file.

    If there are multiple certificates in the file, the first is returned.

    :param cert_file: The name of the file
    :param cert_type: The certificate type
    :return: A base64 encoded certificate as a string or the empty string
    """
    if not cert_file:
        return ""

    with open(cert_file, "rb") as fp:
        data = fp.read()

    try:
        cert = None
        if cert_type == "pem":
            cert = x509.load_pem_x509_certificate(data)
        elif cert_type == "der":
            cert = x509.load_der_x509_certificate(data)
        else:
            raise ValueError(f"cert-type {cert_type} not supported")
        pem_data = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    except Exception as e:
        raise CertificateError(e)

    pem_data_no_headers = "".join(pem_data.splitlines()[1:-1])
    return pem_data_no_headers
