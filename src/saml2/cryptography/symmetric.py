"""This module provides methods for symmetric cryptography.

The default symmetric cryptography method used is Fernet by the cryptography
library. Reference: https://cryptography.io/en/latest/fernet/
"""

import cryptography.fernet as _fernet


class Default(object):
    """The default symmetric cryptography method."""

    @staticmethod
    def generate_key():
        """Return a key suitable for use by this method.

        :return: byte data representing the encyption/decryption key
        """
        key = _fernet.Fernet.generate_key()
        return key

    def __init__(self, key=None):
        """Initialize this method by optionally providing a key.

        :param key: byte data representing the encyption/decryption key
        """
        self._symmetric = _fernet.Fernet(key or self.__class__.generate_key())

    def encrypt(self, plaintext):
        """Encrypt the given plaintext.

        :param plaintext: byte data representing the plaintext
        :return: byte data representing the ciphertext
        """
        ciphertext = self._symmetric.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt the given ciphertext.

        :param ciphertext: byte data representing the ciphertext
        :return: byte data representing the plaintext
        """
        plaintext = self._symmetric.decrypt(ciphertext)
        return plaintext
