import os
from base64 import b64decode
from base64 import b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes


POSTFIX_MODE = {
    'cbc': modes.CBC,
    'cfb': modes.CFB,
    'ecb': modes.ECB,
}

AES_BLOCK_SIZE = int(algorithms.AES.block_size / 8)


class AESCipher(object):
    def __init__(self, key, iv=None):
        """
        :param key: The encryption key
        :param iv: Init vector
        :return: AESCipher instance
        """
        self.key = key
        self.iv = iv

    def build_cipher(self, iv=None, alg='aes_128_cbc'):
        """
        :param iv: init vector
        :param alg: cipher algorithm
        :return: A Cipher instance
        """
        typ, bits, cmode = alg.lower().split('_')
        bits = int(bits)

        if not iv:
            if self.iv:
                iv = self.iv
            else:
                iv = os.urandom(AES_BLOCK_SIZE)

        if len(iv) != AES_BLOCK_SIZE:
            raise Exception('Wrong iv size: {}'.format(len(iv)))

        if bits not in algorithms.AES.key_sizes:
            raise Exception('Unsupported key length: {}'.format(bits))

        if len(self.key) != bits / 8:
            raise Exception('Wrong Key length: {}'.format(len(self.key)))

        try:
            mode = POSTFIX_MODE[cmode]
        except KeyError:
            raise Exception('Unsupported chaining mode: {}'.format(cmode))

        cipher = Cipher(
                algorithms.AES(self.key),
                mode(iv),
                backend=default_backend())

        return cipher, iv

    def encrypt(self, msg, iv=None, alg='aes_128_cbc', padding='PKCS#7',
                b64enc=True, block_size=AES_BLOCK_SIZE):
        """
        :param key: The encryption key
        :param iv: init vector
        :param msg: Message to be encrypted
        :param padding: Which padding that should be used
        :param b64enc: Whether the result should be base64encoded
        :param block_size: If PKCS#7 padding which block size to use
        :return: The encrypted message
        """

        if padding == 'PKCS#7':
            _block_size = block_size
        elif padding == 'PKCS#5':
            _block_size = 8
        else:
            _block_size = 0

        if _block_size:
            plen = _block_size - (len(msg) % _block_size)
            c = chr(plen).encode()
            msg += c * plen

        cipher, iv = self.build_cipher(iv, alg)
        encryptor = cipher.encryptor()
        cmsg = iv + encryptor.update(msg) + encryptor.finalize()

        if b64enc:
            enc_msg = b64encode(cmsg)
        else:
            enc_msg = cmsg

        return enc_msg

    def decrypt(self, msg, iv=None, alg='aes_128_cbc', padding='PKCS#7',
                b64dec=True):
        """
        :param key: The encryption key
        :param iv: init vector
        :param msg: Base64 encoded message to be decrypted
        :return: The decrypted message
        """
        data = b64decode(msg) if b64dec else msg

        _iv = data[:AES_BLOCK_SIZE]
        if iv:
            assert iv == _iv
        cipher, iv = self.build_cipher(iv, alg=alg)
        decryptor = cipher.decryptor()
        res = decryptor.update(data)[AES_BLOCK_SIZE:] + decryptor.finalize()
        if padding in ['PKCS#5', 'PKCS#7']:
            idx = bytearray(res)[-1]
            res = res[:-idx]
        return res


def run_test():
    key = b'1234523451234545'  # 16 byte key
    iv = os.urandom(AES_BLOCK_SIZE)
    # Iff padded, the message doesn't have to be multiple of 16 in length
    original_msg = b'ToBeOrNotTobe W.S.'
    aes = AESCipher(key)

    encrypted_msg = aes.encrypt(original_msg, iv)
    decrypted_msg = aes.decrypt(encrypted_msg, iv)
    assert decrypted_msg == original_msg

    encrypted_msg = aes.encrypt(original_msg)
    decrypted_msg = aes.decrypt(encrypted_msg)
    assert decrypted_msg == original_msg

    aes = AESCipher(key, iv)
    encrypted_msg = aes.encrypt(original_msg)
    decrypted_msg = aes.decrypt(encrypted_msg)
    assert decrypted_msg == original_msg


if __name__ == '__main__':
    run_test()
