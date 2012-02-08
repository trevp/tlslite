# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""PyCrypto AES implementation."""

from .cryptomath import *
from .aes import *

if pycryptoLoaded:
    import Crypto.Cipher.AES

    def new(key, mode, IV):
        return PyCrypto_AES(key, mode, IV)

    class PyCrypto_AES(AES):

        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, "pycrypto")
            key = bytesToString(key)
            IV = bytesToString(IV)
            self.context = Crypto.Cipher.AES.new(key, mode, IV)

        def encrypt(self, plaintext):
            plaintext = bytesToString(plaintext)
            return stringToBytes(self.context.encrypt(plaintext))

        def decrypt(self, ciphertext):
            ciphertext = bytesToString(ciphertext)
            return stringToBytes(self.context.decrypt(ciphertext))