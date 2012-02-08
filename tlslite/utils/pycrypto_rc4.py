# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""PyCrypto RC4 implementation."""

from .cryptomath import *
from .rc4 import *

if pycryptoLoaded:
    import Crypto.Cipher.ARC4

    def new(key):
        return PyCrypto_RC4(key)

    class PyCrypto_RC4(RC4):

        def __init__(self, key):
            RC4.__init__(self, key, "pycrypto")
            key = bytesToString(key)
            self.context = Crypto.Cipher.ARC4.new(key)

        def encrypt(self, plaintext):
            plaintext = bytesToString(plaintext)
            return stringToBytes(self.context.encrypt(plaintext))

        def decrypt(self, ciphertext):
            ciphertext = bytesToString(ciphertext)
            return stringToBytes(self.context.decrypt(ciphertext))