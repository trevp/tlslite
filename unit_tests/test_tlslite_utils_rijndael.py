# Copyright (c) 2016, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
from __future__ import division
try:
        import unittest2 as unittest
except ImportError:
        import unittest

import tlslite.utils.rijndael as rijndael

class TestConstants(unittest.TestCase):
    pass

class TestSelfDecryptEncrypt(unittest.TestCase):
    def enc_dec(self, k_len, b_len):
        plaintext = bytearray(b'b' * b_len)
        cipher = rijndael.rijndael(bytearray(b'a' * k_len), b_len)
        self.assertEqual(plaintext,
                         cipher.decrypt(cipher.encrypt(plaintext)))

    def test_16_16(self):
        self.enc_dec(16, 16)

    def test_16_24(self):
        self.enc_dec(16, 24)

    def test_16_32(self):
        self.enc_dec(16, 32)

    def test_24_16(self):
        self.enc_dec(24, 16)

    def test_24_24(self):
        self.enc_dec(24, 24)

    def test_24_32(self):
        self.enc_dec(24, 32)

    def test_32_16(self):
        self.enc_dec(32, 16)

    def test_32_24(self):
        self.enc_dec(32, 24)

    def test_32_32(self):
        self.enc_dec(32, 32)

