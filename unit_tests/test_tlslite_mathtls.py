# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
        import unittest2 as unittest
except ImportError:
        import unittest

from tlslite.mathtls import PRF_1_2, calcMasterSecret

class TestCalcMasterSecret(unittest.TestCase):
    def test_with_empty_values(self):
        ret = calcMasterSecret((3, 3), bytearray(48), bytearray(32),
                               bytearray(32))

        self.assertEqual(bytearray(
            b'I\xcf\xae\xe5[\x86\x92\xd3\xbbm\xd6\xeekSo/' +
            b'\x17\xaf\xbc\x84\x18\tGc\xbc\xb5\xbe\xd6\xb0\x05\xad\xf8' +
            b'\x88\xd0`\xe4\x8c^\xb2&ls\xcb\x1a=-Kh'
            ), ret)
        self.assertEqual(48, len(ret))

class TestPRF1_2(unittest.TestCase):
    def test_with_bogus_values(self):
        ret = PRF_1_2(bytearray(1), b"key expansion", bytearray(1), 10)

        self.assertEqual(bytearray(b'\xaa2\xca\r\x8b\x85N\xad?\xab'), ret)

    def test_with_realistic_values(self):
        ret = PRF_1_2(bytearray(48), b"key expansion", bytearray(64), 16)

        self.assertEqual(bytearray(b'S\xb5\xdb\xc8T }u)BxuB\xe4\xeb\xeb'), ret)
