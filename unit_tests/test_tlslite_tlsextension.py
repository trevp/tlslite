# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
from tlslite.tlsextension import TLSExtension
from tlslite.utils.codec import Parser

class TestTLSExtension(unittest.TestCase):
    def test___init__(self):
        tls_extension = TLSExtension()

        assert(tls_extension)
        self.assertIsNone(tls_extension.ext_type)
        self.assertEqual(bytearray(0), tls_extension.ext_data)

    def test_create(self):
        tls_extension = TLSExtension().create(1, bytearray(b'\x01\x00'))

        assert tls_extension
        self.assertEqual(1, tls_extension.ext_type)
        self.assertEqual(bytearray(b'\x01\x00'), tls_extension.ext_data)

    def test_write(self):
        tls_extension = TLSExtension()

        with self.assertRaises(AssertionError) as environment:
            tls_extension.write()

    def test_write_with_data(self):
        tls_extension = TLSExtension().create(44, bytearray(b'garbage'))

        self.assertEqual(bytearray(
            b'\x00\x2c' +       # type of extension - 44
            b'\x00\x07' +       # length of extension - 7 bytes
            # utf-8 encoding of "garbage"
            b'\x67\x61\x72\x62\x61\x67\x65'
            ), tls_extension.write())

    def test_parse(self):
        p = Parser(bytearray(
            b'\x00\x42' + # type of extension
            b'\x00\x01' + # length of rest of data
            b'\xff'       # value of extension
            ))
        tls_extension = TLSExtension().parse(p)

        self.assertEqual(66, tls_extension.ext_type)
        self.assertEqual(bytearray(b'\xff'), tls_extension.ext_data)

    def test_parse_with_length_long_by_one(self):
        p = Parser(bytearray(
            b'\x00\x42' + # type of extension
            b'\x00\x03' + # length of rest of data
            b'\xff\xfa'   # value of extension
            ))

        with self.assertRaises(SyntaxError) as context:
            TLSExtension().parse(p)

if __name__ == '__main__':
    unittest.main()
