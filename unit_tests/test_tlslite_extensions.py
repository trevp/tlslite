# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
from tlslite.extensions import TLSExtension, SNIExtension, NPNExtension,\
        SRPExtension, ClientCertTypeExtension, ServerCertTypeExtension
from tlslite.utils.codec import Parser
from tlslite.constants import NameType

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

    def test_parse_with_sni_ext(self):
        p = Parser(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x10' +   # length of extension - 16 bytes
            b'\x00\x0e' +   # length of array
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        tls_extension = TLSExtension().parse(p)

        self.assertEqual(bytearray(b'example.com'), tls_extension.host_names[0])

    def test_equality(self):
        a = TLSExtension().create(0, bytearray(0))
        b = SNIExtension().create()

        self.assertTrue(a == b)

    def test_equality_with_empty_array_in_sni_extension(self):
        a = TLSExtension().create(0, bytearray(b'\x00\x00'))
        b = SNIExtension().create(server_names=[])

        self.assertTrue(a == b)

    def test_parse_of_server_hello_extension(self):
        ext = TLSExtension(server=True)

        p = Parser(bytearray(
            b'\x00\x09' +       # extension type - cert_type (9)
            b'\x00\x01' +       # extension length - 1 byte
            b'\x01'             # certificate type - OpenGPG (1)
            ))

        ext = ext.parse(p)

        self.assertEqual(1, ext.cert_type)

class TestSNIExtension(unittest.TestCase):
    def test___init__(self):
        server_name = SNIExtension()

        self.assertEqual(None, server_name.server_names)
        self.assertEqual(tuple(), server_name.host_names)
        # properties inherited from TLSExtension:
        self.assertEqual(0, server_name.ext_type)
        self.assertEqual(bytearray(0), server_name.ext_data)

    def test_create(self):
        server_name = SNIExtension()
        server_name = server_name.create()

        self.assertEqual(None, server_name.server_names)
        self.assertEqual(tuple(), server_name.host_names)

    def test_create_with_hostname(self):
        server_name = SNIExtension()
        server_name = server_name.create(bytearray(b'example.com'))

        self.assertEqual((bytearray(b'example.com'),), server_name.host_names)
        self.assertEqual([SNIExtension.ServerName(
            NameType.host_name,
            bytearray(b'example.com')
            )], server_name.server_names)

    def test_create_with_host_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(host_names=[bytearray(b'example.com'),
            bytearray(b'www.example.com')])

        self.assertEqual((
            bytearray(b'example.com'),
            bytearray(b'www.example.com')
            ), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(
                NameType.host_name,
                bytearray(b'example.com')),
            SNIExtension.ServerName(
                NameType.host_name,
                bytearray(b'www.example.com'))],
            server_name.server_names)

    def test_create_with_server_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com')),
            SNIExtension.ServerName(0, bytearray(b'example.net'))])

        self.assertEqual((bytearray(b'example.net'),), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(
                1, bytearray(b'example.com')),
            SNIExtension.ServerName(
                4, bytearray(b'www.example.com')),
            SNIExtension.ServerName(
                0, bytearray(b'example.net'))],
            server_name.server_names)

    def test_host_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[
            SNIExtension.ServerName(0, bytearray(b'example.net')),
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))
            ])

        server_name.host_names = \
                [bytearray(b'example.com')]

        self.assertEqual((bytearray(b'example.com'),), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(0, bytearray(b'example.com')),
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))],
            server_name.server_names)

    def test_host_names_delete(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[
            SNIExtension.ServerName(0, bytearray(b'example.net')),
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))
            ])

        del server_name.host_names

        self.assertEqual(tuple(), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))],
            server_name.server_names)

    def test_write(self):
        server_name = SNIExtension()
        server_name = server_name.create(bytearray(b'example.com'))

        self.assertEqual(bytearray(
            b'\x00\x0e' +   # length of array - 14 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'
            ), server_name.ext_data)

        self.assertEqual(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x10' +   # length of extension - 16 bytes
            b'\x00\x0e' +   # length of array - 14 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'
            ), server_name.write())

    def test_write_with_multiple_hostnames(self):
        server_name = SNIExtension()
        server_name = server_name.create(host_names=[
            bytearray(b'example.com'),
            bytearray(b'example.org')])

        self.assertEqual(bytearray(
            b'\x00\x1c' +   # lenght of array - 28 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # utf-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d' +
            b'\x00' +       # type of elemnt - host_name (0)
            b'\x00\x0b' +   # length of elemnet - 11 bytes
            # utf-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67'
            ), server_name.ext_data)

        self.assertEqual(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x1e' +   # length of extension - 26 bytes
            b'\x00\x1c' +   # lenght of array - 24 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # utf-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d' +
            b'\x00' +       # type of elemnt - host_name (0)
            b'\x00\x0b' +   # length of elemnet - 11 bytes
            # utf-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67'
            ), server_name.write())

    def test_write_of_empty_extension(self):
        server_name = SNIExtension()

        self.assertEqual(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x00'     # length of extension - 0 bytes
            ), server_name.write())

    def test_write_of_empty_list_of_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[])

        self.assertEqual(bytearray(
            b'\x00\x00'    # length of array - 0 bytes
            ), server_name.ext_data)

        self.assertEqual(bytearray(
            b'\x00\x00' +  # type of extension - SNI 0
            b'\x00\x02' +  # length of extension - 2 bytes
            b'\x00\x00'    # length of array of names - 0 bytes
            ), server_name.write())

    def test_parse(self):
        server_name = SNIExtension()

        p = Parser(bytearray(0))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_null_length_array(self):
        server_name = SNIExtension()

        p = Parser(bytearray(b'\x00\x00'))

        server_name = server_name.parse(p)

        self.assertEqual([], server_name.server_names)

    def test_parse_with_host_name(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x0e' +   # length of array
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        server_name = server_name.parse(p)

        self.assertEqual(bytearray(b'example.com'), server_name.host_names[0])
        self.assertEqual(tuple([bytearray(b'example.com')]),
                server_name.host_names)

    def test_parse_with_multiple_host_names(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        server_name = server_name.parse(p)

        self.assertEqual(bytearray(b'example.com'), server_name.host_names[0])
        self.assertEqual(tuple([bytearray(b'example.com')]),
                server_name.host_names)

        SN = SNIExtension.ServerName

        self.assertEqual([
            SN(10, bytearray(b'example.org')),
            SN(0, bytearray(b'example.com'))
            ], server_name.server_names)

    def test_parse_with_array_length_long_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x0f' +   # length of array (one too long)
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_with_array_length_short_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x0d' +   # length of array (one too short)
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_with_name_length_long_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0c' +   # length of name - 12 bytes (long by one)
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0c' +   # length of name - 12 bytes (long by one)
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_with_name_length_short_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0a' +   # length of name - 10 bytes (short by one)
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0a' +   # length of name - 10 bytes (short by one)
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

class TestClientCertTypeExtension(unittest.TestCase):
    def test___init___(self):
        cert_type = ClientCertTypeExtension()

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(0), cert_type.ext_data)
        self.assertEqual(None, cert_type.cert_types)

    def test_create(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create()

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(0), cert_type.ext_data)
        self.assertEqual(None, cert_type.cert_types)

    def test_create_with_empty_list(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create([])

        self.assertEqual(bytearray(b'\x00'), cert_type.ext_data)
        self.assertEqual([], cert_type.cert_types)

    def test_create_with_list(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create([0])

        self.assertEqual(bytearray(b'\x01\x00'), cert_type.ext_data)
        self.assertEqual([0], cert_type.cert_types)

    def test_write(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create([0, 1])

        self.assertEqual(bytearray(
            b'\x00\x09' +
            b'\x00\x03' +
            b'\x02' +
            b'\x00\x01'), cert_type.write())

    def test_parse(self):
        cert_type = ClientCertTypeExtension()

        p = Parser(bytearray(b'\x00'))

        cert_type = cert_type.parse(p)

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual([], cert_type.cert_types)

    def test_parse_with_list(self):
        cert_type = ClientCertTypeExtension()

        p = Parser(bytearray(b'\x02\x01\x00'))

        cert_type = cert_type.parse(p)

        self.assertEqual([1, 0], cert_type.cert_types)

    def test_parse_with_length_long_by_one(self):
        cert_type = ClientCertTypeExtension()

        p = Parser(bytearray(b'\x03\x01\x00'))

        with self.assertRaises(SyntaxError):
            cert_type.parse(p)

class TestServerCertTypeExtension(unittest.TestCase):
    def test___init__(self):
        cert_type = ServerCertTypeExtension()

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(0), cert_type.ext_data)
        self.assertEqual(None, cert_type.cert_type)

    def test_create(self):
        cert_type = ServerCertTypeExtension().create(0)

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(b'\x00'), cert_type.ext_data)
        self.assertEqual(0, cert_type.cert_type)

    def test_parse(self):
        p = Parser(bytearray(
            b'\x00'             # certificate type - X.509 (0)
            ))

        cert_type = ServerCertTypeExtension().parse(p)

        self.assertEqual(0, cert_type.cert_type)

    def test_parse_with_no_data(self):
        p = Parser(bytearray(0))

        cert_type = ServerCertTypeExtension()

        with self.assertRaises(SyntaxError):
            cert_type.parse(p)

    def test_parse_with_too_much_data(self):
        p = Parser(bytearray(b'\x00\x00'))

        cert_type = ServerCertTypeExtension()

        with self.assertRaises(SyntaxError):
            cert_type.parse(p)

    def test_write(self):
        cert_type = ServerCertTypeExtension().create(1)

        self.assertEqual(bytearray(
            b'\x00\x09' +       # extension type - cert_type (9)
            b'\x00\x01' +       # extension length - 1 byte
            b'\x01'             # selected certificate type - OpenPGP (1)
            ), cert_type.write())

class TestSRPExtension(unittest.TestCase):
    def test___init___(self):
        srp_extension = SRPExtension()

        self.assertEqual(None, srp_extension.identity)
        self.assertEqual(12, srp_extension.ext_type)
        self.assertEqual(bytearray(0), srp_extension.ext_data)

    def test_create(self):
        srp_extension = SRPExtension()
        srp_extension = srp_extension.create()

        self.assertEqual(None, srp_extension.identity)
        self.assertEqual(12, srp_extension.ext_type)
        self.assertEqual(bytearray(0), srp_extension.ext_data)

    def test_create_with_name(self):
        srp_extension = SRPExtension()
        srp_extension = srp_extension.create(bytearray(b'username'))

        self.assertEqual(bytearray(b'username'), srp_extension.identity)
        self.assertEqual(bytearray(
            b'\x08' + # length of string - 8 bytes
            b'username'), srp_extension.ext_data)

    def test_create_with_too_long_name(self):
        srp_extension = SRPExtension()

        with self.assertRaises(ValueError):
            srp_extension = srp_extension.create(bytearray(b'a'*256))

    def test_write(self):
        srp_extension = SRPExtension()
        srp_extension = srp_extension.create(bytearray(b'username'))

        self.assertEqual(bytearray(
            b'\x00\x0c' +   # type of extension - SRP (12)
            b'\x00\x09' +   # length of extension - 9 bytes
            b'\x08' +       # length of encoded name
            b'username'), srp_extension.write())

    def test_parse(self):
        srp_extension = SRPExtension()
        p = Parser(bytearray(b'\x00'))

        srp_extension = srp_extension.parse(p)

        self.assertEqual(bytearray(0), srp_extension.identity)

    def test_parse(self):
        srp_extension = SRPExtension()
        p = Parser(bytearray(
            b'\x08' +
            b'username'))

        srp_extension = srp_extension.parse(p)

        self.assertEqual(bytearray(b'username'),
                srp_extension.identity)

    def test_parse_with_length_long_by_one(self):
        srp_extension = SRPExtension()
        p = Parser(bytearray(
            b'\x09' +
            b'username'))

        with self.assertRaises(SyntaxError):
            srp_extension = srp_extension.parse(p)

class TestNPNExtension(unittest.TestCase):
    def test___init___(self):
        npn_extension = NPNExtension()

        self.assertEqual(None, npn_extension.protocols)
        self.assertEqual(13172, npn_extension.ext_type)
        self.assertEqual(bytearray(0), npn_extension.ext_data)

    def test_create(self):
        npn_extension = NPNExtension()
        npn_extension = npn_extension.create()

        self.assertEqual(None, npn_extension.protocols)
        self.assertEqual(13172, npn_extension.ext_type)
        self.assertEqual(bytearray(0), npn_extension.ext_data)

    def test_create_with_list_of_protocols(self):
        npn_extension = NPNExtension()
        npn_extension = npn_extension.create([
            bytearray(b'http/1.1'),
            bytearray(b'spdy/3')])

        self.assertEqual([
            bytearray(b'http/1.1'),
            bytearray(b'spdy/3')], npn_extension.protocols)
        self.assertEqual(bytearray(
            b'\x08' +   # length of name of protocol
            # utf-8 encoding of "http/1.1"
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31' +
            b'\x06' +   # length of name of protocol
            # utf-8 encoding of "http/1.1"
            b'\x73\x70\x64\x79\x2f\x33'
            ), npn_extension.ext_data)

    def test_write(self):
        npn_extension = NPNExtension().create()

        self.assertEqual(bytearray(
            b'\x33\x74' +   # type of extension - NPN
            b'\x00\x00'     # length of extension
            ), npn_extension.write())

    def test_write_with_list(self):
        npn_extension = NPNExtension()
        npn_extensnio = npn_extension.create([
            bytearray(b'http/1.1'),
            bytearray(b'spdy/3')])

        self.assertEqual(bytearray(
            b'\x33\x74' +   # type of extension - NPN
            b'\x00\x10' +   # length of extension
            b'\x08' +       # length of name of protocol
            # utf-8 encoding of "http/1.1"
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31' +
            b'\x06' +       # length of name of protocol
            # utf-8 encoding of "spdy/3"
            b'\x73\x70\x64\x79\x2f\x33'
            ), npn_extension.write())

    def test_parse(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(0))

        npn_extension = npn_extension.parse(p)

        self.assertEqual(bytearray(0), npn_extension.ext_data)
        self.assertEqual([], npn_extension.protocols)

    def test_parse_with_procotol(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(
            b'\x08' +   # length of name
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'))

        npn_extension = npn_extension.parse(p)

        self.assertEqual([bytearray(b'http/1.1')], npn_extension.protocols)

    def test_parse_with_protocol_length_short_by_one(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(
            b'\x07' +   # length of name - 7 (short by one)
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'))

        with self.assertRaises(SyntaxError):
            npn_extension.parse(p)

    def test_parse_with_protocol_length_long_by_one(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(
            b'\x09' +   # length of name - 9 (short by one)
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'))

        with self.assertRaises(SyntaxError):
            npn_extension.parse(p)

if __name__ == '__main__':
    unittest.main()
