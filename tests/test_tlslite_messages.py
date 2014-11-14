# Author: Hubert Kario (c) 2014
# see LICENCE file for legal information regarding use of this file

import unittest
from tlslite.messages import ClientHello, ServerHello
from tlslite.utils.codec import Parser
from tlslite.constants import CipherSuite, CertificateType

class TestClientHello(unittest.TestCase):
    def test___init__(self):
        client_hello = ClientHello()

        assert client_hello
        self.assertEqual(False, client_hello.ssl2)
        self.assertEqual((0,0), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)

    def test_create(self):
        client_hello = ClientHello()
        client_hello.create((3,0), bytearray(32), bytearray(0), \
                [])

        self.assertEqual((3,0), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([0], client_hello.compression_methods)

    def test_create_with_one_ciphersuite(self):
        client_hello = ClientHello()
        client_hello.create((3,0), bytearray(32), bytearray(0), \
                [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV])

        self.assertEqual((3,0), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV], \
                client_hello.cipher_suites)
        self.assertEqual([0], client_hello.compression_methods)

    def test_create_with_random(self):
        client_hello = ClientHello()
        client_hello.create((3,0), bytearray(b'\x01' + \
                b'\x00'*30 + b'\x02'), bytearray(0), \
                [])

        self.assertEqual((3,0), client_hello.client_version)
        self.assertEqual(bytearray(b'\x01' + b'\x00'*30 + b'\x02'), \
                client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([0], client_hello.compression_methods)

    def test_parse(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x26' + # length - 38 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00'               # compression methods length
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)

    def test_write(self):
        # client_hello = ClientHello(ssl2)
        client_hello = ClientHello()

        self.assertEqual(list(bytearray(
            b'\x01' +               # type of message - client_hello
            b'\x00'*2 + b'\x26' +   # length - 38 bytes
            b'\x00'*2 +             # protocol version
            b'\x00'*32 +            # client random
            b'\x00' +               # session ID length
            b'\x00'*2 +             # cipher suites length
            b'\x00'                 # compression methods length
            )), list(client_hello.write()))

    def test_write_with_certificate_types(self):

        # note that ClienHello is "clever" and doesn't send the extension
        # if only x509 certificate type is present, so we pass two values
        client_hello = ClientHello().create((3,1),
                bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                [], certificate_types=[
                    CertificateType.x509, CertificateType.openpgp])

        self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x30' +   # length - 48 bytes
                b'\x03\x01' +           # protocol version (TLS 1.0)
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x07' +           # extensions length
                b'\x00\x09' +           # cert_type extension value (9)
                b'\x00\x03' +           # size of the extension
                b'\x02' +               # length of supported types
                b'\x00' +               # type - X.509
                b'\x01'                 # type - OpenPGP
                )), list(client_hello.write()))

    def test_write_with_srp_username(self):
        client_hello = ClientHello().create((3,1),
                bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                [], srpUsername="example-test")

        self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x3a' +   # length - 58 bytes
                b'\x03\x01' +           # protocol version (TLS 1.0)
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x11' +           # extensions length
                b'\x00\x0c' +           # srp extension value (12)
                b'\x00\x0d' +           # size of the extension
                b'\x0c' +               # length of name
                # ascii encoding of "example-test":
                b'\x65\x78\x61\x6d\x70\x6c\x65\x2d\x74\x65\x73\x74'
                )), list(client_hello.write()))

    def test_write_with_tack(self):
         client_hello = ClientHello().create((3,1),
                 bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                 [], tack=True)

         self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x2d' +   # length - 45 bytes
                b'\x03\x01' +           # protocol version
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x04' +           # extensions length
                b'\xf3\x00' +           # TACK extension value (62208)
                b'\x00\x00'             # size of the extension
                )), list(client_hello.write()))

    def test_write_with_npn(self):
         client_hello = ClientHello().create((3,1),
                 bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                 [], supports_npn=True)

         self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x2d' +   # length - 45 bytes
                b'\x03\x01' +           # protocol version
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x04' +           # extensions length
                b'\x33\x74' +           # NPN extension value (13172)
                b'\x00\x00'             # size of the extension
                )), list(client_hello.write()))

    def test_write_with_server_name(self):
         client_hello = ClientHello().create((3,1),
                 bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                 [], serverName="example.com")

         self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x3d' +   # length - 61 bytes
                b'\x03\x01' +           # protocol version
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x14' +           # extensions length
                b'\x00\x00' +           # servername extension value (0)
                b'\x00\x10' +           # byte size of the extension
                b'\x00\x0e' +           # length of the list
                b'\x00' +               # name type: host_name (0)
                b'\x00\x0b' +           # length of host name
                # utf-8 encoding of "example.com"
                b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'
                )), list(client_hello.write()))

class TestServerHello(unittest.TestCase):
    def test___init__(self):
        server_hello = ServerHello()

        self.assertEqual((0,0), server_hello.server_version)
        self.assertEqual(bytearray(32), server_hello.random)
        self.assertEqual(bytearray(0), server_hello.session_id)
        self.assertEqual(0, server_hello.cipher_suite)
        self.assertEqual(CertificateType.x509, server_hello.certificate_type)
        self.assertEqual(0, server_hello.compression_method)
        self.assertEqual(None, server_hello.tackExt)
        self.assertEqual(None, server_hello.next_protos_advertised)
        self.assertEqual(None, server_hello.next_protos)

    def test_create(self):
        server_hello = ServerHello().create(
                (1,1),                          # server version
                bytearray(b'\x00'*31+b'\x01'),  # random
                bytearray(0),                   # session id
                4,                              # cipher suite
                1,                              # certificate type
                None,                           # TACK ext
                None)                           # next protos advertised

        self.assertEqual((1,1), server_hello.server_version)
        self.assertEqual(bytearray(b'\x00'*31 + b'\x01'), server_hello.random)
        self.assertEqual(bytearray(0), server_hello.session_id)
        self.assertEqual(4, server_hello.cipher_suite)
        self.assertEqual(CertificateType.openpgp, server_hello.certificate_type)
        self.assertEqual(0, server_hello.compression_method)
        self.assertEqual(None, server_hello.tackExt)
        self.assertEqual(None, server_hello.next_protos_advertised)

    def test_parse(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x36' +               # length - 54 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01' +                       # compression method (zlib)
            b'\x00\x0e' +                   # extensions length - 14 bytes
            b'\xff\x01' +                   # ext type - renegotiation_info
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x00' +                       # value - supported (0)
            b'\x00\x23' +                   # ext type - session ticket (35)
            b'\x00\x00' +                   # ext length - 0 bytes
            b'\x00\x0f' +                   # ext type - heartbeat (15)
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x01'))                       # peer allowed to send requests (1)
        server_hello = ServerHello()
        server_hello = server_hello.parse(p)

        self.assertEqual((3,3), server_hello.server_version)
        self.assertEqual(bytearray(b'\x01'*31 + b'\x02'), server_hello.random)
        self.assertEqual(bytearray(0), server_hello.session_id)
        self.assertEqual(157, server_hello.cipher_suite)
        # XXX not sent by server!
        self.assertEqual(CertificateType.x509, server_hello.certificate_type)
        self.assertEqual(1, server_hello.compression_method)
        self.assertEqual(None, server_hello.tackExt)
        self.assertEqual(None, server_hello.next_protos_advertised)

    def test_parse_with_length_short_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x25' +               # length - 37 bytes (one short)
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01'                         # compression method (zlib)
            ))
        server_hello = ServerHello()
        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message probably could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_parse_with_length_long_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x27' +               # length - 39 bytes (one long)
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01'                         # compression method (zlib)
            ))
        server_hello = ServerHello()
        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message probably could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_parse_with_extensions_length_short_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x36' +               # length - 54 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01' +                       # compression method (zlib)
            b'\x00\x0d' +                   # extensions length - 13 bytes (!)
            b'\xff\x01' +                   # ext type - renegotiation_info
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x00' +                       # value - supported (0)
            b'\x00\x23' +                   # ext type - session ticket (35)
            b'\x00\x00' +                   # ext length - 0 bytes
            b'\x00\x0f' +                   # ext type - heartbeat (15)
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x01'))                       # peer allowed to send requests (1)
        server_hello = ServerHello()

        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_parse_with_extensions_length_long_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x36' +               # length - 54 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01' +                       # compression method (zlib)
            b'\x00\x0f' +                   # extensions length - 15 bytes (!)
            b'\xff\x01' +                   # ext type - renegotiation_info
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x00' +                       # value - supported (0)
            b'\x00\x23' +                   # ext type - session ticket (35)
            b'\x00\x00' +                   # ext length - 0 bytes
            b'\x00\x0f' +                   # ext type - heartbeat (15)
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x01'))                       # peer allowed to send requests (1)
        server_hello = ServerHello()

        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_write(self):
        server_hello = ServerHello().create(
                (1,1),                          # server version
                bytearray(b'\x00'*31+b'\x02'),  # random
                bytearray(0),                   # session id
                4,                              # cipher suite
                None,                           # certificate type
                None,                           # TACK ext
                None)                           # next protos advertised

        self.assertEqual(list(bytearray(
            b'\x02' +               # type of message - server_hello
            b'\x00\x00\x26' +       # length
            b'\x01\x01' +           # proto version
            b'\x00'*31 + b'\x02' +  # random
            b'\x00' +               # session id length
            b'\x00\x04' +           # cipher suite
            b'\x00'                 # compression method
            )), list(server_hello.write()))

    def test_write_with_next_protos(self):
        server_hello = ServerHello().create(
                (1,1),                          # server version
                bytearray(b'\x00'*31+b'\x02'),  # random
                bytearray(0),                   # session id
                4,                              # cipher suite
                0,                              # certificate type
                None,                           # TACK ext
                [b'spdy/3', b'http/1.1'])       # next protos advertised

        self.assertEqual(list(bytearray(
            b'\x02' +               # type of message - server_hello
            b'\x00\x00\x3c' +       # length
            b'\x01\x01' +           # proto version
            b'\x00'*31 + b'\x02' +  # random
            b'\x00' +               # session id length
            b'\x00\x04' +           # cipher suite
            b'\x00' +               # compression method
            b'\x00\x14' +           # extensions length
            b'\x33\x74' +           # ext type - NPN (13172)
            b'\x00\x10' +           # ext length - 16 bytes
            b'\x06' +               # first entry length - 6 bytes
            # utf-8 encoding of 'spdy/3'
            b'\x73\x70\x64\x79\x2f\x33'
            b'\x08' +               # second entry length - 8 bytes
            # utf-8 endoding of 'http/1.1'
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'
            )), list(server_hello.write()))

if __name__ == '__main__':
    unittest.main()
