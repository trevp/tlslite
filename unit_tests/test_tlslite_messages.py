# Author: Hubert Kario (c) 2014
# see LICENCE file for legal information regarding use of this file

import unittest
from tlslite.messages import ClientHello
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

if __name__ == '__main__':
    unittest.main()
