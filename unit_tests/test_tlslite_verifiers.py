# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
        import unittest2 as unittest
except ImportError:
        import unittest

from tlslite.verifiers import ServerHelloVerifier
from tlslite.messages import ClientHello, ServerHello
from tlslite.constants import CipherSuite, ExtensionType
from tlslite.extensions import TLSExtension, ServerCertTypeExtension,\
        ClientCertTypeExtension
from tlslite.errors import TLSIllegalParameterException,\
        TLSProtocolVersionException
from tlslite.handshakesettings import HandshakeSettings

class TestServerHelloVerifier(unittest.TestCase):
    def test___init__(self):
        verifier = ServerHelloVerifier(None)

        self.assertIsNotNone(verifier)

    def test_verify(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [1]
        client_hello.client_version = (3, 3)
        server_hello = ServerHello()
        server_hello.cipher_suite = 1
        server_hello.server_version = (3, 3)

        verifier = ServerHelloVerifier(client_hello)

        self.assertTrue(verifier.verify(server_hello))

    def test_verify_with_renegotiation_info_scsv(self):
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.cipher_suites = \
                [1, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

        server_hello = ServerHello()
        server_hello.cipher_suite = 1
        server_hello.server_version = (3, 3)
        server_hello.extensions = [TLSExtension().create(\
                ExtensionType.renegotiation_info,
                bytearray(1))]

        verifier = ServerHelloVerifier(client_hello)

        self.assertTrue(verifier.verify(server_hello))

    def test_verify_abort_with_renegotiation_info_without_scsv(self):
        client_hello = ClientHello()

        server_hello = ServerHello()
        server_hello.extensions = [TLSExtension().create(\
                ExtensionType.renegotiation_info,
                bytearray(1))]

        verifier = ServerHelloVerifier(client_hello)

        with self.assertRaises(TLSIllegalParameterException) as context:
            verifier.verify(server_hello)

        self.assertTrue('Extension ID' in str(context.exception))

    def test_verify_with_duplicate_extensions(self):
        client_hello = ClientHello()
        client_hello.extensions = [
                TLSExtension().create(0, bytearray(0))]

        server_hello = ServerHello()
        server_hello.extensions = [
                TLSExtension().create(0, bytearray(0)),
                TLSExtension().create(0, bytearray(1))]

        verifier = ServerHelloVerifier(client_hello)

        with self.assertRaises(TLSIllegalParameterException) as context:
            verifier.verify(server_hello)

        self.assertTrue('Duplicate extensions' in str(context.exception))

    def test_verify_with_wrong_cipher_suite(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [1, 2, 3]

        server_hello = ServerHello()
        server_hello.cipher_suite = 4

        verifier = ServerHelloVerifier(client_hello)

        with self.assertRaises(TLSIllegalParameterException) as context:
            verifier.verify(server_hello)

        self.assertTrue('incorrect ciphersuite' in str(context.exception))

    def test_verify_with_bad_compression(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [0]

        server_hello = ServerHello()
        server_hello.compression_method = 1

        verifier = ServerHelloVerifier(client_hello)

        with self.assertRaises(TLSIllegalParameterException) as context:
            verifier.verify(server_hello)

        self.assertTrue('incorrect compression' in str(context.exception))

    def test_verify_with_too_low_server_version(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [0]
        client_hello.client_version = (3, 3)

        settings = HandshakeSettings()
        settings.minVersion = (3, 2)

        server_hello = ServerHello()
        server_hello.server_version = (3, 1)

        verifier = ServerHelloVerifier(client_hello, settings)

        with self.assertRaises(TLSProtocolVersionException) as context:
            verifier.verify(server_hello)

        self.assertTrue('Too old' in str(context.exception))

    def test_verify_with_too_high_server_version(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [0]
        client_hello.client_version = (3, 3)

        settings = HandshakeSettings()
        settings.maxVersion = (3, 2)

        server_hello = ServerHello()
        server_hello.server_version = (3, 3)

        verifier = ServerHelloVerifier(client_hello, settings)

        with self.assertRaises(TLSProtocolVersionException) as context:
            verifier.verify(server_hello)

        self.assertTrue('Too new' in str(context.exception))

    def test_verify_with_too_high_server_version_selected_by_server(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [0]
        client_hello.client_version = (3, 2)

        server_hello = ServerHello()
        server_hello.server_version = (3, 3)

        verifier = ServerHelloVerifier(client_hello)

        with self.assertRaises(TLSProtocolVersionException) as context:
            verifier.verify(server_hello)

        self.assertTrue('Newer version than adv' in str(context.exception))

    def test_verify_with_correct_cert_type(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [1]
        client_hello.client_version = (3, 3)
        client_hello.extensions = [ClientCertTypeExtension().create([0, 1])]
        server_hello = ServerHello()
        server_hello.cipher_suite = 1
        server_hello.server_version = (3, 3)
        server_hello.extensions = [ServerCertTypeExtension().create(1)]

        verifier = ServerHelloVerifier(client_hello)

        self.assertTrue(verifier.verify(server_hello))

    def test_verify_with_bad_cert_type_selected_by_server(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [1]
        client_hello.client_version = (3, 3)
        client_hello.extensions = [ClientCertTypeExtension().create([1])]
        server_hello = ServerHello()
        server_hello.cipher_suite = 1
        server_hello.server_version = (3, 3)
        server_hello.extensions = [ServerCertTypeExtension().create(0)]

        verifier = ServerHelloVerifier(client_hello)

        with self.assertRaises(TLSIllegalParameterException) as context:
            verifier.verify(server_hello)

        self.assertTrue('incorrect certificate type' in str(context.exception))

    def test_check(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [0]
        client_hello.client_version = (3, 3)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)

        verifier = ServerHelloVerifier(client_hello)

        self.assertTrue(verifier.check(server_hello))

    def test_check_with_bad_server_hello(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [0]
        client_hello.client_version = (3, 3)
        server_hello = ServerHello()
        server_hello.cipher_suite = 1
        server_hello.server_version = (3, 3)

        verifier = ServerHelloVerifier(client_hello)

        self.assertFalse(verifier.check(server_hello))
