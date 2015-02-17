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
from tlslite.extensions import TLSExtension
from tlslite.errors import TLSIllegalParameterException

class TestServerHelloVerifier(unittest.TestCase):
    def test___init__(self):
        verifier = ServerHelloVerifier(None)

        self.assertIsNotNone(verifier)

    def test_verify(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = [1]
        server_hello = ServerHello()
        server_hello.cipher_suite = 1

        verifier = ServerHelloVerifier(client_hello)

        self.assertTrue(verifier.verify(server_hello))

    def test_verify_with_renegotiation_info_scsv(self):
        client_hello = ClientHello()
        client_hello.cipher_suites = \
                [1, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

        server_hello = ServerHello()
        server_hello.cipher_suite = 1
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
