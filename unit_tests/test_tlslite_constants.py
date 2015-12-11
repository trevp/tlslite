# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.constants import CipherSuite, HashAlgorithm, SignatureAlgorithm, \
        ContentType, AlertDescription, AlertLevel, HandshakeType, GroupName

class TestHashAlgorithm(unittest.TestCase):

    def test_toRepr(self):
        self.assertEqual(HashAlgorithm.toRepr(5), 'sha384')

    def test_toRepr_with_invalid_id(self):
        self.assertIsNone(HashAlgorithm.toRepr(None))

    def test_toRepr_with_unknown_id(self):
        self.assertIsNone(HashAlgorithm.toRepr(200))

    def test_toStr_with_unknown_id(self):
        self.assertEqual(HashAlgorithm.toStr(200), '200')

    def test_toStr(self):
        self.assertEqual(HashAlgorithm.toStr(6), 'sha512')

class TestSignatureAlgorithm(unittest.TestCase):

    def test_toRepr(self):
        self.assertEqual(SignatureAlgorithm.toRepr(1), 'rsa')

class TestContentType(unittest.TestCase):

    def test_toRepr_with_invalid_value(self):
        self.assertIsNone(ContentType.toRepr((20, 21, 22, 23)))

    def test_toStr_with_invalid_value(self):
        self.assertEqual(ContentType.toStr((20, 21, 22, 23)),
                         '(20, 21, 22, 23)')

class TestGroupName(unittest.TestCase):

    def test_toRepr(self):
        self.assertEqual(GroupName.toRepr(256), 'ffdhe2048')

    def test_toRepr_with_brainpool(self):
        self.assertEqual(GroupName.toRepr(27), 'brainpoolP384r1')

class TestAlertDescription(unittest.TestCase):
    def test_toRepr(self):
        self.assertEqual(AlertDescription.toStr(40), 'handshake_failure')

class TestAlertLevel(unittest.TestCase):
    def test_toRepr(self):
        self.assertEqual(AlertLevel.toStr(1), 'warning')

class TestHandshakeType(unittest.TestCase):
    def test_toRepr(self):
        self.assertEqual(HandshakeType.toStr(1), 'client_hello')

class TestCipherSuite(unittest.TestCase):

    def test___init__(self):
        cipherSuites = CipherSuite()

        self.assertIsNotNone(cipherSuites)

    def test_filterForVersion_with_SSL3_ciphers(self):
        suites = [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_RC4_128_MD5]

        filtered = CipherSuite.filterForVersion(suites, (3, 0), (3, 0))

        self.assertEqual(filtered,
                         [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_RC4_128_MD5])

        filtered = CipherSuite.filterForVersion(suites, (3, 3), (3, 3))

        self.assertEqual(filtered,
                         [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_RC4_128_MD5])

    def test_filterForVersion_with_unknown_ciphers(self):
        suites = [0, 0xfffe]

        filtered = CipherSuite.filterForVersion(suites, (3, 0), (3, 3))

        self.assertEqual(filtered, [])

    def test_filterForVersion_with_TLS_1_2_ciphers(self):
        suites = [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                  CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256]

        filtered = CipherSuite.filterForVersion(suites, (3, 2), (3, 2))

        self.assertEqual(filtered,
                         [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_RC4_128_MD5])
