# Author: Hubert Kario (c) 2014
# see LICENCE file for legal information regarding use of this file

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.handshakesettings import HandshakeSettings

class TestHandshakeSettings(unittest.TestCase):
    def test___init__(self):
        hs = HandshakeSettings()

        self.assertIsNotNone(hs)

    def test_validate(self):
        hs = HandshakeSettings()
        newHS = hs.validate()

        self.assertIsNotNone(newHS)
        self.assertIsNot(hs, newHS)

    def test_minKeySize_too_small(self):
        hs = HandshakeSettings()
        hs.minKeySize = 511

        with self.assertRaises(ValueError):
            hs.validate()

    def test_minKeySize_too_large(self):
        hs = HandshakeSettings()
        hs.minKeySize = 16385

        with self.assertRaises(ValueError):
            hs.validate()

    def test_maxKeySize_too_small(self):
        hs = HandshakeSettings()
        hs.maxKeySize = 511

        with self.assertRaises(ValueError):
            hs.validate()

    def test_maxKeySize_too_large(self):
        hs = HandshakeSettings()
        hs.maxKeySize = 16385

        with self.assertRaises(ValueError):
            hs.validate()

    def test_maxKeySize_smaller_than_minKeySize(self):
        hs = HandshakeSettings()
        hs.maxKeySize = 1024
        hs.minKeySize = 2048

        with self.assertRaises(ValueError):
            hs.validate()

    def test_cipherNames_with_unknown_name(self):
        hs = HandshakeSettings()
        hs.cipherNames = ["aes256"]

        newHs = hs.validate()

        self.assertEqual(["aes256"], newHs.cipherNames)

    def test_cipherNames_with_unknown_name(self):
        hs = HandshakeSettings()
        hs.cipherNames = ["aes256gcm", "aes256"]

        with self.assertRaises(ValueError):
            hs.validate()

    def test_cipherNames_empty(self):
        hs = HandshakeSettings()
        hs.cipherNames = []

        with self.assertRaises(ValueError):
            hs.validate()

    def test_certificateTypes_empty(self):
        hs = HandshakeSettings()
        hs.certificateTypes = []

        with self.assertRaises(ValueError):
            hs.validate()

    def test_certificateTypes_with_unknown_type(self):
        hs = HandshakeSettings()
        hs.certificateTypes = [0, 42]

        with self.assertRaises(ValueError):
            hs.validate()

    def test_cipherImplementations_empty(self):
        hs = HandshakeSettings()
        hs.cipherImplementations = []

        with self.assertRaises(ValueError):
            hs.validate()

    def test_cipherImplementations_with_unknown_implementations(self):
        hs = HandshakeSettings()
        hs.cipherImplementations = ["openssl", "NSS"]

        with self.assertRaises(ValueError):
            hs.validate()

    def test_minVersion_higher_than_maxVersion(self):
        hs = HandshakeSettings()
        hs.minVersion = (3, 3)
        hs.maxVersion = (3, 0)

        with self.assertRaises(ValueError):
            hs.validate()

    def test_minVersion_with_unknown_version(self):
        hs = HandshakeSettings()
        hs.minVersion = (2, 0)

        with self.assertRaises(ValueError):
            hs.validate()

    def test_maxVersion_with_unknown_version(self):
        hs = HandshakeSettings()
        hs.maxVersion = (3, 4)

        with self.assertRaises(ValueError):
            hs.validate()

    def test_maxVersion_without_TLSv1_2(self):
        hs = HandshakeSettings()
        hs.maxVersion = (3, 2)

        self.assertTrue('sha256' in hs.macNames)

        new_hs = hs.validate()

        self.assertFalse("sha256" in new_hs.macNames)

    def test_getCertificateTypes(self):
        hs = HandshakeSettings()

        self.assertEqual([0], hs.getCertificateTypes())

    def test_getCertificateTypes_with_unsupported_type(self):
        hs = HandshakeSettings()
        hs.certificateTypes = ["x509", "openpgp"]

        with self.assertRaises(AssertionError):
            hs.getCertificateTypes()
