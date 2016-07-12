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
        hs.cipherNames = ["camellia256gcm", "aes256"]

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

    def test_useEncryptThenMAC(self):
        hs = HandshakeSettings()
        self.assertTrue(hs.useEncryptThenMAC)

        hs.useEncryptThenMAC = False

        n_hs = hs.validate()

        self.assertFalse(n_hs.useEncryptThenMAC)

    def test_useEncryptThenMAC_with_wrong_value(self):
        hs = HandshakeSettings()
        hs.useEncryptThenMAC = None

        with self.assertRaises(ValueError):
            hs.validate()

    def test_useExtendedMasterSecret(self):
        hs = HandshakeSettings()
        self.assertTrue(hs.useExtendedMasterSecret)

        hs.useExtendedMasterSecret = False

        n_hs = hs.validate()

        self.assertFalse(n_hs.useExtendedMasterSecret)

    def test_useExtendedMasterSecret_with_wrong_value(self):
        hs = HandshakeSettings()
        hs.useExtendedMasterSecret = None

        with self.assertRaises(ValueError):
            hs.validate()

    def test_requireExtendedMasterSecret(self):
        hs = HandshakeSettings()
        self.assertFalse(hs.requireExtendedMasterSecret)

        hs.requireExtendedMasterSecret = True

        n_hs = hs.validate()

        self.assertTrue(n_hs.requireExtendedMasterSecret)

    def test_requireExtendedMasterSecret_with_wrong_value(self):
        hs = HandshakeSettings()
        hs.requireExtendedMasterSecret = None

        with self.assertRaises(ValueError):
            hs.validate()

    def test_requireExtendedMasterSecret_with_incompatible_use_EMS(self):
        hs = HandshakeSettings()
        hs.useExtendedMasterSecret = False
        hs.requireExtendedMasterSecret = True

        with self.assertRaises(ValueError):
            hs.validate()

    def test_invalid_MAC(self):
        hs = HandshakeSettings()
        hs.macNames = ['sha1', 'whirpool']

        with self.assertRaises(ValueError):
            hs.validate()

    def test_invalid_KEX(self):
        hs = HandshakeSettings()
        hs.keyExchangeNames = ['rsa', 'ecdhe_rsa', 'gost']

        with self.assertRaises(ValueError):
            hs.validate()

    def test_invalid_signature_algorithm(self):
        hs = HandshakeSettings()
        hs.rsaSigHashes += ['md2']
        with self.assertRaises(ValueError):
            hs.validate()

    def test_no_signature_hashes_set_with_TLS1_2(self):
        hs = HandshakeSettings()
        hs.rsaSigHashes = []
        with self.assertRaises(ValueError):
            hs.validate()

    def test_no_signature_hashes_set_with_TLS1_1(self):
        hs = HandshakeSettings()
        hs.rsaSigHashes = []
        hs.maxVersion = (3, 2)
        self.assertIsNotNone(hs.validate())

    def test_invalid_curve_name(self):
        hs = HandshakeSettings()
        hs.eccCurves = ['P-256']
        with self.assertRaises(ValueError):
            hs.validate()

    def test_usePaddingExtension(self):
        hs = HandshakeSettings()
        self.assertTrue(hs.usePaddingExtension)

    def test_invalid_usePaddingExtension(self):
        hs = HandshakeSettings()
        hs.usePaddingExtension = -1
        with self.assertRaises(ValueError):
            hs.validate()

if __name__ == '__main__':
    unittest.main()
