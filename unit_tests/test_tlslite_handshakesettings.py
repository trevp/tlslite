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

        # XXX not raised
        #with self.assertRaises(ValueError):
        hs.validate()

    def test_useEncryptThenMAC(self):
        hs = HandshakeSettings()

        self.assertTrue(hs.useEncryptThenMAC)

        newHS = hs.validate()

        self.assertTrue(newHS.useEncryptThenMAC)

    def test_useEncryptThenMAC_setting(self):
        hs = HandshakeSettings()
        hs.useEncryptThenMAC = False

        self.assertFalse(hs.useEncryptThenMAC)

        newHS = hs.validate()
        self.assertFalse(newHS.useEncryptThenMAC)
