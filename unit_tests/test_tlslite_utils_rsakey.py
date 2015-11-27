# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.utils.rsakey import RSAKey
from tlslite.utils.python_rsakey import Python_RSAKey

# because RSAKey is an abstract class...
class TestRSAKey(unittest.TestCase):

    # random RSA parameters
    N = int("101394340507163232476731540998223559348384567842249950630680016"
            "729829651735259973644737329194901739140557378171784099933376993"
            "53519793819698299093375577631")
    e = 65537
    d = int("141745721972918790698280063566067268498148845185400775263435953"
            "111621933337897734637889622802200979017278309730638712431978569"
            "771023240787627463565420833")
    p = int("903614668974112441151570413608036278756730123846327797584414732"
            "71561046135679")
    q = int("112209710608480690748363491355148749700390327497055102381924341"
            "581861552321889")
    dP = int("37883511062045429960298073888481933556799848761465588242411735"
             "654811958185817")
    dQ = int("62620473256245674709410658602365234471246407950887183034263101"
             "286525236349249")
    qInv = int("479278327226690415958629934820002183615697717603796111150941"
               "44623120451328875")


    def test___init__(self):
        rsa = Python_RSAKey()

        self.assertIsNotNone(rsa)

    def test___init___with_values(self):
        rsa = Python_RSAKey(self.N, self.e, self.d, self.p, self.q, self.dP,
                            self.dQ, self.qInv)

        self.assertIsNotNone(rsa)

    def test_hashAndSign(self):
        rsa = Python_RSAKey(self.N, self.e, self.d, self.p, self.q, self.dP,
                            self.dQ, self.qInv)

        sigBytes = rsa.hashAndSign(bytearray(b'text to sign'))

        self.assertEqual(bytearray(
            b'K\x7f\xf2\xca\x81\xf0A1\x95\xb1\x19\xe3\xd7QTL*Q|\xb6\x04' +
            b'\xbdG\x88H\x12\xc3\xe2\xb3\x97\xd2\xcd\xd8\xe8^Zn^\x8f\x1a' +
            b'\xae\x9a\x0b)\xb5K\xe8\x98|R\xac\xdc\xdc\n\x7f\x8b\xe7\xe6' +
            b'HQ\xc3hS\x19'), sigBytes)

    def test_hashAndVerify(self):
        rsa = Python_RSAKey(self.N, self.e)

        sigBytes = bytearray(
            b'K\x7f\xf2\xca\x81\xf0A1\x95\xb1\x19\xe3\xd7QTL*Q|\xb6\x04' +
            b'\xbdG\x88H\x12\xc3\xe2\xb3\x97\xd2\xcd\xd8\xe8^Zn^\x8f\x1a' +
            b'\xae\x9a\x0b)\xb5K\xe8\x98|R\xac\xdc\xdc\n\x7f\x8b\xe7\xe6' +
            b'HQ\xc3hS\x19')

        self.assertTrue(rsa.hashAndVerify(sigBytes,
                                          bytearray(b'text to sign')))

    def test_hashAndVerify_without_NULL_encoding_of_SHA1(self):
        rsa = Python_RSAKey(self.N, self.e)

        sigBytes = bytearray(
            b'F\xe7\x8a>\x8a<;Cj\xdd\xea\x7f\x9d\x0c\xfd\xa7r\xd8\xa1O' +
            b'\xe1\xf5\x174\x0bR\xad:+\xc9C\x06\xf4\x88n\tp\x14FJ=\xfa' +
            b'\x8b\xefc\xe2\xdf\x00e\xc1\x1e\xe8\xd2\x97@\x8a\x96\xe2' +
            b'\x039Y_\x9c\xc9')

        self.assertTrue(rsa.hashAndVerify(sigBytes,
                                          bytearray(b'text to sign')))

    def test_hashAndVerify_with_invalid_signature(self):
        rsa = Python_RSAKey(self.N, self.e)

        sigBytes = bytearray(64)

        self.assertFalse(rsa.hashAndVerify(sigBytes,
                                           bytearray(b'text to sign')))

    def test_hashAndVerify_with_slightly_wrong_signature(self):
        rsa = Python_RSAKey(self.N, self.e)

        sigBytes = bytearray(
            b'K\x7f\xf2\xca\x81\xf0A1\x95\xb1\x19\xe3\xd7QTL*Q|\xb6\x04' +
            b'\xbdG\x88H\x12\xc3\xe2\xb3\x97\xd2\xcd\xd8\xe8^Zn^\x8f\x1a' +
            b'\xae\x9a\x0b)\xb5K\xe8\x98|R\xac\xdc\xdc\n\x7f\x8b\xe7\xe6' +
            b'HQ\xc3hS\x19')
        sigBytes[0] = 255

        self.assertFalse(rsa.hashAndVerify(sigBytes,
                                           bytearray(b'text to sign')))

    def test_addPKCS1SHA1Prefix(self):
        data = bytearray(b' sha-1 hash of data ')

        self.assertEqual(RSAKey.addPKCS1SHA1Prefix(data), bytearray(
            b'0!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14' + 
            b' sha-1 hash of data '))

    def test_addPKCS1SHA1Prefix_without_NULL(self):
        data = bytearray(b' sha-1 hash of data ')

        self.assertEqual(RSAKey.addPKCS1SHA1Prefix(data, False), bytearray(
            b'0\x1f0\x07\x06\x05+\x0e\x03\x02\x1a\x04\x14' +
            b' sha-1 hash of data '))

    def test_addPKCS1Prefix(self):
        data = bytearray(b' sha-1 hash of data ')

        self.assertEqual(RSAKey.addPKCS1Prefix(data, 'sha1'), bytearray(
            b'0!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14' +
            b' sha-1 hash of data '))
