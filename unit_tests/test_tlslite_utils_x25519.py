# Copyright (c) 2017, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call

from tlslite.utils.x25519 import decodeUCoordinate, decodeScalar22519, \
        decodeScalar448, x25519, x448
from tlslite.utils.compat import a2b_hex

class TestDecodeUCoordinate(unittest.TestCase):
    def test_x25519_decode(self):
        value = a2b_hex('e6db6867583030db3594c1a424b15f7c7'
                        '26624ec26b3353b10a903a6d0ab1c4c')

        scalar = decodeUCoordinate(value, 255)

        self.assertEqual(scalar, int("344264340339195944511551077811888216513"
                                     "16167215306631574996226621102155684838"))


    def test_u_decode_with_invalid_bits(self):
        v = a2b_hex('e6db6867583030db3594c1a424b15f7c7'
                    '26624ec26b3353b10a903a6d0ab1c4c')
        with self.assertRaises(ValueError):
            decodeUCoordinate(v, 256)


    def test_x448_decode(self):
        value = a2b_hex('06fce640fa3487bfda5f6cf2d5263f8'
                        'aad88334cbd07437f020f08f9'
                        '814dc031ddbdc38c19c6da2583fa542'
                        '9db94ada18aa7a7fb4ef8a086')

        scalar = decodeUCoordinate(value, 448)

        self.assertEqual(scalar, int("38223991081410733011622996123"
                                     "4899377031416365"
                                     "24057132514834655592243802516"
                                     "2094455820962429"
                                     "14297133958436003433731007979"
                                     "1515452463053830"))


    def test_x25519_decode_scalar(self):
        value = a2b_hex('a546e36bf0527c9d3b16154b82465edd6'
                        '2144c0ac1fc5a18506a2244ba449ac4')

        scalar = decodeScalar22519(value)

        self.assertEqual(scalar, int("310298424921150409048955604518630896564"
                                     "72772604678260265531221036453811406496"))


    def test_x448_decode_scalar(self):
        value = a2b_hex('3d262fddf9ec8e88495266fea19a34d2'
                        '8882acef045104d0d1aae121'
                        '700a779c984c24f8cdd78fbff44943eb'
                        'a368f54b29259a4f1c600ad3')

        scalar = decodeScalar448(value)

        self.assertEqual(int("599189175373896402783756016145213256157230856"
                             "085026129926891459468622403380588640249457727"
                             "683869421921443004045221642549886377526240828"),
                         scalar)


    # RFC 7748 Section 5.2, vector #1
    def test_x25519_1(self):
        k = a2b_hex("a546e36bf0527c9d3b16154b82465ed"
                    "d62144c0ac1fc5a18506a2244ba449ac4")
        u = a2b_hex("e6db6867583030db3594c1a424b15f7"
                    "c726624ec26b3353b10a903a6d0ab1c4c")

        ret = x25519(k, u)

        self.assertEqual(a2b_hex("c3da55379de9c6908e94ea4df28d084f"
                                 "32eccf03491c71f754b4075577a28552"),
                         ret)


    # RFC 7748 Section 5.2, vector #2
    def test_x25519_2(self):
        k = a2b_hex("4b66e9d4d1b4673c5ad22691957d6af"
                    "5c11b6421e0ea01d42ca4169e7918ba0d")
        u = a2b_hex("e5210f12786811d3f4b7959d0538ae2"
                    "c31dbe7106fc03c3efc4cd549c715a493")

        ret = x25519(k, u)

        self.assertEqual(ret,
                         a2b_hex("95cbde9476e8907d7aade45cb4b873f88"
                                 "b595a68799fa152e6f8f7647aac7957"))


    # RFC 7748 Section 5.2, vector #3
    def test_x448_1(self):
        k = a2b_hex("3d262fddf9ec8e88495266fea19a34d"
                    "28882acef045104d0d1aae121"
                    "700a779c984c24f8cdd78fbff44943e"
                    "ba368f54b29259a4f1c600ad3")
        u = a2b_hex("06fce640fa3487bfda5f6cf2d5263f8"
                    "aad88334cbd07437f020f08f9"
                    "814dc031ddbdc38c19c6da2583fa542"
                    "9db94ada18aa7a7fb4ef8a086")

        ret = x448(k, u)

        self.assertEqual(ret,
                         a2b_hex("ce3e4ff95a60dc6697da1db1d85e6afbd"
                                 "f79b50a2412d7546d5f239f"
                                 "e14fbaadeb445fc66a01b0779d9822396"
                                 "1111e21766282f73dd96b6f"))


    # RFC 7748 Section 5.2, vector #4
    def test_x448_2(self):
        k = a2b_hex("203d494428b8399352665ddca42f9de"
                    "8fef600908e0d461cb021f8c5"
                    "38345dd77c3e4806e25f46d3315c44e"
                    "0a5b4371282dd2c8d5be3095f")
        u = a2b_hex("0fbcc2f993cd56d3305b0b7d9e55d4c"
                    "1a8fb5dbb52f8e9a1e9b6201b"
                    "165d015894e56c4d3570bee52fe205e"
                    "28a78b91cdfbde71ce8d157db")

        ret = x448(k, u)

        self.assertEqual(ret,
                         a2b_hex("884a02576239ff7a2f2f63b2db6a9ff37"
                                 "047ac13568e1e30fe63c4a7"
                                 "ad1b3ee3a5700df34321d62077e63633c"
                                 "575c1c954514e99da7c179d"))


    def test_x25519_one_iteration(self):
        k = a2b_hex("0900000000000000000000000000000"
                    "000000000000000000000000000000000")
        u = bytearray(k)

        ret = x25519(k, u)

        self.assertEqual(ret,
                         a2b_hex("422c8e7a6227d7bca1350b3e2bb7279f7"
                                 "897b87bb6854b783c60e80311ae3079"))


    @unittest.skip("slow test case")
    def test_x25519_thousand_iterations(self):
        k = a2b_hex("0900000000000000000000000000000"
                    "000000000000000000000000000000000")
        u = bytearray(k)

        for _ in range(1000):
            u, k = bytearray(k), x25519(k, u)

        self.assertEqual(k,
                         a2b_hex("684cf59ba83309552800ef566f2f4d3c"
                                 "1c3887c49360e3875f2eb94d99532c51"))


    @unittest.skip("very slow test case")
    def test_x25519_million_iterations(self):
        k = a2b_hex("0900000000000000000000000000000"
                    "000000000000000000000000000000000")
        u = bytearray(k)

        for _ in range(1000000):
            u, k = bytearray(k), x25519(k, u)

        self.assertEqual(k,
                         a2b_hex("7c3911e0ab2586fd864497297e575e6f3b"
                                 "c601c0883c30df5f4dd2d24f665424"))


    def test_x448_one_iteration(self):
        k = a2b_hex("05000000000000000000000000000000000000000"
                    "000000000000000"
                    "00000000000000000000000000000000000000000"
                    "000000000000000")
        u = bytearray(k)

        ret = x448(k, u)

        self.assertEqual(ret,
                         a2b_hex("3f482c8a9f19b01e6c46ee9711d9dc14fd"
                                 "4bf67af30765c2ae2b846a"
                                 "4d23a8cd0db897086239492caf350b51f8"
                                 "33868b9bc2b3bca9cf4113"))


    @unittest.skip("slow test case")
    def test_x448_thousand_iterations(self):
        k = a2b_hex("05000000000000000000000000000000000000000"
                    "000000000000000"
                    "00000000000000000000000000000000000000000"
                    "000000000000000")
        u = bytearray(k)

        for _ in range(1000):
            u, k = bytearray(k), x448(k, u)

        self.assertEqual(k,
                         a2b_hex("aa3b4749d55b9daf1e5b00288826c46727"
                                 "4ce3ebbdd5c17b975e09d4"
                                 "af6c67cf10d087202db88286e2b79fceea"
                                 "3ec353ef54faa26e219f38"))


    @unittest.skip("very slow test case")
    def test_x448_million_iterations(self):
        k = a2b_hex("05000000000000000000000000000000000000000"
                    "000000000000000"
                    "00000000000000000000000000000000000000000"
                    "000000000000000")
        u = bytearray(k)

        for _ in range(1000000):
            u, k = bytearray(k), x448(k, u)

        self.assertEqual(k,
                         a2b_hex("077f453681caca3693198420bbe515cae"
                                 "0002472519b3e67661a7e89"
                                 "cab94695c8f4bcd66e61b9b9c946da8d5"
                                 "24de3d69bd9d9d66b997e37"))
