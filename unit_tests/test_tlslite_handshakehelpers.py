# Copyright (c) 2014, Karel Srot
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from tlslite.handshakehelpers import HandshakeHelpers
from tlslite.messages import ClientHello
from tlslite.extensions import SNIExtension

class TestHandshakeHelpers(unittest.TestCase):
    def test_alignClientHelloPadding_length_less_than_256_bytes(self):
        clientHello = ClientHello()
        clientHello.create((3,0), bytearray(32), bytearray(0), [])

        clientHelloLength = len(clientHello.write())
        self.assertTrue(clientHelloLength - 4 < 256)

        HandshakeHelpers.alignClientHelloPadding(clientHello)

        # clientHello should not be changed due to small length
        self.assertEqual(clientHelloLength, len(clientHello.write()))

    def test_alignClientHelloPadding_length_256_bytes(self):
        clientHello = ClientHello()
        clientHello.create((3,0), bytearray(32), bytearray(0), [])
        clientHello.extensions = []

        ext = SNIExtension()
        ext.create(hostNames=[
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeee'),
        ])
        clientHello.extensions.append(ext)
        clientHelloLength = len(clientHello.write())
        # clientHello length (excluding 4B header) should equal to 256
        self.assertEqual(256, clientHelloLength - 4)

        HandshakeHelpers.alignClientHelloPadding(clientHello)

        # clientHello length (excluding 4B header) should equal to 512
        data = clientHello.write()
        self.assertEqual(512, len(data) - 4)
        # previously created data should be extended with the padding extension
        # starting with the padding extension type \x00\x15 (21)
        self.assertEqual(bytearray(b'\x00\x15'), data[clientHelloLength:clientHelloLength+2])

    def test_alignClientHelloPadding_length_of_508_bytes(self):
        clientHello = ClientHello()
        clientHello.create((3,0), bytearray(32), bytearray(0), [])
        clientHello.extensions = []

        ext = SNIExtension()
        ext.create(hostNames=[
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccdddd'),
        ])
        clientHello.extensions.append(ext)
        clientHelloLength = len(clientHello.write())
        self.assertEqual(508, clientHelloLength - 4)

        HandshakeHelpers.alignClientHelloPadding(clientHello)

        # clientHello length should equal to 512, ignoring handshake
        # protocol header (4B)
        data = clientHello.write()
        self.assertEqual(512, len(data) - 4)
        # padding extension should have zero byte size
        self.assertEqual(bytearray(b'\x00\x15\x00\x00'), data[clientHelloLength:])

    def test_alignClientHelloPadding_length_of_511_bytes(self):
        clientHello = ClientHello()
        clientHello.create((3,0), bytearray(32), bytearray(0), [])
        clientHello.extensions = []

        ext = SNIExtension()
        ext.create(hostNames=[
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddd'),
        ])
        clientHello.extensions.append(ext)
        clientHelloLength = len(clientHello.write())
        self.assertEqual(511, clientHelloLength - 4)

        HandshakeHelpers.alignClientHelloPadding(clientHello)

        # clientHello length should equal to 515, ignoring handshake
        # protocol header (4B)
        data = clientHello.write()
        self.assertEqual(515, len(data) - 4)
        # padding extension should have zero byte size
        self.assertEqual(bytearray(b'\x00\x15\x00\x00'), data[clientHelloLength:])


    def test_alignClientHelloPadding_length_of_512_bytes(self):
        clientHello = ClientHello()
        clientHello.create((3,0), bytearray(32), bytearray(0), [])
        clientHello.extensions = []

        ext = SNIExtension()
        ext.create(hostNames=[
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee'),
            bytearray(b'aaaaaaaaaabbbbbbbbbbccccccccccdddddddd'),
        ])
        clientHello.extensions.append(ext)
        clientHelloLength = len(clientHello.write())
        self.assertEqual(512, clientHelloLength - 4)

        HandshakeHelpers.alignClientHelloPadding(clientHello)

        # clientHello should not be changed due to sufficient length (>=512)
        self.assertEqual(clientHelloLength, len(clientHello.write()))

    def test_alignClientHelloPadding_extension_list_initialization(self):
        clientHello = ClientHello()
        clientHello.create((3,0), bytearray(32), bytearray(0), range(0, 129))

        clientHelloLength = len(clientHello.write())
        self.assertTrue(512 > clientHelloLength - 4 > 255)

        HandshakeHelpers.alignClientHelloPadding(clientHello)

        # verify that the extension list has been added to clientHello
        self.assertTrue(type(clientHello.extensions) is list)
        # clientHello length should equal to 512, ignoring handshake
        # protocol header (4B)
        data = clientHello.write()
        self.assertEqual(512, len(data) - 4)
        # padding extension should have been added after 2 extra bytes
        # added due to an extension list
        self.assertEqual(bytearray(b'\x00\x15'), data[clientHelloLength+2:clientHelloLength+4])

if __name__ == '__main__':
    unittest.main()
