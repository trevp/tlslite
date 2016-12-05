# Copyright (c) 2014, Hubert Kario
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

import socket
import errno

from tlslite.messages import Message
from tlslite.recordlayer import RecordSocket
from tlslite.constants import ContentType
from unit_tests.mocksock import MockSocket
from tlslite.errors import TLSRecordOverflow, TLSIllegalParameterException,\
        TLSAbruptCloseError

class TestRecordSocket(unittest.TestCase):
    def test___init__(self):
        sock = RecordSocket(-42)

        self.assertIsNotNone(sock)
        self.assertEqual(sock.sock, -42)
        self.assertEqual(sock.version, (0, 0))

    def test_send(self):
        mockSock = MockSocket(bytearray(0))
        sock = RecordSocket(mockSock)
        sock.version = (3, 3)

        msg = Message(ContentType.handshake, bytearray(10))

        for result in sock.send(msg):
            if result in (0, 1):
                self.assertTrue(False, "Blocking socket")
            else: break

        self.assertEqual(len(mockSock.sent), 1)
        self.assertEqual(bytearray(
            b'\x16' +           # handshake message
            b'\x03\x03' +       # version
            b'\x00\x0a' +       # payload length
            b'\x00'*10          # payload
            ), mockSock.sent[0])

    def test_send_with_very_slow_socket(self):
        mockSock = MockSocket(bytearray(0), maxWrite=1, blockEveryOther=True)
        sock = RecordSocket(mockSock)

        msg = Message(ContentType.handshake, bytearray(b'\x32'*2))

        gotRetry = False
        for result in sock.send(msg):
            if result in (0, 1):
                gotRetry = True
            else: break

        self.assertTrue(gotRetry)
        self.assertEqual([
            bytearray(b'\x16'),  # handshake message
            bytearray(b'\x00'), bytearray(b'\x00'), # version (unset)
            bytearray(b'\x00'), bytearray(b'\x02'), # payload length
            bytearray(b'\x32'), bytearray(b'\x32')],
            mockSock.sent)

    def test_send_with_errored_out_socket(self):
        mockSock = mock.create_autospec(socket.socket)
        mockSock.send.side_effect = socket.error(errno.ETIMEDOUT)

        sock = RecordSocket(mockSock)

        msg = Message(ContentType.handshake, bytearray(10))

        gen = sock.send(msg)

        with self.assertRaises(socket.error):
            next(gen)

    def test_recv(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ))
        sock = RecordSocket(mockSock)

        for result in sock.recv():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")
            else: break

        header, data = result

        self.assertEqual(data, bytearray(4))
        self.assertEqual(header.type, ContentType.handshake)
        self.assertEqual(header.version, (3, 3))
        self.assertEqual(header.length, 4)

    def test_recv_stops_itelf(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ))
        sock = RecordSocket(mockSock)

        for result in sock.recv():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")

        header, data = result

        self.assertEqual(data, bytearray(4))
        self.assertEqual(header.type, ContentType.handshake)
        self.assertEqual(header.version, (3, 3))
        self.assertEqual(header.length, 4)

    def test_recv_with_trickling_socket(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ), maxRet=1)

        sock = RecordSocket(mockSock)

        for result in sock.recv():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")
            else: break

        header, data = result

        self.assertEqual(bytearray(4), data)

    def test_recv_with_blocking_socket(self):
        mockSock = mock.create_autospec(socket.socket)
        mockSock.recv.side_effect = socket.error(errno.EWOULDBLOCK)

        sock = RecordSocket(mockSock)

        gen = sock.recv()

        self.assertEqual(0, next(gen))

    def test_recv_with_errored_out_socket(self):
        mockSock = mock.create_autospec(socket.socket)
        mockSock.recv.side_effect = socket.error(errno.ETIMEDOUT)

        sock = RecordSocket(mockSock)

        gen = sock.recv()

        with self.assertRaises(socket.error):
            next(gen)

    def test_recv_with_empty_socket(self):
        mockSock = mock.create_autospec(socket.socket)
        mockSock.recv.side_effect = [bytearray(0)]

        sock = RecordSocket(mockSock)

        gen = sock.recv()

        with self.assertRaises(TLSAbruptCloseError):
            next(gen)

    def test_recv_with_slow_socket(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ), maxRet=1, blockEveryOther=True)

        sock = RecordSocket(mockSock)

        gotRetry = False
        for result in sock.recv():
            if result in (0, 1):
                gotRetry = True
            else: break

        header, data = result

        self.assertTrue(gotRetry)
        self.assertEqual(bytearray(4), data)

    def test_recv_with_malformed_record(self):
        mockSock = MockSocket(bytearray(
            b'\x01' +           # wrong type
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x01' +       # length
            b'\x00'))

        sock = RecordSocket(mockSock)

        gen = sock.recv()

        with self.assertRaises(TLSIllegalParameterException):
            next(gen)

    def test_recv_with_too_big_record(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\xff\xff' +       # length
            b'\x00'*65536))

        sock = RecordSocket(mockSock)

        gen = sock.recv()

        with self.assertRaises(TLSRecordOverflow):
            next(gen)


    def test_recv_with_empty_data(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x00'))       # length

        sock = RecordSocket(mockSock)

        gen = sock.recv()

        for result in sock.recv():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")
            else: break

        header, data = result

        self.assertEqual(ContentType.handshake, header.type)
        self.assertEqual((3, 3), header.version)
        self.assertEqual(0, header.length)

        self.assertEqual(bytearray(0), data)

    def test_recv_with_SSL2_record(self):
        mockSock = MockSocket(bytearray(
            b'\x80' +           # tag
            b'\x04' +           # length
            b'\x00'*4))

        sock = RecordSocket(mockSock)

        for result in sock.recv():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")
            else: break

        header, data = result

        self.assertTrue(header.ssl2)
        self.assertEqual(ContentType.handshake, header.type)
        self.assertEqual(4, header.length)
        self.assertEqual((2, 0), header.version)

        self.assertEqual(bytearray(4), data)

    def test_recv_with_not_complete_SSL2_record(self):
        mockSock = MockSocket(bytearray(
            b'\x80' +           # tag
            b'\x04' +           # length
            b'\x00'*3))

        sock = RecordSocket(mockSock)

        for result in sock.recv():
            break

        self.assertEqual(0, result)

    def test_recv_with_SSL2_record_with_incomplete_header(self):
        mockSock = MockSocket(bytearray(
            b'\x80'             # tag
            ))

        sock = RecordSocket(mockSock)

        for result in sock.recv():
            break

        self.assertEqual(0, result)
