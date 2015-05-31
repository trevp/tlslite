# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

"""Implementation of the TLS Record Layer protocol"""

import socket
import errno
from tlslite.constants import ContentType
from .messages import RecordHeader3, RecordHeader2
from .utils.codec import Parser
from .errors import TLSRecordOverflow, TLSIllegalParameterException,\
        TLSAbruptCloseError

class RecordSocket(object):

    """Socket wrapper for reading and writing TLS Records"""

    def __init__(self, sock):
        """
        Assign socket to wrapper

        @type sock: socket.socket
        """
        self.sock = sock
        self.version = (0, 0)

    def _sockSendAll(self, data):
        """
        Send all data through socket

        @type data: bytearray
        @param data: data to send
        @raise socket.error: when write to socket failed
        """
        while 1:
            try:
                bytesSent = self.sock.send(data)
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 1
                    continue
                raise

            if bytesSent == len(data):
                return
            data = data[bytesSent:]
            yield 1

    def send(self, msg):
        """
        Send the message through socket.

        @type msg: bytearray
        @param msg: TLS message to send
        @raise socket.error: when write to socket failed
        """

        data = msg.write()

        header = RecordHeader3().create(self.version,
                                        msg.contentType,
                                        len(data))

        data = header.write() + data

        for result in self._sockSendAll(data):
            yield result

    def _sockRecvAll(self, length):
        """
        Read exactly the amount of bytes specified in L{length} from raw socket.

        @rtype: generator
        @return: generator that will return 0 or 1 in case the socket is non
           blocking and would block and bytearray in case the read finished
        @raise TLSAbruptCloseError: when the socket closed
        """

        buf = bytearray(0)

        if length == 0:
            yield buf

        while True:
            try:
                socketBytes = self.sock.recv(length - len(buf))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                    continue
                else:
                    raise

            #if the connection closed, raise socket error
            if len(socketBytes) == 0:
                raise TLSAbruptCloseError()

            buf += bytearray(socketBytes)
            if len(buf) == length:
                yield buf

    def _recvHeader(self):
        """Read a single record header from socket"""
        #Read the next record header
        buf = bytearray(0)
        ssl2 = False

        result = None
        for result in self._sockRecvAll(1):
            if result in (0, 1):
                yield result
            else: break
        assert result is not None

        buf += result

        if buf[0] in ContentType.all:
            ssl2 = False
            # SSLv3 record layer header is 5 bytes long, we already read 1
            result = None
            for result in self._sockRecvAll(4):
                if result in (0, 1):
                    yield result
                else: break
            assert result is not None
            buf += result
        # XXX this should be 'buf[0] & 128', otherwise hello messages longer
        # than 127 bytes won't be properly parsed
        elif buf[0] == 128:
            ssl2 = True
            # in SSLv2 we need to read 2 bytes in total to know the size of
            # header, we already read 1
            result = None
            for result in self._sockRecvAll(1):
                if result in (0, 1):
                    yield result
                else: break
            assert result is not None
            buf += result
        else:
            raise TLSIllegalParameterException(
                "Record header type doesn't specify known type")

        #Parse the record header
        if ssl2:
            record = RecordHeader2().parse(Parser(buf))
        else:
            record = RecordHeader3().parse(Parser(buf))

        yield record

    def recv(self):
        """
        Read a single record from socket, handles both SSLv2 and SSLv3 record
        layer

        @rtype: generator
        @return: generator that returns 0 or 1 in case the read would be
            blocking or a tuple containing record header (object) and record
            data (bytearray) read from socket
        @raise socket.error: In case of network error
        @raise TLSAbruptCloseError: When the socket was closed on the other
        side in middle of record receiving
        @raise TLSRecordOverflow: When the received record was longer than
        allowed by TLS
        @raise TLSIllegalParameterException: When the record header was
        malformed
        """

        record = None
        for record in self._recvHeader():
            if record in (0, 1):
                yield record
            else: break
        assert record is not None

        #Check the record header fields
        # 18432 = 2**14 (basic record size limit) + 1024 (maximum compression
        # overhead) + 1024 (maximum encryption overhead)
        if record.length > 18432:
            raise TLSRecordOverflow()

        #Read the record contents
        buf = bytearray(0)

        result = None
        for result in self._sockRecvAll(record.length):
            if result in (0, 1):
                yield result
            else: break
        assert result is not None

        buf += result

        yield (record, buf)
