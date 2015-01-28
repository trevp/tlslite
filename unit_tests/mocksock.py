# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

import socket
import errno
class MockSocket(socket.socket):
    def __init__(self, buf):
        self.index = 0
        self.buf = buf
        self.sent = []
        self.closed = False

    def __repr__(self):
        return "MockSocket(index={0}, buf={1!r}, sent={2!r})".format(
                self.index, self.buf, self.sent)

    def recv(self, size):
        if self.closed:
            raise ValueError("Read from closed socket")
        if size == 0:
            return bytearray(0)
        if len(self.buf[self.index:]) == 0:
            raise socket.error(errno.EWOULDBLOCK)
        elif len(self.buf[self.index:]) < size:
            ret = self.buf[self.index:]
            self.index = len(self.buf)
            return ret
        else:
            ret = self.buf[self.index:self.index+size]
            self.index+=size
            return ret

    def send(self, data):
        if self.closed:
            raise ValueError("Write to closed socket")
        self.sent.append(data)
        return len(data)

    def close(self):
        self.closed = True
