#!/usr/bin/env python
# coding: utf-8
# Very basic TLS Client using tlslite (0.4.1 library, which supports NPN).
# https://groups.google.com/d/msg/spdy-dev/gY66X7Ew0aA/HbN_lmUGT5kJ

import socket

from tlslite.api import *

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('mail.google.com', 443))
    #sock.connect(('localhost', 443))
    connection = TLSConnection(sock)
    connection.handshakeClientCert(nextProtos=["spdy/2"])
    print connection.read().encode('hex')
