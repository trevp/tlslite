#!/usr/bin/env python2
# coding: utf-8
# Very basic TLS Client using tlslite (0.4.1 library, which supports NPN).
# Python 2.7+, does NOT work in Python 3.x.
# https://groups.google.com/d/msg/spdy-dev/gY66X7Ew0aA/HbN_lmUGT5kJ

import sys
import socket
import spdy.frames
from tlslite.api import TLSConnection

DEFAULT_HOST = 'mail.google.com'
DEFAULT_PORT = 443

def str2hexa(string):
    """ Helper function to print hexadecimal bytestrings
        Example:
            In [5]: str2hexa('abc\n')
            Out[5]: '0x61 0x62 0x63 0x0A'
    """
    hexa=''
    for s in string:
        hexa += '0x%02x' % ord(s) + ' '
    return hexa.rstrip()

def parse_args():
    len_args = len(sys.argv)
    if len_args == 2:
        host = sys.argv[1]
        port = DEFAULT_PORT
    elif len_args > 2:
        host = sys.argv[1]
        try:
            port = int(sys.argv[2])
        except ValueError:
            port = DEFAULT_PORT
    else:
        host = DEFAULT_HOST
        port = DEFAULT_PORT
    return (host, port)

if __name__ == '__main__':
    host, port = parse_args()

    print('Trying to connect to %s:%i' % (host, port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    connection = TLSConnection(sock)
    connection.handshakeClientCert(nextProtos=["spdy/2"])

    # Just ping the server
    spdy_ctx = spdy.Context(spdy.CLIENT)
    ping_frame = spdy.frames.Ping(spdy_ctx.next_ping_id)
    spdy_ctx.put_frame(ping_frame)
    out = spdy_ctx.outgoing()

    connection.write(out)
    while True:
        answer = connection.read()
        print('new frame:')
        for i in range(0, len(answer), 4):
            print str2hexa(answer[i:i+4])
