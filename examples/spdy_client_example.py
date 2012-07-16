#!/usr/bin/env python2
# coding: utf-8

# Very basic TLS Client using tlslite (0.4.1 library, which supports NPN).
# It connects to a SPDY v2 server doing Client NPN Negotiation and prints out
# the SPDY frames in/out the pipe. 
# python-spdy library required: https://github.com/marcelofernandez/python-spdy
# Python 2.7+, does NOT work in Python 3.x.
# https://groups.google.com/d/msg/spdy-dev/gY66X7Ew0aA/HbN_lmUGT5kJ
#
# Author: Marcelo Fernández
# marcelo.fidel.fernandez@gmail.com / mail@marcelofernandez.info

import sys
import socket
import spdy
from spdy.frames import SynStream, Ping
from tlslite.api import TLSConnection

DEFAULT_HOST = 'www.google.com'
DEFAULT_PORT = 443

def str2hexa(string, columns=4):
    """ Helper function to print hexadecimal bytestrings.
        Columns controls how many columns (bytes) are printer before end of line.
        If columns == 0, then only add EoL at the end.

        Example:
            In [5]: str2hexa('abc\n')
            Out[5]: '0x61 0x62 0x63 0x0A'

        TODO: Doesn't work in python 3, remedy this
    """
    hexa =''
    if columns < 1: columns = len(string)
    for i, s in enumerate(string, 1):
        hexa += '0x%02x' % ord(s) + ' '
        if i % columns == 0:
            hexa = hexa[:-1] + '\n'
    return hexa[:-1]

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

def ping_test(spdy_ctx):
    """ Just Pings the server through a SPDY Ping Frame """
    ping_frame = Ping(spdy_ctx.next_ping_id)
    print('>>', ping_frame)
    spdy_ctx.put_frame(ping_frame)

def get_page(spdy_ctx, host, url='/'):
    syn_frame = SynStream(stream_id=spdy_ctx.next_stream_id, \
                      flags=spdy.FLAG_FIN, \
                      headers={'method' : 'GET',
                               'url'   : url,
                               'version': 'HTTP/1.1',
                               'host'   : host,
                               'scheme' : 'https',
                               })
    print('>>', syn_frame)
    spdy_ctx.put_frame(syn_frame)

def get_frame(spdy_ctx):
    try:
        return spdy_ctx.get_frame()
    except spdy.SpdyProtocolError as e:
        print ('error parsing frame: %s' % str(e))

if __name__ == '__main__':
    host, port = parse_args()

    print('Trying to connect to %s:%i' % (host, port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    connection = TLSConnection(sock)
    connection.handshakeClientCert(nextProtos=["spdy/2"])

    spdy_ctx = spdy.Context(spdy.CLIENT)

    ping_test(spdy_ctx)
    get_page(spdy_ctx, host)

    out = spdy_ctx.outgoing()
#    print str2hexa(str(out))
    connection.write(out)
    file_out = open('/tmp/spdyout.txt', 'wb')
    goaway = False
    while not goaway:
        answer = connection.read() # Blocking
#        print '<<\n', str2hexa(answer)
        spdy_ctx.incoming(answer)
        frame = get_frame(spdy_ctx)
        while frame:
            print ('<<', frame)
            if hasattr(frame, 'data'):
                file_out.write(frame.data)
                file_out.flush()
            frame = get_frame(spdy_ctx)
            if isinstance(frame, spdy.Goaway):
                goaway = True