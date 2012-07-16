#!/usr/bin/env python
# coding: utf-8

# https://groups.google.com/d/msg/spdy-dev/gY66X7Ew0aA/HA9iblM0zGAJ
# Very basic example of Server TLS-NPN Negotiation posted in the SPDY-dev group

import os, socket, struct, sys, tlslite
spdy_port = 4443

CERTIFICATE_FILE = os.path.join(os.path.dirname(__file__), 'localhost.pem')
KEY_FILE = os.path.join(os.path.dirname(__file__), 'localhost.key')
assert os.path.isfile(CERTIFICATE_FILE), \
    'Cannot find SSL certificate file localhost.pem'
assert os.path.isfile(KEY_FILE), \
    'Cannot find SSL certificate file localhost.key'

cert_pem_bytes = file(CERTIFICATE_FILE, 'r').read()
x509 = tlslite.X509()
x509.parse(cert_pem_bytes)
cert_chain = tlslite.X509CertChain([x509])

key_pem_bytes = file(KEY_FILE, 'r').read()
key = tlslite.parsePEMKey(key_pem_bytes, private=True)

spdy_server_socket = socket.socket()
spdy_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
spdy_server_socket.bind(('localhost', spdy_port))
spdy_server_socket.listen(16)

print 'Please open https://localhost:%d in Firefox >= 13.x...' % spdy_port

while 1:
  client_socket = spdy_server_socket.accept()[0]
  tls_connection = tlslite.api.TLSConnection(client_socket)
  tls_connection.handshakeServer(nextProtos=["spdy/2", "http/1.1"],
                                 certChain=cert_chain,
                                 privateKey=key)
  break;

if tls_connection.next_proto:
    print 'Next-Protocol Negotiated with Client: %s' % tls_connection.next_proto
else:
    print 'No Next-Protocol Negotiated with Client' 
request = ''
while len(request) < 100: # Adjust this value, YMMV
    request += tls_connection.recv(16384)
print 'Request chunk: %d bytes %s' % (len(request), repr(request))
print 'SPDY header DWORDS: %08X %08X' % struct.unpack('!II', request[:8])
sys.exit(1)
