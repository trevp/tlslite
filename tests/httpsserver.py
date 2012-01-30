#!/usr/bin/env python

from SocketServer import *
from BaseHTTPServer import *
from SimpleHTTPServer import *
from tlslite import *

s = open("./serverX509Cert.pem").read()
x509 = X509()
x509.parse(s)
certChain = X509CertChain([x509])

s = open("./serverX509Key.pem").read()
privateKey = parsePEMKey(s, private=True)

sessionCache = SessionCache()

class MyHTTPServer(ThreadingMixIn, TLSSocketServerMixIn, HTTPServer):
    def handshake(self, tlsConnection):
        try:
            tlsConnection.handshakeServer(certChain=certChain,
                                          privateKey=privateKey,
                                          sessionCache=sessionCache)
            tlsConnection.ignoreAbruptClose = True
            return True
        except TLSError, error:
            print "Handshake failure:", str(error)
            return False

print("I am a TLS Lite test server, I will listen on localhost:4443")
httpd = MyHTTPServer(('localhost', 4443), SimpleHTTPRequestHandler)
httpd.serve_forever()