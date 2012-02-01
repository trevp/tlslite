#!/usr/bin/env python

import sys
from SocketServer import *
from BaseHTTPServer import *
from SimpleHTTPServer import *
from tlslite import *

s = open("./serverX509Cert.pem", "rU").read()
x509 = X509()
x509.parse(s)
certChain = X509CertChain([x509])

s = open("./serverX509Key.pem", "rU").read()
privateKey = parsePEMKey(s, private=True)

try:
    from TACKpy import TACK, TACK_Break_Sig
    s = open("./TACK1.pem", "rU").read()
    tack = TACK()
    tack.parsePem(s)
    s = open("./TACK_Break_Sigs.pem", "rU").read()
    tackBreakSigs = TACK_Break_Sig.parsePemList(s)
    tackStr = " (with TACK)"
except ImportError:
    tack = None
    tackBreakSigs = None
    tackStr = " (with NO TACK)"

sessionCache = SessionCache()

class MyHTTPServer(ThreadingMixIn, TLSSocketServerMixIn, HTTPServer):
    def handshake(self, tlsConnection):
        try:
            tlsConnection.handshakeServer(certChain=certChain,
                                          privateKey=privateKey,
                                          tack=tack,
                                          tackBreakSigs=tackBreakSigs,
                                          sessionCache=sessionCache)
            tlsConnection.ignoreAbruptClose = True
            print("Handshaked!")
            return True
        except TLSError as error:
            print "Handshake failure:", str(error)
            return False

if len(sys.argv) > 1:
    address = sys.argv[1]
    address = address.split(":")
    address = ( address[0], int(address[1]) )
else:
    address = ("localhost", 4443)
print("I am an HTTPS test server%s, I will listen on %s:%d" % 
        (tackStr, address[0], address[1]))
httpd = MyHTTPServer(address, SimpleHTTPRequestHandler)
httpd.serve_forever()