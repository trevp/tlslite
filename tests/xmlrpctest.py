import sys
import xmlrpclib
from tlslite import *

s = open("./serverX509Cert.pem").read()
x509 = X509()
x509.parse(s)
certChain = X509CertChain([x509])
s = open("./serverX509Key.pem").read()
privateKey = parsePEMKey(s, private=True)

sessionCache = SessionCache()

class Server(TLSXMLRPCServer):
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

def printUsage(s=None):
    if s:
        print("ERROR: %s" % s)
    print """ 
Commands:
  server HOST:PORT

  client HOST:PORT
"""
    sys.exit(-1)

def serverTestCmd(address):
    #Split address into hostname/port tuple
    address = address.split(":")
    address = ( address[0], int(address[1]) )

    class MyFuncs:
        def pow(self, x, y): return pow(x, y)
        def add(self, x, y) : return x + y

    server = Server(address)
    server.register_instance(MyFuncs())
    sa = server.socket.getsockname()
    print "Serving HTTPS on", sa[0], "port", sa[1]
    server.serve_forever()

def clientTestCmd(address):
    #Split address into hostname/port tuple
    address = address.split(":")
    address = ( address[0], int(address[1]) )

    server = xmlrpclib.Server('https://%s:%s' % address)
    assert server.add(1,2) == 3
    assert server.pow(2,4) == 16
    print 'Test 1 - good standard https client'

    transport = XMLRPCTransport()
    server = xmlrpclib.Server('https://%s:%s' % address, transport)
    assert server.add(1,2) == 3
    assert server.pow(2,4) == 16
    print 'Test 2 - good tlslite client'

    server = xmlrpclib.Server('http://%s:%s' % address, transport)
    assert server.add(1,2) == 3
    assert server.pow(2,4) == 16
    print 'Test 3 - good ignored protocol'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "client"[:len(sys.argv[1])]:
        clientTestCmd(*sys.argv[2:])
    elif sys.argv[1] == "server"[:len(sys.argv[1])]:
        serverTestCmd(*sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])
