#!/usr/bin/env python

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

import sys
import os
import os.path
import socket
import thread
import time
import getopt
import httplib
import BaseHTTPServer
import SimpleHTTPServer

from tlslite import TLSConnection, Fault, HandshakeSettings, \
    X509, X509CertChain, IMAP4_TLS, VerifierDB, Session, SessionCache, \
    parsePEMKey, \
    AlertDescription, HTTPTLSConnection, TLSSocketServerMixIn, \
    POP3_TLS, m2cryptoLoaded, pycryptoLoaded, gmpyLoaded, tackpyLoaded, \
    Checker, __version__

from tlslite.errors import *
from tlslite.utils.cryptomath import prngName

try:
    from TACKpy import TACK, TACK_Break_Sig
except ImportError:
    pass

def printUsage(s=None):
    if m2cryptoLoaded:
        crypto = "M2Crypto/OpenSSL"
    else:
        crypto = "Python crypto"        
    if s:
        print("ERROR: %s" % s)
    print("""\ntls.py version %s (using %s)  

Commands:
  server HOST:PORT DIRECTORY

  client HOST:PORT DIRECTORY
""" % (__version__, crypto))
    sys.exit(-1)
    

def testConnClient(conn):
    b1 = os.urandom(1)
    b10 = os.urandom(10)
    b100 = os.urandom(100)
    b1000 = os.urandom(1000)
    conn.write(b1)
    conn.write(b10)
    conn.write(b100)
    conn.write(b1000)
    assert(conn.read(min=1, max=1) == b1)
    assert(conn.read(min=10, max=10) == b10)
    assert(conn.read(min=100, max=100) == b100)
    assert(conn.read(min=1000, max=1000) == b1000)

def clientTestCmd(argv):
    
    address = argv[0]
    dir = argv[1]    

    #Split address into hostname/port tuple
    address = address.split(":")
    address = ( address[0], int(address[1]) )

    def connect():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(sock, 'settimeout'): #It's a python 2.3 feature
            sock.settimeout(5)
        sock.connect(address)
        c = TLSConnection(sock)
        return c

    test = 0

    badFault = False
    
    print "Test 1 - good X509"
    connection = connect()
    connection.handshakeClientCert()
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print "Test 1.a - good X509, SSLv3"
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)    
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()    
    
    if tackpyLoaded:
        print "Test 2.a - good X.509, good TACK"
        connection = connect()
        connection.handshakeClientCert(reqTack=True, 
         checker=Checker(tackID="BHNHV.8Q3RM.Q74EA.4X8F1.FMQEQ", hardTack=True))
        testConnClient(connection)    
        connection.close()    

        try:
            print "Test 2.b - good X.509, \"wrong\" TACK"
            connection = connect()
            connection.handshakeClientCert(reqTack=True, 
             checker=Checker(tackID="B4444.EQ61B.F34EL.9KKLN.3WEW5", hardTack=True))
            assert(False)
        except TLSTackMismatchError:
            pass

        print "Test 2.c - good X.509, \"wrong\" TACK but break signature (hardTack)"
        connection = connect()
        try:
            connection.handshakeClientCert(reqTack=True, 
                checker=Checker(tackID="BHNHV.8Q3RM.Q74EA.4X8F1.FMQEQ", hardTack=True))
            assert(False)
        except TLSTackBreakError:
            pass

        print "Test 2.d - good X.509, \"wrong\" TACK but break signature (not hardTack)"
        connection = connect()
        connection.handshakeClientCert(reqTack=True, 
            checker=Checker(tackID="BHNHV.8Q3RM.Q74EA.4X8F1.FMQEQ", hardTack=False))
        testConnClient(connection)    
        connection.close()    

        print "Test 2.e - good X.509, TACK unrelated to cert chain"
        connection = connect()
        try:
            connection.handshakeClientCert(reqTack=True)
            assert(False)
        except TLSLocalAlert as alert:
            assert(alert.description == AlertDescription.handshake_failure)
        connection.close()

        try:
            print "Test 2.f - good X.509, no TACK but expected"
            connection = connect()
            connection.handshakeClientCert(reqTack=True, 
                checker=Checker(tackID="B4444.EQ61B.F34EL.9KKLN.3WEW5", hardTack=False))
            assert(False)
        except TLSTackMissingError:
            pass

    print "Test 3 - good SRP"
    connection = connect()
    connection.handshakeClientSRP("test", "password")
    testConnClient(connection)
    connection.close()

    print "Test 4 - SRP faults"
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientSRP("test", "password")
            print "  Good Fault %s" % (Fault.faultNames[fault])
        except TLSFaultError, e:
            print "  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e))
            badFault = True

    print "Test 6 - good SRP: with X.509 certificate, TLSv1.0"
    settings = HandshakeSettings()
    settings.minVersion = (3,1)
    settings.maxVersion = (3,1)    
    connection = connect()
    connection.handshakeClientSRP("test", "password", settings=settings)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    testConnClient(connection)
    connection.close()

    print "Test 7 - X.509 with SRP faults"
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientSRP("test", "password")
            print "  Good Fault %s" % (Fault.faultNames[fault])
        except TLSFaultError, e:
            print "  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e))
            badFault = True

    print "Test 11 - X.509 faults"
    for fault in Fault.clientNoAuthFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientCert()
            print "  Good Fault %s" % (Fault.faultNames[fault])
        except TLSFaultError, e:
            print "  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e))
            badFault = True

    print "Test 14 - good mutual X509"
    x509Cert = X509().parse(open(os.path.join(dir, "clientX509Cert.pem")).read())
    x509Chain = X509CertChain([x509Cert])
    s = open(os.path.join(dir, "clientX509Key.pem")).read()
    x509Key = parsePEMKey(s, private=True)

    connection = connect()
    connection.handshakeClientCert(x509Chain, x509Key)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print "Test 14.a - good mutual X509, SSLv3"
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeClientCert(x509Chain, x509Key, settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print "Test 15 - mutual X.509 faults"
    for fault in Fault.clientCertFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientCert(x509Chain, x509Key)
            print "  Good Fault %s" % (Fault.faultNames[fault])
        except TLSFaultError, e:
            print "  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e))
            badFault = True

    print "Test 18 - good SRP, prepare to resume..."
    connection = connect()
    connection.handshakeClientSRP("test", "password")
    testConnClient(connection)
    connection.close()
    session = connection.session

    print "Test 19 - resumption"
    connection = connect()
    connection.handshakeClientSRP("test", "garbage", session=session)
    testConnClient(connection)
    #Don't close! -- see below

    print "Test 20 - invalidated resumption"
    connection.sock.close() #Close the socket without a close_notify!
    connection = connect()
    try:
        connection.handshakeClientSRP("test", "garbage", session=session)
        assert(False)
    except TLSRemoteAlert, alert:
        if alert.description != AlertDescription.bad_record_mac:
            raise
    connection.close()

    print "Test 21 - HTTPS test X.509"
    address = address[0], address[1]+1
    if hasattr(socket, "timeout"):
        timeoutEx = socket.timeout
    else:
        timeoutEx = socket.error
    while 1:
        try:
            time.sleep(2)
            htmlBody = open(os.path.join(dir, "index.html")).read()
            fingerprint = None
            for y in range(2):
                h = HTTPTLSConnection(\
                        address[0], address[1], x509Fingerprint=fingerprint)
                for x in range(3):
                    h.request("GET", "/index.html")
                    r = h.getresponse()
                    assert(r.status == 200)
                    s = r.read()
                    assert(s == htmlBody)
                fingerprint = h.tlsSession.serverCertChain.getFingerprint()
                assert(fingerprint)
            time.sleep(2)
            break
        except timeoutEx:
            print "timeout, retrying..."
            pass

    address = address[0], address[1]+1

    implementations = []
    if m2cryptoLoaded:
        implementations.append("openssl")
    if pycryptoLoaded:
        implementations.append("pycrypto")
    implementations.append("python")

    print "Test 22 - different ciphers, TLSv1.0"
    for implementation in implementations:
        for cipher in ["aes128", "aes256", "rc4"]:

            print "Test 22:",
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]
            settings.minVersion = (3,1)
            settings.maxVersion = (3,1)            
            connection.handshakeClientCert(settings=settings)
            testConnClient(connection)
            print ("%s %s" % (connection.getCipherName(), connection.getCipherImplementation()))
            connection.close()

    print "Test 23 - throughput test"
    for implementation in implementations:
        for cipher in ["aes128", "aes256", "3des", "rc4"]:
            if cipher == "3des" and implementation not in ("openssl", "pycrypto"):
                continue

            print "Test 23:",
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]
            connection.handshakeClientCert(settings=settings)
            print ("%s %s:" % (connection.getCipherName(), connection.getCipherImplementation())),

            startTime = time.clock()
            connection.write("hello"*10000)
            h = connection.read(min=50000, max=50000)
            stopTime = time.clock()
            if stopTime-startTime:
                print "100K exchanged at rate of %d bytes/sec" % int(100000/(stopTime-startTime))
            else:
                print "100K exchanged very fast"

            assert(h == "hello"*10000)
            connection.close()

    print "Test 24 - Internet servers test"
    try:
        i = IMAP4_TLS("cyrus.andrew.cmu.edu")
        i.login("anonymous", "anonymous@anonymous.net")
        i.logout()
        print "Test 24: IMAP4 good"
        p = POP3_TLS("pop.gmail.com")
        p.quit()
        print "Test 24: POP3 good"
    except socket.error, e:
        print "Non-critical error: socket error trying to reach internet server: ", e

    if not badFault:
        print "Test succeeded"
    else:
        print "Test failed"



def testConnServer(connection):
    count = 0
    while 1:
        s = connection.read()
        count += len(s)
        if len(s) == 0:
            break
        connection.write(s)
        if count == 1111:
            break

def serverTestCmd(argv):

    address = argv[0]
    dir = argv[1]
    
    #Split address into hostname/port tuple
    address = address.split(":")
    address = ( address[0], int(address[1]) )

    #Connect to server
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(address)
    lsock.listen(5)

    def connect():
        return TLSConnection(lsock.accept()[0])

    print "Test 1 - good X.509"
    x509Cert = X509().parse(open(os.path.join(dir, "serverX509Cert.pem")).read())
    x509Chain = X509CertChain([x509Cert])
    s = open(os.path.join(dir, "serverX509Key.pem")).read()
    x509Key = parsePEMKey(s, private=True)

    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
    testConnServer(connection)    
    connection.close()

    print "Test 1.a - good X.509, SSL v3"
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, settings=settings)
    testConnServer(connection)
    connection.close()        
    
    if tackpyLoaded:
        # TACK1 and TACK2 are both "good" TACKs, one targetting, the key,
        # one the hash
        tack1 = TACK()
        tack1.parsePem(open("./TACK1.pem", "rU").read())
        tack2 = TACK()
        tack2.parsePem(open("./TACK2.pem", "rU").read())
        tackUnrelated = TACK()
        tackUnrelated.parsePem(open("./TACKunrelated.pem", "rU").read())    
        breakSigs = TACK_Break_Sig.parsePemList(
            open("./TACK_Break_Sigs.pem").read())
        breakSigsActual = TACK_Break_Sig.parsePemList(
            open("./TACK_Break_Sigs_TACK1.pem").read())    

        print "Test 2.a - good X.509, good TACK"
        connection = connect()
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
            tack=tack1, breakSigs=breakSigs)
        testConnServer(connection)    
        connection.close()        

        print "Test 2.b - good X.509, \"wrong\" TACK"
        connection = connect()
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
            tack=tack1)
        connection.close()        

        print "Test 2.c - good X.509, \"wrong\" TACK but break signature (hardTack)"
        connection = connect()
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
            tack=tack2, breakSigs=breakSigsActual)

        print "Test 2.d - good X.509, \"wrong\" TACK but break signature (not hardTack)"
        connection = connect()
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
            tack=tack2, breakSigs=breakSigsActual)
        testConnServer(connection)    
        connection.close()

        print "Test 2.e - good X.509, TACK unrelated to cert chain"
        connection = connect()
        try:
            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                tack=tackUnrelated)
        except TLSRemoteAlert as alert:
            assert(alert.description == AlertDescription.handshake_failure)

        print "Test 2.f - good X.509, no TACK but expected"
        connection = connect()
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
        connection.close()        

    print "Test 3 - good SRP"
    verifierDB = VerifierDB()
    verifierDB.create()
    entry = VerifierDB.makeVerifier("test", "password", 1536)
    verifierDB["test"] = entry

    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB)
    testConnServer(connection)
    connection.close()

    print "Test 4 - SRP faults"
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(verifierDB=verifierDB)
            assert()
        except:
            pass
        connection.close()

    print "Test 6 - good SRP: with X.509 cert"
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, \
                               certChain=x509Chain, privateKey=x509Key)
    testConnServer(connection)    
    connection.close()

    print "Test 7 - X.509 with SRP faults"
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(verifierDB=verifierDB, \
                                       certChain=x509Chain, privateKey=x509Key)
            assert()
        except:
            pass
        connection.close()

    print "Test 11 - X.509 faults"
    for fault in Fault.clientNoAuthFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
            assert()
        except:
            pass
        connection.close()

    print "Test 14 - good mutual X.509"
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True)
    testConnServer(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print "Test 14a - good mutual X.509, SSLv3"
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True, settings=settings)
    testConnServer(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print "Test 15 - mutual X.509 faults"
    for fault in Fault.clientCertFaults + Fault.genericFaults:
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True)
            assert()
        except:
            pass
        connection.close()

    print "Test 18 - good SRP, prepare to resume"
    sessionCache = SessionCache()
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    testConnServer(connection)
    connection.close()

    print "Test 19 - resumption"
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    testConnServer(connection)    
    #Don't close! -- see next test

    print "Test 20 - invalidated resumption"
    try:
        connection.read(min=1, max=1)
        assert() #Client is going to close the socket without a close_notify
    except TLSAbruptCloseError, e:
        pass
    connection = connect()
    try:
        connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    except TLSLocalAlert, alert:
        if alert.description != AlertDescription.bad_record_mac:
            raise
    connection.close()

    print "Test 21 - HTTPS test X.509"

    #Close the current listening socket
    lsock.close()

    #Create and run an HTTP Server using TLSSocketServerMixIn
    class MyHTTPServer(TLSSocketServerMixIn,
                       BaseHTTPServer.HTTPServer):
        def handshake(self, tlsConnection):
                tlsConnection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
                return True
    cd = os.getcwd()
    os.chdir(dir)
    address = address[0], address[1]+1
    httpd = MyHTTPServer(address, SimpleHTTPServer.SimpleHTTPRequestHandler)
    for x in range(6):
        httpd.handle_request()
    httpd.server_close()
    cd = os.chdir(cd)

    #Re-connect the listening socket
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    address = address[0], address[1]+1
    lsock.bind(address)
    lsock.listen(5)

    def connect():
        return TLSConnection(lsock.accept()[0])

    implementations = []
    if m2cryptoLoaded:
        implementations.append("openssl")
    if pycryptoLoaded:
        implementations.append("pycrypto")
    implementations.append("python")

    print "Test 22 - different ciphers"
    for implementation in ["python"] * len(implementations):
        for cipher in ["aes128", "aes256", "rc4"]:

            print "Test 22:",
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]

            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                                        settings=settings)
            print connection.getCipherName(), connection.getCipherImplementation()
            testConnServer(connection)
            connection.close()

    print "Test 23 - throughput test"
    for implementation in implementations:
        for cipher in ["aes128", "aes256", "3des", "rc4"]:
            if cipher == "3des" and implementation not in ("openssl", "pycrypto"):
                continue

            print "Test 23:",
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]

            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                                        settings=settings)
            print connection.getCipherName(), connection.getCipherImplementation()
            h = connection.read(min=50000, max=50000)
            assert(h == "hello"*10000)
            connection.write(h)
            connection.close()

    print "Test succeeded"


if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "client"[:len(sys.argv[1])]:
        clientTestCmd(sys.argv[2:])
    elif sys.argv[1] == "server"[:len(sys.argv[1])]:
        serverTestCmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])
      