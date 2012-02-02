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

if __name__ != "__main__":
    raise "This must be run as a command, not used as a module!"

from tlslite import TLSConnection, TLSFaultError, Fault, HandshakeSettings, \
    X509, X509CertChain, IMAP4_TLS, VerifierDB, Session, SessionCache, \
    TLSLocalAlert, TLSRemoteAlert, TLSAbruptCloseError, parsePEMKey, \
    AlertDescription, HTTPTLSConnection, TLSSocketServerMixIn, \
    POP3_TLS, m2cryptoLoaded, pycryptoLoaded, gmpyLoaded, tackpyLoaded, \
    __version__

from tlslite.utils.cryptomath import prngName

try:
    from TACKpy import TACK, TACK_Break_Sig, writeTextTACKStructures
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
  server  
    [-k KEY] [-c CERT] [-t TACK] [-b BREAKSIGS] [-v VERIFIERDB] [--reqcert]
    HOST:PORT

  client
    [-k KEY] [-c CERT] [-u USER] [-p PASS]
    HOST:PORT
""" % (__version__, crypto))
    sys.exit(-1)

def printError(s):
    """Print error message and exit"""
    sys.stderr.write("ERROR: %s\n" % s)
    sys.exit(-1)


def handleArgs(argv, argString, flagsList=[]):
    # Convert to getopt argstring format:
    # Add ":" after each arg, ie "abc" -> "a:b:c:"
    getOptArgString = ":".join(argString) + ":"
    try:
        opts, argv = getopt.getopt(argv, getOptArgString, flagsList)
    except getopt.GetoptError as e:
        printError(e) 
    # Default values if arg not present  
    privateKey = None
    certChain = None
    username = None
    password = None
    tack = None
    tackBreakSigs = None
    verifierDB = None
    reqCert = False
    
    for opt, arg in opts:
        if opt == "-k":
            s = open(arg, "rb").read()
            privateKey = parsePEMKey(s, private=True)            
        elif opt == "-c":
            s = open(arg, "rb").read()
            x509 = X509()
            x509.parse(s)
            certChain = X509CertChain([x509])
        elif opt == "-u":
            username = arg
        elif opt == "-p":
            password = arg
        elif opt == "-t":
            s = open(arg, "rU").read()
            tack = TACK()
            tack.parsePem(s)
        elif opt == "-b":
            s = open(arg, "rU").read()
            tackBreakSigs = TACK_Break_Sig.parsePemList(s)
        elif opt == "-v":
            verifierDB = VerifierDB(arg)
            verifierDB.open()
        elif opt == "--reqcert":
            reqCert = True
        else:
            assert(False)
            
    if not argv:
        printError("Missing address")
    if len(argv)>1:
        printError("Too many arguments")
    #Split address into hostname/port tuple
    address = argv[0]
    address = address.split(":")
    if len(address) != 2:
        raise SyntaxError("Must specify <host>:<port>")
    address = ( address[0], int(address[1]) )

    # Populate the return list
    retList = [address]
    if "k" in argString:
        retList.append(privateKey)
    if "c" in argString:
        retList.append(certChain)
    if "u" in argString:
        retList.append(username)
    if "p" in argString:
        retList.append(password)
    if "t" in argString:
        retList.append(tack)
    if "b" in argString:
        retList.append(tackBreakSigs)
    if "v" in argString:
        retList.append(verifierDB)
    if "reqcert" in flagsList:
        retList.append(reqCert)

    return retList


def clientCmd(argv):
    (address, privateKey, certChain, username, password) = \
        handleArgs(argv, "kcup")
        
    if (certChain and not privateKey) or (not certChain and privateKey):
        raise SyntaxError("Must specify CERT and KEY together")
    if (username and not password) or (not username and password):
        raise SyntaxError("Must specify USER with PASS")
    if certChain and username:
        raise SyntaxError("Can use SRP or client cert for auth, not both")

    #Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(address)
    connection = TLSConnection(sock)
    
    try:
        start = time.clock()
        if username and password:
            connection.handshakeClientSRP(username, password, reqTack=True)
        else:
            connection.handshakeClientCert(certChain, privateKey,reqTack=True)
        stop = time.clock()        
        print "Handshake success"        
    except TLSLocalAlert, a:
        if a.description == AlertDescription.user_canceled:
            print str(a)
        else:
            raise
        sys.exit(-1)
    except TLSRemoteAlert, a:
        if a.description == AlertDescription.unknown_psk_identity:
            if username:
                print "Unknown username"
            else:
                raise
        elif a.description == AlertDescription.bad_record_mac:
            if username:
                print "Bad username or password"
            else:
                raise
        elif a.description == AlertDescription.handshake_failure:
            print "Unable to negotiate mutually acceptable parameters"
        else:
            raise
        sys.exit(-1)

    print "  Handshake time: %.4f seconds" % (stop - start)
    print "  Version: %s" % connection.getVersionName()
    print("  Cipher: %s %s" % (connection.getCipherName(), 
        connection.getCipherImplementation()))
    if connection.session.srpUsername:
        print("  Client SRP username: %s" % connection.session.srpUsername)
    if connection.session.clientCertChain:
        print("  Client X.509 SHA1 fingerprint: %s" % 
            connection.session.clientCertChain.getFingerprint())
    if connection.session.serverCertChain:
        print("  Server X.509 SHA1 fingerprint: %s" % 
            connection.session.serverCertChain.getFingerprint())
    if connection.session.tack or connection.session.tackBreakSigs:
        print("  TACK:")
        print(writeTextTACKStructures(connection.session.tack, 
                                  connection.session.tackBreakSigs))
    connection.close()


def serverCmd(argv):
    (address, privateKey, certChain, tack, tackBreakSigs, 
        verifierDB, reqCert) = handleArgs(argv, "kctbv", ["reqcert"])

    if (certChain and not privateKey) or (not certChain and privateKey):
        raise SyntaxError("Must specify CERT and KEY together")
    if tack and not certChain:
        raise SyntaxError("Must specify CERT with TACK")
    
    if certChain and privateKey:
        print("Using certificate and private key...")
    if verifierDB:
        print("Using verifier DB...")
    if tack:
        print("Using TACK...")

    #Create handler function - performs handshake, then echos
    def handler(sock):
        try:
            connection = TLSConnection(sock)
            connection.handshakeServer(verifierDB=verifierDB,\
                                       certChain=certChain, 
                                       privateKey=privateKey,
                                       reqCert=reqCert, 
                                       tack=tack,
                                       tackBreakSigs=tackBreakSigs)
            print "Handshake success"
            print "  Version: %s" % connection.getVersionName()
            print "  Cipher: %s %s" % (connection.getCipherName(), 
                            connection.getCipherImplementation())
            if connection.session.srpUsername:
                print("  Client SRP username: %s" % 
                        connection.session.srpUsername)
            if connection.session.clientCertChain:
                print("  Client X.509 SHA1 fingerprint: %s" % 
                        connection.session.clientCertChain.getFingerprint())
            if connection.session.serverCertChain:
                print("  Server X.509 SHA1 fingerprint: %s" % 
                        connection.session.serverCertChain.getFingerprint())
            if connection.session.tack or connection.session.tackBreakSigs:
                print("  TACK:")
                print(writeTextTACKStructures(connection.session.tack, 
                                          connection.session.tackBreakSigs,
                                          True))
            s = ""
            while 1:
                newS = connection.read()
                if not newS:
                    break
                s += newS
                if s[-1]=='\n':
                    connection.write(s)
                    s = ""
        except TLSLocalAlert, a:
            if a.description == AlertDescription.unknown_psk_identity:
                print "Unknown SRP username"
            elif a.description == AlertDescription.bad_record_mac:
                if verifierDB:
                    print "Bad SRP password for:", connection.allegedSrpUsername
                else:
                    raise
            elif a.description == AlertDescription.handshake_failure:
                print "Unable to negotiate mutually acceptable parameters"
            else:
                raise
        except TLSRemoteAlert, a:
            if a.description == AlertDescription.user_canceled:
                print "Handshake cancelled"
            elif a.description == AlertDescription.handshake_failure:
                print "Unable to negotiate mutually acceptable parameters"
            elif a.description == AlertDescription.close_notify:
                pass
            else:
                raise

    #Run multi-threaded server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(address)
    sock.listen(5)
    while 1:
        (newsock, cliAddress) = sock.accept()
        thread.start_new_thread(handler, (newsock,))



if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "client"[:len(sys.argv[1])]:
        clientCmd(sys.argv[2:])
    elif sys.argv[1] == "server"[:len(sys.argv[1])]:
        serverCmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])

