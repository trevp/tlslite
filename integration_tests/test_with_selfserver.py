# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import os
import socket
import threading
from tlslite.api import X509, X509CertChain, TLSConnection, parsePEMKey,\
        HandshakeSettings, VerifierDB
import tlslite.constants as constants

class SockPairTest(unittest.TestCase):
    def serverEcho(self, connection):
        count = 0
        while True:
            data = connection.read()
            count += len(data)
            if len(data) == 0:
                break
            connection.write(data)
            if count == 1111:
                break

    def canary(self, conn):
        b1 = os.urandom(1)
        b10 = os.urandom(10)
        b100 = os.urandom(100)
        b1000 = os.urandom(1000)
        conn.write(b1)
        conn.write(b10)
        conn.write(b100)
        conn.write(b1000)
        self.assertEqual(conn.read(min=1, max=1), b1)
        self.assertEqual(conn.read(min=10, max=10), b10)
        self.assertEqual(conn.read(min=100, max=100), b100)
        self.assertEqual(conn.read(min=1000, max=1000), b1000)

class TestAnonymous(SockPairTest):
    def start_server(self, socket):
        connection = TLSConnection(socket)
        connection.handshakeServer(anon=True)

        self.serverEcho(connection)

        connection.close()

    def setUp(self):
        self.sockClient, sockServer = socket.socketpair()
        t = threading.Thread(\
                target=TestAnonymous.start_server, args=(self, sockServer))
        t.daemon = True
        t.start()

    def test_client(self):

        connection = TLSConnection(self.sockClient)
        connection.handshakeClientAnonymous()
        self.canary(connection)
        connection.close()

class TestX509(SockPairTest):
    certDir = "tests"

    @classmethod
    def setUpClass(cls):
        certFile = open(os.path.join(cls.certDir, "serverX509Cert.pem"))
        x509Cert = X509().parse(certFile.read())
        certFile.close()
        cls._x509Chain = X509CertChain([x509Cert])
        keyFile = open(os.path.join(cls.certDir, "serverX509Key.pem"))
        cls._x509Key = parsePEMKey(keyFile.read())
        keyFile.close()

    def startServer(self, serverMethod):

        self.sockClient, sockServer = socket.socketpair()
        t = threading.Thread(\
                target=serverMethod, args=(self, sockServer))
        t.daemon = True
        t.start()

    #
    # Default test case
    #

    def server_default(self, socket):
        connection = TLSConnection(socket)
        connection.handshakeServer(\
                certChain=self._x509Chain,
                privateKey=self._x509Key)
        self.serverName = connection.session.serverName
        self.serverEcho(connection)
        connection.close()

    def test_default(self):
        self.startServer(TestX509.server_default)

        connection = TLSConnection(self.sockClient)
        serverName = "localhost"
        connection.handshakeClientCert(serverName=serverName)


        self.canary(connection)

        # asserts from threads are not passed to unittest so we have to
        # copy it over, canary() works as a barrier here
        self.assertEqual(self.serverName, serverName)
        self.assertIsInstance(connection.session.serverCertChain, X509CertChain)
        self.assertEqual(connection.session.serverName, serverName)
        connection.close()

    #
    # SSLv3 test case
    #

    def server_sslv3(self, socket):
        connection = TLSConnection(socket)
        settings = HandshakeSettings()
        settings.minVersion = (3,0)
        settings.maxVersion = (3,0)
        connection.handshakeServer(
                certChain=self._x509Chain,
                privateKey=self._x509Key,
                settings=settings)
        self.serverEcho(connection)
        connection.close()

    def test_sslv3(self):
        self.startServer(TestX509.server_sslv3)

        connection = TLSConnection(self.sockClient)
        settings = HandshakeSettings()
        settings.minVersion = (3,0)
        settings.maxVersion = (3,0)
        connection.handshakeClientCert(settings=settings)

        self.canary(connection)

        self.assertIsInstance(connection.session.serverCertChain, X509CertChain)
        connection.close()

    #
    # RC4-MD5 test case
    #

    def server_rc4_md5(self, socket):
        connection = TLSConnection(socket)
        settings = HandshakeSettings()
        settings.macNames = ["sha", "md5"]
        settings.cipherNames = ["rc4"]
        connection.handshakeServer(
                certChain=self._x509Chain,
                privateKey=self._x509Key,
                settings=settings)
        self.serverEcho(connection)
        connection.close()

    def test_rc4_md5(self):
        self.startServer(TestX509.server_rc4_md5)

        connection = TLSConnection(self.sockClient)
        settings = HandshakeSettings()
        settings.macNames = ["md5"]
        connection.handshakeClientCert(settings=settings)

        self.canary(connection)

        self.assertIsInstance(connection.session.serverCertChain, X509CertChain)
        self.assertEqual(connection.session.cipherSuite,
                constants.CipherSuite.TLS_RSA_WITH_RC4_128_MD5)
        connection.close()

    #
    # TODO: tackpy
    #

    #
    # good SRP
    #

    def server_srp(self, socket):
        verifierDB = VerifierDB()
        verifierDB.create()
        entry = VerifierDB.makeVerifier("test", "password", 1536)
        verifierDB["test"] = entry

        connection = TLSConnection(socket)
        connection.handshakeServer(verifierDB=verifierDB)
        self.serverEcho(connection)
        connection.close()

    def test_srp(self):
        self.startServer(TestX509.server_srp)

        connection = TLSConnection(self.sockClient)
        connection.handshakeClientSRP("test", "password")

        self.canary(connection)

        connection.close()
