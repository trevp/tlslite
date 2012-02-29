# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""TLS Lite + xmlrpclib."""

import xmlrpclib
import httplib
from tlslite.integration.httptlsconnection import HTTPTLSConnection
from tlslite.integration.clienthelper import ClientHelper


class XMLRPCTransport(xmlrpclib.Transport, ClientHelper):
    """Handles an HTTPS transaction to an XML-RPC server."""

    # Pre python 2.7, the make_connection returns a HTTP class
    transport = xmlrpclib.Transport()
    conn_class_is_http = not hasattr(transport, '_connection')
    del(transport)

    def __init__(self, use_datetime=0,
                 username=None, password=None,
                 certChain=None, privateKey=None,
                 x509Fingerprint=None,
                 tackID=None,
                 hardTack=None,                 
                 settings=None):
        """Create a new XMLRPCTransport.

        An instance of this class can be passed to L{xmlrpclib.ServerProxy}
        to use TLS with XML-RPC calls::

            from tlslite import XMLRPCTransport
            from xmlrpclib import ServerProxy

            transport = XMLRPCTransport(user="alice", password="abra123")
            server = ServerProxy("https://localhost", transport)

        For client authentication, use one of these argument
        combinations:
         - username, password (SRP)
         - certChain, privateKey (certificate)

        For server authentication, you can either rely on the
        implicit mutual authentication performed by SRP or
        you can do certificate-based server
        authentication with one of these argument combinations:
         - x509Fingerprint

        Certificate-based server authentication is compatible with
        SRP or certificate-based client authentication.

        The constructor does not perform the TLS handshake itself, but
        simply stores these arguments for later.  The handshake is
        performed only when this class needs to connect with the
        server.  Thus you should be prepared to handle TLS-specific
        exceptions when calling methods of L{xmlrpclib.ServerProxy}.  See the
        client handshake functions in
        L{tlslite.TLSConnection.TLSConnection} for details on which
        exceptions might be raised.

        @type username: str
        @param username: SRP username.  Requires the
        'password' argument.

        @type password: str
        @param password: SRP password for mutual authentication.
        Requires the 'username' argument.

        @type certChain: L{tlslite.x509certchain.X509CertChain}
        @param certChain: Certificate chain for client authentication.
        Requires the 'privateKey' argument.  Excludes the SRP arguments.

        @type privateKey: L{tlslite.utils.rsakey.RSAKey}
        @param privateKey: Private key for client authentication.
        Requires the 'certChain' argument.  Excludes the SRP arguments.

        @type x509Fingerprint: str
        @param x509Fingerprint: Hex-encoded X.509 fingerprint for
        server authentication.

        @type tackID: str
        @param tackID: TACK ID for server authentication.

        @type hardTack: bool
        @param hardTack: Whether to raise TackBreakSigError on TACK Break.

        @type settings: L{tlslite.handshakesettings.HandshakeSettings}
        @param settings: Various settings which can be used to control
        the ciphersuites, certificate types, and SSL/TLS versions
        offered by the client.
        """

        # self._connection is new in pythion 2.7, since we're using it here,
        # we'll add this ourselves too, just in case we've pre-2.7
        self._connection = (None, None)
        xmlrpclib.Transport.__init__(self, use_datetime)
        ClientHelper.__init__(self,
                 username, password, 
                 certChain, privateKey,
                 x509Fingerprint,
                 tackID,
                 hardTack,
                 settings)

    def make_connection(self, host):
        # return an existing connection if possible.  This allows
        # HTTP/1.1 keep-alive.
        if self._connection and host == self._connection[0]:
            http = self._connection[1]
        else:
            # create a HTTPS connection object from a host descriptor
            chost, extra_headers, x509 = self.get_host_info(host)

            http = HTTPTLSConnection(chost, None,
                                     self.username, self.password,
                                     self.certChain, self.privateKey,
                                     self.checker.x509Fingerprint,
                                     self.checker.tackID,
                                     self.checker.hardTack,
                                     self.settings)
            # store the host argument along with the connection object
            self._connection = host, http
        if not self.conn_class_is_http:
            return http
        http2 = httplib.HTTP()
        http2._setup(http)
        return http2
