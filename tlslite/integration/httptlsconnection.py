# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""TLS Lite + httplib."""

import socket
import httplib
from tlslite.tlsconnection import TLSConnection
from tlslite.integration.clienthelper import ClientHelper


class HTTPTLSConnection(httplib.HTTPConnection, ClientHelper):
    """This class extends L{httplib.HTTPConnection} to support TLS."""

    def __init__(self, host, port=None, strict=None, 
                timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                source_address=None,
                username=None, password=None,
                certChain=None, privateKey=None,
                x509Fingerprint=None,
                tackID=None,
                hardTack=None,
                settings = None):
        """Create a new HTTPTLSConnection.

        For client authentication, use one of these argument
        combinations:
         - username, password (SRP)
         - certChain, privateKey (certificate)

        For server authentication, you can either rely on the
        implicit mutual authentication performed by SRP
        or you can do certificate-based server
        authentication with one of these argument combinations:
         - x509Fingerprint

        Certificate-based server authentication is compatible with
        SRP or certificate-based client authentication.

        The constructor does not perform the TLS handshake itself, but
        simply stores these arguments for later.  The handshake is
        performed only when this class needs to connect with the
        server.  Thus you should be prepared to handle TLS-specific
        exceptions when calling methods inherited from
        L{httplib.HTTPConnection} such as request(), connect(), and
        send().  See the client handshake functions in
        L{tlslite.TLSConnection.TLSConnection} for details on which
        exceptions might be raised.

        @type host: str
        @param host: Server to connect to.

        @type port: int
        @param port: Port to connect to.

        @type username: str
        @param username: SRP username.  Requires the
        'password' argument.

        @type password: str
        @param password: SRP password for mutual authentication.
        Requires the 'username' argument.

        @type certChain: L{tlslite.x509certchain.X509CertChain} or
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
        if source_address:
            httplib.HTTPConnection.__init__(self, host, port, strict,
                                            timeout, source_address)
        if not source_address:
            httplib.HTTPConnection.__init__(self, host, port, strict,
                                            timeout)
            
        ClientHelper.__init__(self,
                 username, password, 
                 certChain, privateKey,
                 x509Fingerprint,
                 tackID,
                 hardTack,
                 settings)

    def connect(self):
         httplib.HTTPConnection.connect(self)
         self.sock = TLSConnection(self.sock)
         ClientHelper._handshake(self, self.sock)