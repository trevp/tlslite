# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Class representing a TLS session."""

from .utils.compat import *
from .mathtls import *
from .constants import *

class Session:
    """
    This class represents a TLS session.

    TLS distinguishes between connections and sessions.  A new
    handshake creates both a connection and a session.  Data is
    transmitted over the connection.

    The session contains a more permanent record of the handshake.  The
    session can be inspected to determine handshake results.  The
    session can also be used to create a new connection through
    "session resumption". If the client and server both support this,
    they can create a new connection based on an old session without
    the overhead of a full handshake.

    The session for a L{tlslite.TLSConnection.TLSConnection} can be
    retrieved from the connection's 'session' attribute.

    @type srpUsername: str
    @ivar srpUsername: The client's SRP username (or None).

    @type clientCertChain: L{tlslite.x509certchain.X509CertChain}
    @ivar clientCertChain: The client's certificate chain (or None).

    @type serverCertChain: L{tlslite.x509certchain.X509CertChain}
    @ivar serverCertChain: The server's certificate chain (or None).
    """

    def __init__(self):
        self.masterSecret = createByteArraySequence([])
        self.sessionID = createByteArraySequence([])
        self.cipherSuite = 0
        self.srpUsername = None
        self.clientCertChain = None
        self.serverCertChain = None
        self.tackExt = None
        self.resumable = False

    def create(self, masterSecret, sessionID, cipherSuite,
            srpUsername, clientCertChain, serverCertChain, 
            tackExt, resumable=True):
        self.masterSecret = masterSecret
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
        self.srpUsername = srpUsername
        self.clientCertChain = clientCertChain
        self.serverCertChain = serverCertChain
        self.tackExt = tackExt
        self.resumable = resumable

    def _clone(self):
        other = Session()
        other.masterSecret = self.masterSecret
        other.sessionID = self.sessionID
        other.cipherSuite = self.cipherSuite
        other.srpUsername = self.srpUsername
        other.clientCertChain = self.clientCertChain
        other.serverCertChain = self.serverCertChain
        other.tackExt = self.tackExt
        other.resumable = self.resumable
        return other

    def valid(self):
        """If this session can be used for session resumption.

        @rtype: bool
        @return: If this session can be used for session resumption.
        """
        return self.resumable and self.sessionID

    def _setResumable(self, boolean):
        #Only let it be set to True if the sessionID is non-null
        if (not boolean) or (boolean and self.sessionID):
            self.resumable = boolean

    def getTACKID(self):
        if self.tackExt and self.tackExt.tack:
            return self.tackExt.tack.getTACKID()
        else:
            return None
        
    def getBreakSigs(self):
        if self.tackExt and self.tackExt.break_sigs:
            return self.tackExt.break_sigs
        else:
            return None

    def getCipherName(self):
        """Get the name of the cipher used with this connection.

        @rtype: str
        @return: The name of the cipher used with this connection.
        Either 'aes128', 'aes256', 'rc4', or '3des'.
        """
        if self.cipherSuite in CipherSuite.aes128Suites:
            return "aes128"
        elif self.cipherSuite in CipherSuite.aes256Suites:
            return "aes256"
        elif self.cipherSuite in CipherSuite.rc4Suites:
            return "rc4"
        elif self.cipherSuite in CipherSuite.tripleDESSuites:
            return "3des"
        else:
            return None
