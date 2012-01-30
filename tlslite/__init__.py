# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""
TLS Lite is a free python library that implements SSL and TLS. TLS Lite
supports RSA and SRP ciphersuites. TLS Lite is pure python, however it can use
other libraries for faster crypto operations. TLS Lite integrates with several
stdlib neworking libraries.

API documentation is available in the 'docs' directory.

If you have questions or feedback, feel free to contact me.

To use, do::

    from tlslite import TLSConnection

Then use the L{tlslite.TLSConnection.TLSConnection} class with a socket.
(Or, use one of the integration classes in L{tlslite.integration}).

@version: 0.3.8a
"""
__version__ = "0.3.8a"

from .constants import AlertLevel, AlertDescription, Fault
from .errors import *
from .checker import Checker
from .handshakesettings import HandshakeSettings
from .session import Session
from .sessioncache import SessionCache
from .tlsconnection import TLSConnection
from .verifierdb import VerifierDB
from .x509 import X509
from .x509certchain import X509CertChain

from .integration.httptlsconnection import HTTPTLSConnection
from .integration.tlssocketservermixin import TLSSocketServerMixIn
from .integration.tlsasyncdispatchermixin import TLSAsyncDispatcherMixIn
from .integration.pop3_tls import POP3_TLS
from .integration.imap4_tls import IMAP4_TLS
from .integration.smtp_tls import SMTP_TLS
from .integration.xmlrpctransport import XMLRPCTransport

from .utils.cryptomath import m2cryptoLoaded, gmpyLoaded, \
                             pycryptoLoaded, prngName
from .utils.keyfactory import generateRSAKey, parsePEMKey, \
                             parseAsPublicKey, parsePrivateKey