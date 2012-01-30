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

from constants import AlertLevel, AlertDescription, Fault
from errors import *
from Checker import Checker
from HandshakeSettings import HandshakeSettings
from Session import Session
from SessionCache import SessionCache
from TLSConnection import TLSConnection
from VerifierDB import VerifierDB
from X509 import X509
from X509CertChain import X509CertChain

from integration.HTTPTLSConnection import HTTPTLSConnection
from integration.TLSSocketServerMixIn import TLSSocketServerMixIn
from integration.TLSAsyncDispatcherMixIn import TLSAsyncDispatcherMixIn
from integration.POP3_TLS import POP3_TLS
from integration.IMAP4_TLS import IMAP4_TLS
from integration.SMTP_TLS import SMTP_TLS
from integration.XMLRPCTransport import XMLRPCTransport

from utils.cryptomath import m2cryptoLoaded, gmpyLoaded, \
                             pycryptoLoaded, prngName
from utils.keyfactory import generateRSAKey, parsePEMKey, \
                             parseAsPublicKey, parsePrivateKey