# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Import this module for easy access to TLS Lite objects.

The TLS Lite API consists of classes, functions, and variables spread
throughout this package.  Instead of importing them individually with::

    from tlslite.TLSConnection import TLSConnection
    from tlslite.HandshakeSettings import HandshakeSettings
    from tlslite.errors import *
    .
    .

It's easier to do::

    from tlslite.api import *

This imports all the important objects (TLSConnection, Checker,
HandshakeSettings, etc.) into the global namespace.  In particular, it
imports::

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
    from integration.POP3_TLS import POP3_TLS
    from integration.IMAP4_TLS import IMAP4_TLS
    from integration.SMTP_TLS import SMTP_TLS
    from integration.XMLRPCTransport import XMLRPCTransport
    from integration.TLSSocketServerMixIn import TLSSocketServerMixIn
    from integration.TLSAsyncDispatcherMixIn import TLSAsyncDispatcherMixIn
    from utils.cryptomath import m2cryptoLoaded,
                                 gmpyLoaded, pycryptoLoaded, prngName
    from utils.keyfactory import generateRSAKey, parsePEMKey
                                 parseAsPublicKey, parsePrivateKey
"""

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
