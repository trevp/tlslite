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

    from tlslite.api import *

Then use the L{tlslite.TLSConnection.TLSConnection} class with a socket,
or use one of the integration classes in L{tlslite.integration}.

@version: 0.3.8
"""
__version__ = "0.3.8"

__all__ = ["api",
           "BaseDB",
           "Checker",
           "constants",
           "errors",
           "FileObject",
           "HandshakeSettings",
           "mathtls",
           "messages",
           "Session",
           "SessionCache",
           "TLSConnection",
           "TLSRecordLayer",
           "VerifierDB",
           "X509",
           "X509CertChain",
           "integration",
           "utils"]
