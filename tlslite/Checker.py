# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Class for post-handshake certificate checking."""

from X509 import X509
from X509CertChain import X509CertChain
from errors import *


class Checker:
    """This class is passed to a handshake function to check the other
    party's certificate chain.

    If a handshake function completes successfully, but the Checker
    judges the other party's certificate chain to be missing or
    inadequate, a subclass of
    L{tlslite.errors.TLSAuthenticationError} will be raised.

    Currently, the Checker can check an X.509 chain.
    """

    def __init__(self, 
                 x509Fingerprint=None,
                 x509TrustList=None, x509CommonName=None,
                 checkResumedSession=False):
        """Create a new Checker instance.

        You must pass in one of these argument combinations:
         - x509Fingerprint
         - x509TrustList[, x509CommonName] (requires cryptlib_py)

        @type x509Fingerprint: str
        @param x509Fingerprint: A hex-encoded X.509 end-entity
        fingerprint which the other party's end-entity certificate must
        match.  Mutually exclusive with the
        'x509TrustList' arguments.

        @type x509TrustList: list of L{tlslite.X509.X509}
        @param x509TrustList: A list of trusted root certificates.  The
        other party must present a certificate chain which extends to
        one of these root certificates.  The cryptlib_py module must be
        installed.  Mutually exclusive with the
        'x509Fingerprint' arguments.

        @type x509CommonName: str
        @param x509CommonName: The end-entity certificate's 'CN' field
        must match this value.  For a web server, this is typically a
        server name such as 'www.amazon.com'.  Mutually exclusive with
        the 'x509Fingerprint' arguments.  Requires the
        'x509TrustList' argument.

        @type checkResumedSession: bool
        @param checkResumedSession: If resumed sessions should be
        checked.  This defaults to False, on the theory that if the
        session was checked once, we don't need to bother
        re-checking it.
        """

        if x509Fingerprint and x509TrustList:
            raise ValueError()
        if x509CommonName and not x509TrustList:
            raise ValueError()
        if x509TrustList:
            import cryptlib_py #So we raise an error here
        self.x509Fingerprint = x509Fingerprint
        self.x509TrustList = x509TrustList
        self.x509CommonName = x509CommonName
        self.checkResumedSession = checkResumedSession

    def __call__(self, connection):
        """Check a TLSConnection.

        When a Checker is passed to a handshake function, this will
        be called at the end of the function.

        @type connection: L{tlslite.TLSConnection.TLSConnection}
        @param connection: The TLSConnection to examine.

        @raise tlslite.errors.TLSAuthenticationError: If the other
        party's certificate chain is missing or bad.
        """
        if not self.checkResumedSession and connection.resumed:
            return

        if self.x509Fingerprint or self.x509TrustList:
            if connection._client:
                chain = connection.session.serverCertChain
            else:
                chain = connection.session.clientCertChain

            if self.x509Fingerprint or self.x509TrustList:
                if isinstance(chain, X509CertChain):
                    if self.x509Fingerprint:
                        if chain.getFingerprint() != self.x509Fingerprint:
                            raise TLSFingerprintError(\
                                "X.509 fingerprint mismatch: %s, %s" % \
                                (chain.getFingerprint(), self.x509Fingerprint))
                    else: #self.x509TrustList
                        if not chain.validate(self.x509TrustList):
                            raise TLSValidationError("X.509 validation failure")
                        if self.x509CommonName and \
                               (chain.getCommonName() != self.x509CommonName):
                           raise TLSAuthorizationError(\
                               "X.509 Common Name mismatch: %s, %s" % \
                               (chain.getCommonName(), self.x509CommonName))
                elif chain:
                    raise TLSAuthenticationTypeError()
                else:
                    raise TLSNoAuthenticationError()
