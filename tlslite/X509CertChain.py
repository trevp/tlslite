"""Class representing an X.509 certificate chain."""

from utils import cryptomath

class X509CertChain:
    """This class represents a chain of X.509 certificates.

    @type x509List: list
    @ivar x509List: A list of L{tlslite.X509.X509} instances,
    starting with the end-entity certificate and with every
    subsequent certificate certifying the previous.
    """

    def __init__(self, x509List=None):
        """Create a new X509CertChain.

        @type x509List: list
        @param x509List: A list of L{tlslite.X509.X509} instances,
        starting with the end-entity certificate and with every
        subsequent certificate certifying the previous.
        """
        if x509List:
            self.x509List = x509List
        else:
            self.x509List = []

    def getNumCerts(self):
        """Get the number of certificates in this chain.

        @rtype: int
        """
        return len(self.x509List)

    def getEndEntityPublicKey(self):
        """Get the public key from the end-entity certificate.

        @rtype: L{tlslite.utils.RSAKey.RSAKey}
        """
        if self.getNumCerts() == 0:
            raise AssertionError()
        return self.x509List[0].publicKey

    def getFingerprint(self):
        """Get the hex-encoded fingerprint of the end-entity certificate.

        @rtype: str
        @return: A hex-encoded fingerprint.
        """
        if self.getNumCerts() == 0:
            raise AssertionError()
        return self.x509List[0].getFingerprint()
