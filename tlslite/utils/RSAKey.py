# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Abstract class for RSA."""

from .cryptomath import *


class RSAKey:
    """This is an abstract base class for RSA keys.

    Particular implementations of RSA keys, such as
    L{openssl_rsakey.OpenSSL_RSAKey},
    L{python_rsakey.Python_RSAKey}, and
    L{pycrypto_rsakey.PyCrypto_RSAKey},
    inherit from this.

    To create or parse an RSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    L{tlslite.utils.keyfactory}.
    """

    def __init__(self, n=0, e=0):
        """Create a new RSA key.

        If n and e are passed in, the new key will be initialized.

        @type n: int
        @param n: RSA modulus.

        @type e: int
        @param e: RSA public exponent.
        """
        raise NotImplementedError()

    def __len__(self):
        """Return the length of this key in bits.

        @rtype: int
        """
        return numBits(self.n)

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        @rtype: bool
        """
        raise NotImplementedError()

    def hashAndSign(self, bytes):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1-SHA1 signature on the passed-in data.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: The value which will be hashed and signed.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1-SHA1 signature on the passed-in data.
        """
        if not isinstance(bytes, type("")):
            bytes = bytesToString(bytes)
        hashBytes = stringToBytes(sha1(bytes).digest())
        prefixedHashBytes = self._addPKCS1SHA1Prefix(hashBytes)
        sigBytes = self.sign(prefixedHashBytes)
        return sigBytes

    def hashAndVerify(self, sigBytes, bytes):
        """Hash and verify the passed-in bytes with the signature.

        This verifies a PKCS1-SHA1 signature on the passed-in data.

        @type sigBytes: L{bytearray} of unsigned bytes
        @param sigBytes: A PKCS1-SHA1 signature.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: The value which will be hashed and verified.

        @rtype: bool
        @return: Whether the signature matches the passed-in data.
        """
        if not isinstance(bytes, type("")):
            bytes = bytesToString(bytes)
        hashBytes = stringToBytes(sha1(bytes).digest())
        prefixedHashBytes = self._addPKCS1SHA1Prefix(hashBytes)
        return self.verify(sigBytes, prefixedHashBytes)

    def sign(self, bytes):
        """Sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 signature on the passed-in data.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be signed.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1 signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise AssertionError()
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        m = bytesToNumber(paddedBytes)
        if m >= self.n:
            raise ValueError()
        c = self._rawPrivateKeyOp(m)
        sigBytes = numberToBytes(c)
        return sigBytes

    def verify(self, sigBytes, bytes):
        """Verify the passed-in bytes with the signature.

        This verifies a PKCS1 signature on the passed-in data.

        @type sigBytes: L{bytearray} of unsigned bytes
        @param sigBytes: A PKCS1 signature.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be verified.

        @rtype: bool
        @return: Whether the signature matches the passed-in data.
        """
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        c = bytesToNumber(sigBytes)
        if c >= self.n:
            return False
        m = self._rawPublicKeyOp(c)
        checkBytes = numberToBytes(m)
        return checkBytes == paddedBytes

    def encrypt(self, bytes):
        """Encrypt the passed-in bytes.

        This performs PKCS1 encryption of the passed-in data.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be encrypted.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1 encryption of the passed-in data.
        """
        paddedBytes = self._addPKCS1Padding(bytes, 2)
        m = bytesToNumber(paddedBytes)
        if m >= self.n:
            raise ValueError()
        c = self._rawPublicKeyOp(m)
        encBytes = numberToBytes(c)
        return encBytes

    def decrypt(self, encBytes):
        """Decrypt the passed-in bytes.

        This requires the key to have a private component.  It performs
        PKCS1 decryption of the passed-in data.

        @type encBytes: L{bytearray} of unsigned bytes
        @param encBytes: The value which will be decrypted.

        @rtype: L{bytearray} of unsigned bytes or None.
        @return: A PKCS1 decryption of the passed-in data or None if
        the data is not properly formatted.
        """
        if not self.hasPrivateKey():
            raise AssertionError()
        c = bytesToNumber(encBytes)
        if c >= self.n:
            return None
        m = self._rawPrivateKeyOp(c)
        decBytes = numberToBytes(m)
        if (len(decBytes) != numBytes(self.n)-1): #Check first byte
            return None
        if decBytes[0] != 2: #Check second byte
            return None
        for x in range(len(decBytes)-1): #Scan through for zero separator
            if decBytes[x]== 0:
                break
        else:
            return None
        return decBytes[x+1:] #Return everything after the separator

    def _rawPrivateKeyOp(self, m):
        raise NotImplementedError()

    def _rawPublicKeyOp(self, c):
        raise NotImplementedError()

    def acceptsPassword(self):
        """Return True if the write() method accepts a password for use
        in encrypting the private key.

        @rtype: bool
        """
        raise NotImplementedError()

    def write(self, password=None):
        """Return a string containing the key.

        @rtype: str
        @return: A string describing the key, in whichever format (PEM)
        is native to the implementation.
        """
        raise NotImplementedError()

    def generate(bits):
        """Generate a new key with the specified bit length.

        @rtype: L{tlslite.utils.RSAKey.RSAKey}
        """
        raise NotImplementedError()
    generate = staticmethod(generate)


    # **************************************************************************
    # Helper Functions for RSA Keys
    # **************************************************************************

    def _addPKCS1SHA1Prefix(self, bytes, withNULL=False):
        # There is a long history of confusion over whether the SHA1 
        # algorithmIdentifier should be encoded with a NULL parameter or 
        # with the parameter omitted.  While the original intention was 
        # apparently to omit it, many toolkits went the other way.  TLS 1.2
        # specifies the NULL should be omitted, so maybe the pendulum is 
        # swinging back towards the original intention.  Anyways, verification
        # code should accept both, so the above hashAndVerify() is not
        # yet correct.  However, nothing uses this code yet - an eventual
        # TLS 1.2 implementation will have to fix that.
        if not withNULL:
            prefixBytes = createByteArraySequence(\
            [0x30,0x1f,0x30,0x07,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x04,0x14])            
        else:
            prefixBytes = createByteArraySequence(\
            [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14])            
        prefixedBytes = prefixBytes + bytes
        return prefixedBytes

    def _addPKCS1Padding(self, bytes, blockType):
        padLength = (numBytes(self.n) - (len(bytes)+3))
        if blockType == 1: #Signature padding
            pad = [0xFF] * padLength
        elif blockType == 2: #Encryption padding
            pad = createByteArraySequence([])
            while len(pad) < padLength:
                padBytes = getRandomBytes(padLength * 2)
                pad = [b for b in padBytes if b != 0]
                pad = pad[:padLength]
        else:
            raise AssertionError()

        #NOTE: To be proper, we should add [0,blockType].  However,
        #the zero is lost when the returned padding is converted
        #to a number, so we don't even bother with it.  Also,
        #adding it would cause a misalignment in verify()
        padding = createByteArraySequence([blockType] + pad + [0])
        paddedBytes = padding + bytes
        return paddedBytes
