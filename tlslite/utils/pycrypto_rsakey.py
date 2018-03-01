# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""PyCrypto RSA implementation."""

from __future__ import print_function
import sys

from .cryptomath import *

from .rsakey import *
from .python_rsakey import Python_RSAKey
from .compat import compatLong

if pycryptoLoaded:

    from Crypto.PublicKey import RSA

    class PyCrypto_RSAKey(RSAKey):
        def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0):
            if not d:
                self.rsa = RSA.construct((compatLong(n), compatLong(e)))
            else:
                self.rsa = RSA.construct((compatLong(n), compatLong(e),
                                          compatLong(d), compatLong(p),
                                          compatLong(q)))

        def __getattr__(self, name):
            return getattr(self.rsa, name)

        def hasPrivateKey(self):
            return self.rsa.has_private()

        def _rawPrivateKeyOp(self, m):
            try:
                return self.rsa.decrypt((compatLong(m),))
            except ValueError as e:
                print("rsa: {0!r}".format(self.rsa), file=sys.stderr)
                values = []
                for name in ["n", "e", "d", "p", "q", "dP", "dQ", "qInv"]:
                    values.append("{0}: {1}".format(name,
                                                    getattr(self, name, None)))
                print(", ".join(values), file=sys.stderr)
                print("m: {0}".format(m), file=sys.stderr)
                raise


        def _rawPublicKeyOp(self, c):
            try:
                return self.rsa.encrypt(compatLong(c), None)[0]
            except ValueError as e:
                print("rsa: {0!r}".format(self.rsa), file=sys.stderr)
                values = []
                for name in ["n", "e", "d", "p", "q", "dP", "dQ", "qInv"]:
                    values.append("{0}: {1}".format(name,
                                                    getattr(self, name, None)))
                print(", ".join(values), file=sys.stderr)
                print("c: {0}".format(c), file=sys.stderr)
                raise

        def generate(bits):
            key = PyCrypto_RSAKey()
            def f(numBytes):
                return bytes(getRandomBytes(numBytes))
            key.rsa = RSA.generate(bits, f)
            return key
        generate = staticmethod(generate)
