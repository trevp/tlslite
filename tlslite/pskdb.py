# Author: Fiach Antaw
# See the LICENSE file for legal information regarding use of this file.

"""Class for storing PSK identity/key pairs."""

from .utils.cryptomath import *
from .utils.compat import *
from tlslite import mathtls
from .basedb import BaseDB

class PskDB(BaseDB):
    """This class represent an in-memory or on-disk database of PSK
    identity/key pairs.

    A PskDB can be passed to a client or server handshake to authenticate
    the other party based on one of the key pairs.

    This class is thread-safe.
    """
    def __init__(self, filename=None):
        """Create a new PskDB instance.

        @type filename: str
        @param filename: Filename for an on-disk database, or None for
        an in-memory database.  If the filename already exists, follow
        this with a call to open().  To create a new on-disk database,
        follow this with a call to create().
        """
        BaseDB.__init__(self, filename, "psk")

    def _getItem(self, identity, valueStr):
        return valueStr

    def __setitem__(self, identity, psk):
        """Add a PSK identity/key pair to the database.

        @type identity: str
        @param identity: The PSK identity to associate the key with.
        Must be less than 256 characters in length.  Must not already
        be in the database.

        @type psk: bytes
        @param psk: The pre-shared key to add.
        """
        BaseDB.__setitem__(self, identity, psk)


    def _setItem(self, identity, psk):
        if len(identity)>=256:
            raise ValueError("username too long")
        return psk

    def _checkItem(self, value, identity, psk):
        return value == psk
