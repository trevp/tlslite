# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.
"""Pure Python implementation of ChaCha cipher

Implementation that follows RFC 7539 closely.
"""

from __future__ import division
from .compat import compat26Str
import copy
import struct

class ChaCha(object):

    """Pure python implementation of ChaCha cipher"""

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    @staticmethod
    def rotl32(v, c):
        """Rotate left a 32 bit integer v by c bits"""
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a ChaCha quarter round"""
        rotl32 = ChaCha.rotl32
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = x[d] ^ x[a]
        x[d] = rotl32(x[d], 16)

        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = x[b] ^ x[c]
        x[b] = rotl32(x[b], 12)

        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = x[d] ^ x[a]
        x[d] = rotl32(x[d], 8)

        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = x[b] ^ x[c]
        x[b] = rotl32(x[b], 7)

    @staticmethod
    def double_round(x):
        """Perform two rounds of ChaCha cipher"""
        qr = ChaCha.quarter_round
        qr(x, 0, 4, 8, 12)
        qr(x, 1, 5, 9, 13)
        qr(x, 2, 6, 10, 14)
        qr(x, 3, 7, 11, 15)
        qr(x, 0, 5, 10, 15)
        qr(x, 1, 6, 11, 12)
        qr(x, 2, 7, 8, 13)
        qr(x, 3, 4, 9, 14)

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """Generate a state of a single block"""
        state = []
        state.extend(ChaCha.constants)
        state.extend(key)
        state.append(counter)
        state.extend(nonce)

        working_state = state[:]
        dbl_round = ChaCha.double_round
        for _ in range(0, rounds // 2):
            dbl_round(working_state)

        return [(st + wrkSt) & 0xffffffff for st, wrkSt
                in zip(state, working_state)]

    @staticmethod
    def word_to_bytearray(state):
        """Convert state to little endian bytestream"""
        return bytearray(b"".join(struct.pack('<L', i) for i in state))

    @staticmethod
    def _bytearray_to_words(data):
        """Convert a bytearray to array of word sized ints"""
        ret = []
        for i in range(0, len(data)//4):
            ret.extend(struct.unpack('<L',
                                     compat26Str(data[i*4:(i+1)*4])))
        return ret

    def __init__(self, key, nonce, counter=0, rounds=20):
        """Set the initial state for the ChaCha cipher"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")
        self.key = []
        self.nonce = []
        self.counter = counter
        self.rounds = rounds

        # convert bytearray key and nonce to little endian 32 bit unsigned ints
        self.key = ChaCha._bytearray_to_words(key)
        self.nonce = ChaCha._bytearray_to_words(nonce)

    def encrypt(self, plaintext):
        """Encrypt the data"""
        encrypted_message = bytearray()
        if len(plaintext) % 64 != 0:
            extra = 1
        else:
            extra = 0
        for i in range(0, len(plaintext) // 64 + extra):
            key_stream = ChaCha.chacha_block(self.key,
                                             self.counter + i,
                                             self.nonce,
                                             self.rounds)
            key_stream = ChaCha.word_to_bytearray(key_stream)
            block = plaintext[i*64:(i+1)*64]
            encrypted_message += bytearray(x ^ y for x, y
                                           in zip(key_stream, block))

        return encrypted_message

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        return self.encrypt(ciphertext)
