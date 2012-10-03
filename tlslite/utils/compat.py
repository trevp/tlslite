# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Miscellaneous functions to mask Python version differences."""

import sys
import os
import math

# Requires Python 2.5
from hashlib import md5
from hashlib import sha1 

def createByteArraySequence(seq):
    return bytearray(seq)
def createByteArrayZeros(howMany):
    return bytearray(howMany)

if sys.version_info < (3,):
    # b_chr creates a byte string of length 1
    # b_ord takes an element of a byte string (which is a length-1 byte string)
    # and returns the ordinal
    b_chr = chr
    b_ord = ord

    # Terminology: "bytes" means the mutable bytearray type; elements are ints
    
    # "str" means the immutable byte string type: str in 2.x and bytes in 3.x
    # elements are length-1 strings in 2.x and ints in 3.x
    
    # True character strings never appear in any cryptographic API
    
    bytesToString = str
    stringToBytes = bytearray
else:
    def b_chr(b):
        return bytes((b,))
    def b_ord(b):
        return b
    bytesToString = bytes
    stringToBytes = bytearray

def numBits(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    return int(math.floor(math.log(n, 2))+1)

import traceback
def formatExceptionTrace(e):
    newStr = "".join(traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback))
    return newStr

try:
    long_ = long
    range_list = range
except NameError:
    # Python 3
    long_ = int
    def range_list(*args):
        return list(range(*args))
