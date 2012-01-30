# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Miscellaneous functions to mask Python version differences."""

import sys
import os
import math

# Requires Python 2.5
from hashlib import md5
from hashlib import sha1 

# Requires Python 2.6, will need to be changed for Python 3
def createByteArraySequence(seq):
    return bytearray(seq)
def createByteArrayZeros(howMany):
    return bytearray(howMany)

def bytesToString(bytes):
    return str(bytes)
def stringToBytes(s):
    bytes = bytearray(s)
    return bytes

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

