#!/usr/bin/env python

# Authors:
#   Trevor Perrin
#   Martin von Loewis - python 3 port
#   Fiach Antaw - PskDB implementation
#
# See the LICENSE file for legal information regarding use of this file.

from __future__ import print_function
import sys
import os
import socket
import math
import binascii

if __name__ != "__main__":
    raise "This must be run as a command, not used as a module!"


from tlslite import *
from tlslite import __version__

if len(sys.argv) == 1 or (len(sys.argv)==2 and sys.argv[1].lower().endswith("help")):
    print("")
    print("Version: %s" % __version__)
    print("")
    print("RNG: %s" % prngName)
    print("")
    print("Modules:")
    if m2cryptoLoaded:
        print("  M2Crypto    : Loaded")
    else:
        print("  M2Crypto    : Not Loaded")
    if pycryptoLoaded:
        print("  pycrypto    : Loaded")
    else:
        print("  pycrypto    : Not Loaded")
    if gmpyLoaded:
        print("  GMPY        : Loaded")
    else:
        print("  GMPY        : Not Loaded")
    print("")
    print("Commands:")
    print("")
    print("  createpsk       <db>")
    print("")
    print("  add    <db> <identity> <key>")
    print("  del    <db> <identity>")
    print("  list   <db>")
    print("")
    print("Keys must be provided as hex-encoded strings")
    sys.exit()

cmd = sys.argv[1].lower()

class Args:
    def __init__(self, argv):
        self.argv = argv
    def get(self, index):
        if len(self.argv)<=index:
            raise SyntaxError("Not enough arguments")
        return self.argv[index]
    def getLast(self, index):
        if len(self.argv)>index+1:
            raise SyntaxError("Too many arguments")
        return self.get(index)

args = Args(sys.argv)

def reformatDocString(s):
    lines = s.splitlines()
    newLines = []
    for line in lines:
        newLines.append("  " + line.strip())
    return "\n".join(newLines)

try:
    if cmd == "help":
        command = args.getLast(2).lower()
        if command == "valid":
            print("")
        else:
            print("Bad command: '%s'" % command)

    elif cmd == "createpsk":
        dbName = args.get(2)

        db = PskDB(dbName)
        db.create()

    elif cmd == "add":
        dbName = args.get(2)
        identity = args.get(3)
        key = binascii.unhexlify(args.get(4))

        db = PskDB(dbName)
        db.open()
        if identity in db:
            print("PSK Identity already in database!")
            sys.exit()
        db[identity] = key

    elif cmd == "del":
        dbName = args.get(2)
        identity = args.getLast(3)
        db = PskDB(dbName)
        db.open()
        del(db[identity])

    elif cmd == "list":
        dbName = args.get(2)
        db = PskDB(dbName)
        db.open()

        print("PSK Database")
        for identity in db.keys():
            key = db[identity]
            print(identity, binascii.hexlify(key))
    else:
        print("Bad command: '%s'" % cmd)
except:
    raise
