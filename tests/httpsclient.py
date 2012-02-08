#!/usr/bin/env python

from tlslite import HTTPTLSConnection, tackpyLoaded

if tackpyLoaded:
    tackID = "BHNHV.8Q3RM.Q74EA.4X8F1.FMQEQ"
else:
    tackID = None

# GOOD TACK ID
h = HTTPTLSConnection("localhost", 4443, tackID=tackID, hardTack=True)

h.request("GET", "/index.html")
r = h.getresponse()
print r.read()

# BAD TACK ID
#h = HTTPTLSConnection("localhost", 4443, tackID="XXXXX.EQ61B.F34EL.9KKLN.3WEW5", hardTack=False)
#h.request("GET", "/index.html")

# BROKEN TACK ID
#h = HTTPTLSConnection("localhost", 4443, tackID="BHMXG.NIUGC.4D9EG.BRLP1.DTQBE", hardTack=True)
#h.request("GET", "/index.html")
