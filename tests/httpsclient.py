#!/usr/bin/env python

from tlslite import HTTPTLSConnection

h = HTTPTLSConnection("localhost", 4443, 
    tackID="B3ARS.EQ61B.F34EL.9KKLN.3WEW5", hardTack=True)

h.request("GET", "/index.html")
r = h.getresponse()
print r.read()

# BAD TACK ID
#h = HTTPTLSConnection("localhost", 4443, tackID="XXXXX.EQ61B.F34EL.9KKLN.3WEW5")
#h.request("get", "/")


#h = HTTPTLSConnection("localhost", 4443, 
#    tackID="BHMXG.NIUGC.4D9EG.BRLP1.DTQBE", hardTack=True)
#h.request("get", "/")