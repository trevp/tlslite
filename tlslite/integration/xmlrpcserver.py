# Author: Kees Bos
# See the LICENSE file for legal information regarding use of this file.

"""xmlrpcserver.py - simple XML RPC server supporting TLS"""

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from tlssocketservermixin import TLSSocketServerMixIn


class TLSXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    """XMLRPCRequestHandler using TLS"""
    
    # Redefine the setup method (see SocketServer.StreamRequestHandler)
    def setup(self):
        self.connection = self.request
        if getattr(self, 'timeout', None) is not None:
            # Python 2.7
            self.connection.settimeout(self.timeout)
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb', self.wbufsize)
        
    def do_POST(self):
        """Handles the HTTPS POST request."""
        SimpleXMLRPCRequestHandler.do_POST(self)
        try:
            # shut down the connection
            self.connection.shutdown()
        except:
            pass


class TLSXMLRPCServer(TLSSocketServerMixIn,
                      SimpleXMLRPCServer):
    """Simple XML-RPC server using TLS""" 

    def __init__(self, addr, *args, **kwargs):
        if not args and not 'requestHandler' in kwargs:
            kwargs['requestHandler'] = TLSXMLRPCRequestHandler
        SimpleXMLRPCServer.__init__(self, addr, *args, **kwargs)


class MultiPathTLSXMLRPCServer(TLSXMLRPCServer):
    """Multipath XML-RPC Server using TLS"""

    def __init__(self, addr, *args, **kwargs):
        TLSXMLRPCServer.__init__(addr, *args, **kwargs)
        self.dispatchers = {}
        self.allow_none = allow_none
        self.encoding = encoding
