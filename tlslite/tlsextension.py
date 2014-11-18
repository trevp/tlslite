# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

""" Helper package for handling TLS extensions encountered in ClientHello
and ServerHello messages.
"""
from __future__ import generators
from .utils.codec import Writer, Parser


class TLSExtension(object):
    """
    This class handles the generic information about TLS extensions used by
    both sides of connection in Client Hello and Server Hello messages.
    See U{RFC 4366<https://tools.ietf.org/html/rfc4366>} for more info.

    It is used as a base class for specific users and as a way to store
    extensions that are not implemented in library.

    @type ext_type: int
    @ivar ext_type: a 2^16-1 limited integer specifying the type of the
        extension that it contains, e.g. 0 indicates server name extension

    @type ext_data: bytearray
    @ivar ext_data: a byte array containing the value of the extension as
        to be written on the wire
    """

    def __init__(self):
        """
        Creates a generic TLS extension that can be used either for
        client hello or server hello message parsing or creation.

        You'll need to use L{create} or L{parse} methods to create an extension
        that is actually usable.
        """
        self.ext_type = None
        self.ext_data = bytearray(0)

    def create(self, type, data):
        """
        Initializes a generic TLS extension that can later be used in
        client hello or server hello messages

        @type  type: int
        @param type: type of the extension encoded as an integer between M{0}
            and M{2^16-1}
        @type  data: bytearray
        @param data: raw data representing extension on the wire
        @rtype: L{TLSExtension}
        """
        self.ext_type = type
        self.ext_data = data
        return self

    def write(self):
        """ Returns encoded extension, as encoded on the wire

        @rtype: bytearray
        @return: An array of bytes formatted as is supposed to be written on
           the wire, including the extension_type, length and the extension
           data

        @raise AssertionError: when the object was not initialized
        """

        assert self.ext_type is not None

        w = Writer()
        w.add(self.ext_type, 2)
        w.add(len(self.ext_data), 2)
        w.addFixSeq(self.ext_data, 1)
        return w.bytes

    def parse(self, p):
        """ Parses extension from the wire format

        @type p: L{tlslite.util.codec.Parser}
        @param p:  data to be parsed

        @raise SyntaxError: when the size of the passed element doesn't match
        the internal representation

        @rtype: L{TLSExtension}
        """

        self.ext_type = p.get(2)
        ext_length = p.get(2)
        self.ext_data = p.getFixBytes(ext_length)
        if len(self.ext_data) != ext_length:
            raise SyntaxError()
        return self
