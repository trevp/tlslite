# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

""" Helper package for handling TLS extensions encountered in ClientHello
and ServerHello messages.
"""

from __future__ import generators
from .utils.codec import Writer, Parser
from collections import namedtuple
from .constants import NameType, ExtensionType

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

    @type _extensions: dict
    @cvar _extensions: dictionary with concrete implementations of specific
        TLS extensions, key is the numeric value of the extension ID
    """
    # actual definition at the end of file, after definitions of all classes
    _extensions = {}

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

        ext_type = p.get(2)
        ext_length = p.get(2)

        if ext_type in self._extensions:
            ext = TLSExtension._extensions[ext_type]()
            ext_parser = Parser(p.getFixBytes(ext_length))
            ext = ext.parse(ext_parser)
            return ext

        self.ext_type = ext_type
        self.ext_data = p.getFixBytes(ext_length)
        if len(self.ext_data) != ext_length:
            raise SyntaxError()
        return self

    def __eq__(self, that):
        """ Test if two TLS extensions will result in the same on the wire
        representation.

        Will return False for every object that's not an extension.
        """
        if hasattr(that, 'ext_type') and hasattr(that, 'ext_data'):
            return self.ext_type == that.ext_type and \
                    self.ext_data == that.ext_data
        else:
            return False

class SNIExtension(TLSExtension):
    """
    Class for handling Server Name Indication (server_name) extension from
    RFC 4366.

    Note that while usually the client does advertise just one name, it is
    possible to provide a list of names, each of different type.
    The type is a single byte value (represented by ints), the names are
    opaque byte strings, in case of DNS host names (records of type 0) they
    are UTF-8 encoded domain names (without the ending dot).

    @type host_names: tuple of bytearrays
    @ivar host_names: tuple of hostnames (server name records of type 0)
        advertised in the extension. Note that it may not include all names
        from client hello as the client can advertise other types. Also note
        that while it's not possible to change the returned array in place, it
        is possible to assign a new set of names. IOW, this won't work::

           sni_extension.host_names[0] = bytearray(b'example.com')

        while this will work::

           names = list(sni_extension.host_names)
           names[0] = bytearray(b'example.com')
           sni_extension.host_names = names


    @type server_names: list of L{ServerName}
    @ivar server_names: list of all names advertised in extension.
        L{ServerName} is a namedtuple with two elements, the first
        element (type) defines the type of the name (encoded as int)
        while the other (name) is a bytearray that carries the value.
        Known types are defined in L{tlslite.constants.NameType}.
        The list will be empty if the on the wire extension had and empty
        list while it will be None if the extension was empty.

    @type ext_type: int
    @ivar ext_type: numeric type of SNIExtension, i.e. 0

    @type ext_data: bytearray
    @ivar ext_data: raw representation of the extension
    """

    ServerName = namedtuple('ServerName', 'type name')

    def __init__(self):
        """
        Create an instance of SNIExtension.

        See also: L{create} and L{parse}.
        """
        self.server_names = None

    def create(self, hostname=None, host_names=None, server_names=None):
        """
        Initializes an instance with provided hostname, host names or
        raw server names.

        Any of the parameters may be None, in that case the list inside the
        extension won't be defined, if either host_names or server_names is
        an empty list, then the extension will define a list of lenght 0.

        If multiple parameters are specified at the same time, then the
        resulting list of names will be concatenated in order of hostname,
        host_names and server_names last.

        @type  hostname: bytearray
        @param hostname: raw UTF-8 encoding of the host name

        @type  host_names: list of bytearrays
        @param host_names: list of raw UTF-8 encoded host names

        @type  server_names: list of L{ServerName}
        @param server_names: pairs of type and name

        @rtype: L{SNIExtension}
        """
        if hostname is None and host_names is None and server_names is None:
            self.server_names = None
            return self
        else:
            self.server_names = []

        if hostname:
            self.server_names+=[SNIExtension.ServerName(NameType.host_name,\
                    hostname)]

        if host_names:
            self.server_names+=\
                    [SNIExtension.ServerName(NameType.host_name, x) for x in\
                    host_names]

        if server_names:
            self.server_names+=server_names

        return self

    @property
    def ext_type(self):
        """ Return the type of TLS extension, in this case - 0

        @rtype: int
        """
        return ExtensionType.server_name

    @property
    def host_names(self):
        """ Returns a simulated list of host_names from the extension.

        @rtype: tuple of bytearrays
        """
        # because we can't simulate assignments to array elements we return
        # an immutable type
        if self.server_names is None:
            return tuple()
        else:
            return tuple([x.name for x in self.server_names if \
                x.type == NameType.host_name])

    @host_names.setter
    def host_names(self, host_names):
        """ Removes all host names from the extension and replaces them by
        names in X{host_names} parameter.

        Newly added parameters will be added at the I{beginning} of the list
        of extensions.

        @type host_names: iterable of bytearrays
        @param host_names: host names to replace the old server names of type 0
        """

        self.server_names = \
                [SNIExtension.ServerName(NameType.host_name, x) for x in \
                    host_names] + \
                [x for x in self.server_names if \
                    x.type != NameType.host_name]

    @host_names.deleter
    def host_names(self):
        """ Remove all host names from extension, leaves other name types
        unmodified
        """
        self.server_names = [x for x in self.server_names if \
                x.type != NameType.host_name]

    @property
    def ext_data(self):
        """ raw encoding of extension data, without type and length header

        @rtype: bytearray
        """
        if self.server_names is None:
            return bytearray(0)

        w2 = Writer()
        for server_name in self.server_names:
            w2.add(server_name.type, 1)
            w2.add(len(server_name.name), 2)
            w2.bytes += server_name.name

        # note that when the array is empty we write it as array of length 0
        w = Writer()
        w.add(len(w2.bytes), 2)
        w.bytes += w2.bytes
        return w.bytes

    def write(self):
        """ Returns encoded extension, as encoded on the wire

        @rtype: bytearray
        @return: an array of bytes formatted as they are supposed to be written
            on the wire, including the type, length and extension data
        """

        raw_data = self.ext_data

        w = Writer()
        w.add(self.ext_type, 2)
        w.add(len(raw_data), 2)
        w.bytes += raw_data

        return w.bytes

    def parse(self, p):
        """ Parses the on the wire extension data and returns an object that
        represents it.

        The parser should not include the type or length of extension!

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @rtype: L{SNIExtension}
        @raise SyntaxError: when the internal sizes don't match the attached
            data
        """
        self.server_names = []

        p.startLengthCheck(2)
        while not p.atLengthCheck():
            sn_type = p.get(1)
            sn_name = p.getVarBytes(2)
            self.server_names += [SNIExtension.ServerName(sn_type, sn_name)]
        p.stopLengthCheck()

        return self

class ClientCertTypeExtension(TLSExtension):
    """
    This class handles the Certificate Type extension (variant sent by client)
    defined in RFC 6091.

    @type ext_type: int
    @ivar ext_type: numeric type of Certificate Type extension, i.e. 9

    @type ext_data: bytearray
    @ivar ext_data: raw representation of the extension data

    @type cert_types: list of int
    @ivar cert_types: list of certificate type identifiers (each one byte long)
    """

    def __init__(self):
        """
        Create an instance of ClientCertTypeExtension

        See also: L{create} and L{parse}
        """

        self.cert_types = None

    @property
    def ext_type(self):
        """
        Return the type of TLS extension, in this case - 9

        @rtype: int
        """

        return ExtensionType.cert_type

    @property
    def ext_data(self):
        """
        Return the raw encoding of this extension

        @rtype: bytearray
        """

        if self.cert_types is None:
            return bytearray(0)

        w = Writer()
        w.add(len(self.cert_types), 1)
        for c_type in self.cert_types:
            w.add(c_type, 1)

        return w.bytes

    def create(self, cert_types=None):
        """
        Return instance of this extension with specified certificate types

        @type cert_types: iterable list of int
        @param cert_types: list of certificate types to advertise, all values
            should be between 0 and 2^8-1 inclusive

        @raises ValueError: when the list includes too big or negative integers
        """
        self.cert_types = cert_types
        return self

    def parse(self, p):
        """
        Parse the extension from binary data

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @raise SyntaxError: when the size of the passed element doesn't match
            the internal representation

        @rtype: L{ClientCertTypeExtension}
        """

        self.cert_types = p.getVarList(1, 1)

        return self

class SRPExtension(TLSExtension):
    """
    This class handles the Secure Remote Password protocol TLS extension
    defined in RFC 5054.

    @type ext_type: int
    @ivar ext_type: numeric type of SRPExtension, i.e. 12

    @type ext_data: bytearray
    @ivar ext_data: raw representation of extension data

    @type identity: bytearray
    @ivar identity: UTF-8 encoding of user name
    """

    def __init__(self):
        """
        Create an instance of SRPExtension

        See also: L{create} and L{parse}
        """

        self.identity = None

    @property
    def ext_type(self):
        """
        Return the type of TLS extension, in this case - 12

        @rtype: int
        """

        return ExtensionType.srp

    @property
    def ext_data(self):
        """
        Return raw data encoding of the extension

        @rtype: bytearray
        """

        if self.identity is None:
            return bytearray(0)

        w = Writer()
        w.add(len(self.identity), 1)
        w.addFixSeq(self.identity, 1)

        return w.bytes

    def create(self, identity=None):
        """ Create and instance of SRPExtension with specified protocols

        @type identity: bytearray
        @param identity: UTF-8 encoded identity (user name) to be provided
            to user. MUST be shorter than 2^8-1.

        @raise ValueError: when the identity lenght is longer than 2^8-1
        """

        if identity is None:
            return self

        if len(identity) >= 2**8:
            raise ValueError()

        self.identity = identity
        return self

    def parse(self, p):
        """
        Parse the extension from on the wire format

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @raise SyntaxError: when the data is internally inconsistent

        @rtype: L{SRPExtension}
        """

        self.identity = p.getVarBytes(1)

        return self

class NPNExtension(TLSExtension):
    """
    This class handles the unofficial Next Protocol Negotiation TLS extension.

    @type protocols: list of bytearrays
    @ivar protocols: list of protocol names supported by the server

    @type ext_type: int
    @ivar ext_type: numeric type of NPNExtension, i.e. 13172

    @type ext_data: bytearray
    @ivar ext_data: raw representation of extension data
    """

    def __init__(self):
        """
        Create an instance of NPNExtension

        See also: L{create} and L{parse}
        """

        self.protocols = None

    @property
    def ext_type(self):
        """ Return the type of TLS extension, in this case - 13172

        @rtype: int
        """
        return ExtensionType.supports_npn

    @property
    def ext_data(self):
        """ Return the raw data encoding of the extension

        @rtype: bytearray
        """
        if self.protocols is None:
            return bytearray(0)

        w = Writer()
        for prot in self.protocols:
            w.add(len(prot), 1)
            w.addFixSeq(prot, 1)

        return w.bytes

    def create(self, protocols=None):
        """ Create an instance of NPNExtension with specified protocols

        @type protocols: list of bytearray
        @param protocols: list of protocol names that are supported
        """
        self.protocols = protocols
        return self

    def parse(self, p):
        """ Parse the extension from on the wire format

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @raise SyntaxError: when the size of the passed element doesn't match
            the internal representation

        @rtype: L{NPNExtension}
        """
        self.protocols = []

        while p.getRemainingLength() > 0:
            self.protocols += [p.getVarBytes(1)]

        return self

TLSExtension._extensions = { ExtensionType.server_name : SNIExtension,
        ExtensionType.cert_type : ClientCertTypeExtension,
        ExtensionType.srp : SRPExtension,
        ExtensionType.supports_npn : NPNExtension }
