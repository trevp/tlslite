# Authors:
#   Trevor Perrin
#   Google - handling CertificateRequest.certificate_types
#   Google (adapted by Sam Rushing and Marcelo Fernandez) - NPN support
#   Dimitris Moraitis - Anon ciphersuites
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#   Hubert Kario - 'extensions' cleanup
#
# See the LICENSE file for legal information regarding use of this file.

"""Classes representing TLS messages."""

from .utils.compat import *
from .utils.cryptomath import *
from .errors import *
from .utils.codec import *
from .constants import *
from .x509 import X509
from .x509certchain import X509CertChain
from .utils.tackwrapper import *
from .extensions import *


class RecordHeader(object):
    """Generic interface to SSLv2 and SSLv3 (and later) record headers."""

    def __init__(self, ssl2):
        """Define instance variables."""
        self.type = 0
        self.version = (0, 0)
        self.length = 0
        self.ssl2 = ssl2


class RecordHeader3(RecordHeader):
    """SSLv3 (and later) TLS record header."""

    def __init__(self):
        """Define a SSLv3 style class."""
        super(RecordHeader3, self).__init__(ssl2=False)

    def create(self, version, type, length):
        """Set object values for writing (serialisation)."""
        self.type = type
        self.version = version
        self.length = length
        return self

    def write(self):
        """Serialise object to bytearray."""
        writer = Writer()
        writer.add(self.type, 1)
        writer.add(self.version[0], 1)
        writer.add(self.version[1], 1)
        writer.add(self.length, 2)
        return writer.bytes

    def parse(self, parser):
        """Deserialise object from Parser."""
        self.type = parser.get(1)
        self.version = (parser.get(1), parser.get(1))
        self.length = parser.get(2)
        self.ssl2 = False
        return self

    @property
    def typeName(self):
        matching = [x[0] for x in ContentType.__dict__.items()
                    if x[1] == self.type]
        if len(matching) == 0:
            return "unknown(" + str(self.type) + ")"
        else:
            return str(matching[0])

    def __str__(self):
        return "SSLv3 record,version({0[0]}.{0[1]}),"\
                "content type({1}),length({2})".format(self.version,
                                                       self.typeName,
                                                       self.length)

    def __repr__(self):
        return "RecordHeader3(type={0}, version=({1[0]}.{1[1]}), length={2})".\
                format(self.type, self.version, self.length)


class RecordHeader2(RecordHeader):
    """
    SSLv2 record header.

    :vartype padding: int
    :ivar padding: number of bytes added at end of message to make it multiple
        of block cipher size
    :vartype securityEscape: boolean
    :ivar securityEscape: whether the record contains a security escape message
    """

    def __init__(self):
        """Define a SSLv2 style class."""
        super(RecordHeader2, self).__init__(ssl2=True)
        self.padding = 0
        self.securityEscape = False

    def parse(self, parser):
        """Deserialise object from Parser."""
        firstByte = parser.get(1)
        secondByte = parser.get(1)
        if firstByte & 0x80:
            self.length = ((firstByte & 0x7f) << 8) | secondByte
        else:
            self.length = ((firstByte & 0x3f) << 8) | secondByte
            self.securityEscape = firstByte & 0x40 != 0
            self.padding = parser.get(1)

        self.type = ContentType.handshake
        self.version = (2, 0)
        return self

    def create(self, length, padding=0, securityEscape=False):
        """Set object's values."""
        self.length = length
        self.padding = padding
        self.securityEscape = securityEscape
        return self

    def write(self):
        """Serialise object to bytearray."""
        writer = Writer()

        shortHeader = not (self.padding or self.securityEscape)

        if ((shortHeader and self.length >= 0x8000) or
                (not shortHeader and self.length >= 0x4000)):
            raise ValueError("length too large")

        firstByte = 0
        if shortHeader:
            firstByte |= 0x80
        if self.securityEscape:
            firstByte |= 0x40
        firstByte |= self.length >> 8
        secondByte = self.length & 0xff

        writer.add(firstByte, 1)
        writer.add(secondByte, 1)
        if not shortHeader:
            writer.add(self.padding, 1)

        return writer.bytes


class Message(object):
    """Generic TLS message."""

    def __init__(self, contentType, data):
        """
        Initialize object with specified contentType and data.

        :type contentType: int
        :param contentType: TLS record layer content type of associated data
        :type data: bytearray
        :param data: data
        """
        self.contentType = contentType
        self.data = data

    def write(self):
        """Return serialised object data."""
        return self.data


class Alert(object):
    def __init__(self):
        self.contentType = ContentType.alert
        self.level = 0
        self.description = 0

    def create(self, description, level=AlertLevel.fatal):
        self.level = level
        self.description = description
        return self

    def parse(self, p):
        p.setLengthCheck(2)
        self.level = p.get(1)
        self.description = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.level, 1)
        w.add(self.description, 1)
        return w.bytes

    @staticmethod
    def _noneAsUnknown(text, number):
        """if text is None or empty, format number as 'unknown(number)'"""
        if not text:
            text = "unknown({0})".format(number)
        return text

    @property
    def levelName(self):
        return self._noneAsUnknown(AlertLevel.toRepr(self.level),
                                   self.level)

    @property
    def descriptionName(self):
        return self._noneAsUnknown(AlertDescription.toRepr(self.description),
                                   self.description)

    def __str__(self):
        return "Alert, level:{0}, description:{1}".format(self.levelName,
                                                          self.descriptionName)

    def __repr__(self):
        return "Alert(level={0}, description={1})".format(self.level,
                                                          self.description)


class HandshakeMsg(object):
    def __init__(self, handshakeType):
        self.contentType = ContentType.handshake
        self.handshakeType = handshakeType

    def __eq__(self, other):
        """Check if other object represents the same data as this object."""
        if hasattr(self, "write") and hasattr(other, "write"):
            return self.write() == other.write()
        else:
            return False

    def __ne__(self, other):
        """Check if other object represents different data as this object."""
        return not self.__eq__(other)

    def postWrite(self, w):
        headerWriter = Writer()
        headerWriter.add(self.handshakeType, 1)
        headerWriter.add(len(w.bytes), 3)
        return headerWriter.bytes + w.bytes


class HelloMessage(HandshakeMsg):
    """
    Class for sharing code between :py:class:`ClientHello` and
    :py:class:`ServerHello`.
    """

    def __init__(self, *args, **kwargs):
        """Initialize object."""
        super(HelloMessage, self).__init__(*args, **kwargs)
        self.extensions = None

    def getExtension(self, extType):
        """
        Return extension of given type if present, None otherwise.

        :rtype: ~tlslite.extensions.TLSExtension
        :raises TLSInternalError: when there are multiple extensions of the
            same type
        """
        if self.extensions is None:
            return None

        exts = [ext for ext in self.extensions if ext.extType == extType]
        if len(exts) > 1:
            raise TLSInternalError(
                "Multiple extensions of the same type present")
        elif len(exts) == 1:
            return exts[0]
        else:
            return None

    def addExtension(self, ext):
        """
        Add extension to internal list of extensions.

        :type ext: TLSExtension
        :param ext: extension object to add to list
        """
        if self.extensions is None:
            self.extensions = []

        self.extensions.append(ext)

    def _addExt(self, extType):
        """Add en empty extension of given type, if not already present"""
        ext = self.getExtension(extType)
        if ext is None:
            ext = TLSExtension(extType=extType).create(bytearray(0))
            self.addExtension(ext)

    def _removeExt(self, extType):
        """Remove extension of given type"""
        if self.extensions is not None:
            self.extensions[:] = (i for i in self.extensions
                                  if i.extType != extType)


    def _addOrRemoveExt(self, extType, add):
        """
        Remove or add an empty extension of given type.

        :type extType: int
        :param extType: numeric id of extension to add or remove
        :type add: boolean
        :param add: whether to add (True) or remove (False) the extension
        """
        if add:
            self._addExt(extType)
        else:
            self._removeExt(extType)


class ClientHello(HelloMessage):
    """
    Class for handling the ClientHello SSLv2/SSLv3/TLS message.

    :vartype certificate_types: list
    :ivar certificate_types: list of supported certificate types
        (deprecated)
    :vartype srp_username: bytearray
    :ivar srp_username: name of the user in SRP extension (deprecated)

    :vartype supports_npn: boolean
    :ivar supports_npn: NPN extension presence (deprecated)

    :vartype tack: boolean
    :ivar tack: TACK extension presence (deprecated)

    :vartype server_name: bytearray
    :ivar server_name: first host_name (type 0) present in SNI extension
        (deprecated)

    :vartype extensions: list of :py:class:`TLSExtension`
    :ivar extensions: list of TLS extensions parsed from wire or to send, see
        :py:class:`TLSExtension` and child classes for exact examples
    """

    def __init__(self, ssl2=False):
        super(ClientHello, self).__init__(HandshakeType.client_hello)
        self.ssl2 = ssl2
        self.client_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []         # a list of 16-bit values
        self.compression_methods = []   # a list of 8-bit values

    def __str__(self):
        """
        Return human readable representation of Client Hello.

        :rtype: str
        """
        if self.session_id.count(bytearray(b'\x00')) == len(self.session_id)\
                and len(self.session_id) != 0:
            session = "bytearray(b'\\x00'*{0})".format(len(self.session_id))
        else:
            session = repr(self.session_id)
        ret = "client_hello,version({0[0]}.{0[1]}),random(...),"\
              "session ID({1!s}),cipher suites({2!r}),"\
              "compression methods({3!r})".format(
                  self.client_version, session,
                  self.cipher_suites, self.compression_methods)

        if self.extensions is not None:
            ret += ",extensions({0!r})".format(self.extensions)

        return ret

    def __repr__(self):
        """
        Return machine readable representation of Client Hello.

        :rtype: str
        """
        return "ClientHello(ssl2={0}, client_version=({1[0]}.{1[1]}), "\
               "random={2!r}, session_id={3!r}, cipher_suites={4!r}, "\
               "compression_methods={5}, extensions={6})".format(
                   self.ssl2, self.client_version, self.random,
                   self.session_id, self.cipher_suites,
                   self.compression_methods, self.extensions)

    @property
    def certificate_types(self):
        """
        Return the list of certificate types supported.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection
        """
        cert_type = self.getExtension(ExtensionType.cert_type)
        if cert_type is None:
            # XXX backwards compatibility: TLSConnection
            # depends on a default value of this property
            return [CertificateType.x509]
        else:
            return cert_type.certTypes

    @certificate_types.setter
    def certificate_types(self, val):
        """
        Set list of supported certificate types.

        Sets the list of supported types to list given in :py:obj:`val` if the
        cert_type extension is present. Creates the extension and places it
        last in the list otherwise.

        :type val: list
        :param val: list of supported certificate types by client encoded as
            single byte integers
        """
        cert_type = self.getExtension(ExtensionType.cert_type)

        if cert_type is None:
            ext = ClientCertTypeExtension().create(val)
            self.addExtension(ext)
        else:
            cert_type.certTypes = val

    @property
    def srp_username(self):
        """
        Return username for the SRP.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection
        """
        srp_ext = self.getExtension(ExtensionType.srp)

        if srp_ext is None:
            return None
        else:
            return srp_ext.identity

    @srp_username.setter
    def srp_username(self, name):
        """
        Set the username for SRP.

        :type name: bytearray
        :param name: UTF-8 encoded username
        """
        srp_ext = self.getExtension(ExtensionType.srp)

        if srp_ext is None:
            ext = SRPExtension().create(name)
            self.addExtension(ext)
        else:
            srp_ext.identity = name

    @property
    def tack(self):
        """
        Return whether the client supports TACK.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection

        :rtype: boolean
        """
        return self.getExtension(ExtensionType.tack) is not None

    @tack.setter
    def tack(self, present):
        """
        Create or delete the TACK extension.

        :type present: boolean
        :param present: True will create extension while False will remove
            extension from client hello
        """
        self._addOrRemoveExt(ExtensionType.tack, present)

    @property
    def supports_npn(self):
        """
        Return whether client supports NPN extension.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection

        :rtype: boolean
        """
        return self.getExtension(ExtensionType.supports_npn) is not None

    @supports_npn.setter
    def supports_npn(self, present):
        """
        Create or delete the NPN extension.

        :type present: boolean
        :param present: selects whatever to create or remove the extension
            from list of supported ones
        """
        self._addOrRemoveExt(ExtensionType.supports_npn, present)

    @property
    def server_name(self):
        """
        Return first host_name present in SNI extension.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection

        :rtype: bytearray
        """
        sni_ext = self.getExtension(ExtensionType.server_name)
        if sni_ext is None:
            return bytearray(0)
        else:
            if len(sni_ext.hostNames) > 0:
                return sni_ext.hostNames[0]
            else:
                return bytearray(0)

    @server_name.setter
    def server_name(self, hostname):
        """
        Set the first host_name present in SNI extension.

        :type hostname: bytearray
        :param hostname: name of the host_name to set
        """
        sni_ext = self.getExtension(ExtensionType.server_name)
        if sni_ext is None:
            sni_ext = SNIExtension().create(hostname)
            self.addExtension(sni_ext)
        else:
            names = list(sni_ext.hostNames)
            names[0] = hostname
            sni_ext.hostNames = names

    def create(self, version, random, session_id, cipher_suites,
               certificate_types=None, srpUsername=None,
               tack=False, supports_npn=None, serverName=None,
               extensions=None):
        """
        Create a ClientHello message for sending.

        :type version: tuple
        :param version: the highest supported TLS version encoded as two int
            tuple

        :type random: bytearray
        :param random: client provided random value, in old versions of TLS
            (before 1.2) the first 32 bits should include system time, also
            used as the "challenge" field in SSLv2

        :type session_id: bytearray
        :param session_id: ID of session, set when doing session resumption

        :type cipher_suites: list
        :param cipher_suites: list of ciphersuites advertised as supported

        :type certificate_types: list
        :param certificate_types: list of supported certificate types, uses
            TLS extension for signalling, as such requires TLS1.0 to work

        :type srpUsername: bytearray
        :param srpUsername: utf-8 encoded username for SRP, TLS extension

        :type tack: boolean
        :param tack: whatever to advertise support for TACK, TLS extension

        :type supports_npn: boolean
        :param supports_npn: whatever to advertise support for NPN, TLS
            extension

        :type serverName: bytearray
        :param serverName: the hostname to request in server name indication
            extension, TLS extension. Note that SNI allows to set multiple
            hostnames and values that are not hostnames, use
            :py:class:`~.extensions.SNIExtension`
            together with :py:obj:`extensions` to use it.

        :type extensions: list of :py:class:`~.extensions.TLSExtension`
        :param extensions: list of extensions to advertise
        """
        self.client_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suites = cipher_suites
        self.compression_methods = [0]
        if extensions is not None:
            self.extensions = extensions
        if certificate_types is not None:
            self.certificate_types = certificate_types
        if srpUsername is not None:
            if not isinstance(srpUsername, bytearray):
                raise TypeError("srpUsername must be a bytearray object")
            self.srp_username = srpUsername
        self.tack = tack
        if supports_npn is not None:
            self.supports_npn = supports_npn
        if serverName is not None:
            self.server_name = bytearray(serverName, "utf-8")
        return self

    def parse(self, p):
        """Deserialise object from on the wire data."""
        if self.ssl2:
            self.client_version = (p.get(1), p.get(1))
            cipherSpecsLength = p.get(2)
            sessionIDLength = p.get(2)
            randomLength = p.get(2)
            p.setLengthCheck(cipherSpecsLength +
                             sessionIDLength +
                             randomLength)
            self.cipher_suites = p.getFixList(3, cipherSpecsLength//3)
            self.session_id = p.getFixBytes(sessionIDLength)
            self.random = p.getFixBytes(randomLength)
            if len(self.random) < 32:
                zeroBytes = 32-len(self.random)
                self.random = bytearray(zeroBytes) + self.random
            self.compression_methods = [0]  # Fake this value
            p.stopLengthCheck()
        else:
            p.startLengthCheck(3)
            self.client_version = (p.get(1), p.get(1))
            self.random = p.getFixBytes(32)
            self.session_id = p.getVarBytes(1)
            self.cipher_suites = p.getVarList(2, 2)
            self.compression_methods = p.getVarList(1, 1)
            if not p.atLengthCheck():
                self.extensions = []
                totalExtLength = p.get(2)
                p2 = Parser(p.getFixBytes(totalExtLength))
                while p2.getRemainingLength() > 0:
                    ext = TLSExtension().parse(p2)
                    self.extensions += [ext]
            p.stopLengthCheck()
        return self

    def _writeSSL2(self):
        """Serialise SSLv2 object to on the wire data."""
        writer = Writer()
        writer.add(self.handshakeType, 1)
        writer.add(self.client_version[0], 1)
        writer.add(self.client_version[1], 1)

        ciphersWriter = Writer()
        ciphersWriter.addFixSeq(self.cipher_suites, 3)

        writer.add(len(ciphersWriter.bytes), 2)
        writer.add(len(self.session_id), 2)
        writer.add(len(self.random), 2)

        writer.bytes += ciphersWriter.bytes
        writer.bytes += self.session_id
        writer.bytes += self.random

        # postWrite() is necessary only for SSLv3/TLS
        return writer.bytes

    def _write(self):
        """Serialise SSLv3 or TLS object to on the wire data."""
        w = Writer()
        w.add(self.client_version[0], 1)
        w.add(self.client_version[1], 1)
        w.bytes += self.random
        w.addVarSeq(self.session_id, 1, 1)
        w.addVarSeq(self.cipher_suites, 2, 2)
        w.addVarSeq(self.compression_methods, 1, 1)

        if self.extensions is not None:
            w2 = Writer()
            for ext in self.extensions:
                w2.bytes += ext.write()

            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        return self.postWrite(w)

    def write(self):
        """Serialise object to on the wire data."""
        if self.ssl2:
            return self._writeSSL2()
        else:
            return self._write()


class ServerHello(HelloMessage):
    """
    Handling of Server Hello messages.

    :vartype server_version: tuple
    :ivar server_version: protocol version encoded as two int tuple

    :vartype random: bytearray
    :ivar random: server random value

    :vartype session_id: bytearray
    :ivar session_id: session identifier for resumption

    :vartype cipher_suite: int
    :ivar cipher_suite: server selected cipher_suite

    :vartype compression_method: int
    :ivar compression_method: server selected compression method

    :vartype next_protos: list of bytearray
    :ivar next_protos: list of advertised protocols in NPN extension

    :vartype next_protos_advertised: list of bytearray
    :ivar next_protos_advertised: list of protocols advertised in NPN extension

    :vartype certificate_type: int
    :ivar certificate_type: certificate type selected by server

    :vartype extensions: list
    :ivar extensions: list of TLS extensions present in server_hello message,
        see :py:class:`~.extensions.TLSExtension` and child classes for exact
        examples
    """

    def __init__(self):
        """Initialise ServerHello object."""
        super(ServerHello, self).__init__(HandshakeType.server_hello)
        self.server_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suite = 0
        self.compression_method = 0
        self._tack_ext = None

    def __str__(self):
        base = "server_hello,length({0}),version({1[0]}.{1[1]}),random(...),"\
                "session ID({2!r}),cipher({3:#x}),compression method({4})"\
                .format(len(self.write())-4, self.server_version,
                        self.session_id, self.cipher_suite,
                        self.compression_method)

        if self.extensions is None:
            return base

        ret = ",extensions["
        ret += ",".join(repr(x) for x in self.extensions)
        ret += "]"
        return base + ret

    def __repr__(self):
        return "ServerHello(server_version=({0[0]}, {0[1]}), random={1!r}, "\
                "session_id={2!r}, cipher_suite={3}, compression_method={4}, "\
                "_tack_ext={5}, extensions={6!r})".format(
                    self.server_version, self.random, self.session_id,
                    self.cipher_suite, self.compression_method, self._tack_ext,
                    self.extensions)

    @property
    def tackExt(self):
        """Return the TACK extension."""
        if self._tack_ext is None:
            ext = self.getExtension(ExtensionType.tack)
            if ext is None or not tackpyLoaded:
                return None
            else:
                self._tack_ext = TackExtension(ext.extData)
        return self._tack_ext

    @tackExt.setter
    def tackExt(self, val):
        """Set the TACK extension."""
        self._tack_ext = val
        # makes sure that extensions are included in the on the wire encoding
        if val is not None:
            if self.extensions is None:
                self.extensions = []

    @property
    def certificate_type(self):
        """
        Return the certificate type selected by server.

        :rtype: int
        """
        cert_type = self.getExtension(ExtensionType.cert_type)
        if cert_type is None:
            # XXX backwards compatibility, TLSConnection expects the default
            # value to be that
            return CertificateType.x509
        return cert_type.cert_type

    @certificate_type.setter
    def certificate_type(self, val):
        """
        Set the certificate type supported.

        :type val: int
        :param val: type of certificate
        """
        if val == CertificateType.x509 or val is None:
            # XXX backwards compatibility, x509 value should not be sent
            self._removeExt(ExtensionType.cert_type)
            return

        cert_type = self.getExtension(ExtensionType.cert_type)
        if cert_type is None:
            ext = ServerCertTypeExtension().create(val)
            self.addExtension(ext)
        else:
            cert_type.cert_type = val

    @property
    def next_protos(self):
        """
        Return the advertised protocols in NPN extension.

        :rtype: list of bytearrays
        """
        npn_ext = self.getExtension(ExtensionType.supports_npn)

        if npn_ext is None:
            return None
        else:
            return npn_ext.protocols

    @next_protos.setter
    def next_protos(self, val):
        """
        Set the advertised protocols in NPN extension.

        :type val: list
        :param val: list of protocols to advertise as UTF-8 encoded names
        """
        if val is None:
            # XXX: do not send empty extension
            self._removeExt(ExtensionType.supports_npn)
            return
        else:
            # convinience function, make sure the values are properly encoded
            val = [bytearray(x) for x in val]

        npn_ext = self.getExtension(ExtensionType.supports_npn)

        if npn_ext is None:
            ext = NPNExtension().create(val)
            self.addExtension(ext)
        else:
            npn_ext.protocols = val

    @property
    def next_protos_advertised(self):
        """
        Return the advertised protocols in NPN extension.

        :rtype: list of bytearrays
        """
        return self.next_protos

    @next_protos_advertised.setter
    def next_protos_advertised(self, val):
        """
        Set the advertised protocols in NPN extension.

        :type val: list
        :param val: list of protocols to advertise as UTF-8 encoded names
        """
        self.next_protos = val

    def create(self, version, random, session_id, cipher_suite,
               certificate_type=None, tackExt=None,
               next_protos_advertised=None,
               extensions=None):
        """Initialize the object for deserialisation."""
        self.extensions = extensions
        self.server_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.certificate_type = certificate_type
        self.compression_method = 0
        if tackExt is not None:
            self.tackExt = tackExt
        self.next_protos_advertised = next_protos_advertised
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.server_version = (p.get(1), p.get(1))
        self.random = p.getFixBytes(32)
        if self.server_version <= (3, 3):
            self.session_id = p.getVarBytes(1)
        else:
            self.session_id = None
        self.cipher_suite = p.get(2)
        if self.server_version <= (3, 3):
            self.compression_method = p.get(1)
        else:
            self.compression_method = None
        if not p.atLengthCheck():
            self.extensions = []
            totalExtLength = p.get(2)
            p2 = Parser(p.getFixBytes(totalExtLength))
            while p2.getRemainingLength() > 0:
                ext = TLSExtension(server=True).parse(p2)
                self.extensions += [ext]
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.server_version[0], 1)
        w.add(self.server_version[1], 1)
        w.bytes += self.random
        if self.server_version <= (3, 3):
            w.addVarSeq(self.session_id, 1, 1)
        w.add(self.cipher_suite, 2)
        if self.server_version <= (3, 3):
            w.add(self.compression_method, 1)

        if self.extensions is not None:
            w2 = Writer()
            for ext in self.extensions:
                w2.bytes += ext.write()

            if self.tackExt:
                b = self.tackExt.serialize()
                w2.add(ExtensionType.tack, 2)
                w2.add(len(b), 2)
                w2.bytes += b

            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        return self.postWrite(w)


class ServerHello2(HandshakeMsg):
    """
    SERVER-HELLO message from SSLv2.

    :vartype session_id_hit: int
    :ivar session_id_hit: non zero if the client provided session ID was
        matched in server's session cache

    :vartype certificate_type: int
    :ivar certificate_type: type of certificate sent

    :vartype server_version: tuple of ints
    :ivar server_version: protocol version selected by server

    :vartype certificate: bytearray
    :ivar certificate: certificate sent by server

    :vartype ciphers: array of int
    :ivar ciphers: list of ciphers supported by server

    :vartype session_id: bytearray
    :ivar session_id: idendifier of negotiated session
    """

    def __init__(self):
        super(ServerHello2, self).__init__(SSL2HandshakeType.server_hello)
        self.session_id_hit = 0
        self.certificate_type = 0
        self.server_version = (0, 0)
        self.certificate = bytearray(0)
        self.ciphers = []
        self.session_id = bytearray(0)

    def create(self, session_id_hit, certificate_type, server_version,
               certificate, ciphers, session_id):
        """Initialize fields of the SERVER-HELLO message."""
        self.session_id_hit = session_id_hit
        self.certificate_type = certificate_type
        self.server_version = server_version
        self.certificate = certificate
        self.ciphers = ciphers
        self.session_id = session_id
        return self

    def write(self):
        """Serialise object to on the wire data."""
        writer = Writer()
        writer.add(self.handshakeType, 1)
        writer.add(self.session_id_hit, 1)
        writer.add(self.certificate_type, 1)
        if len(self.server_version) != 2:
            raise ValueError("server version must be a 2-element tuple")
        writer.addFixSeq(self.server_version, 1)
        writer.add(len(self.certificate), 2)

        ciphersWriter = Writer()
        ciphersWriter.addFixSeq(self.ciphers, 3)

        writer.add(len(ciphersWriter.bytes), 2)
        writer.add(len(self.session_id), 2)

        writer.bytes += self.certificate
        writer.bytes += ciphersWriter.bytes
        writer.bytes += self.session_id

        # postWrite() is necessary only for SSLv3/TLS
        return writer.bytes

    def parse(self, parser):
        """Deserialise object from on the wire data."""
        self.session_id_hit = parser.get(1)
        self.certificate_type = parser.get(1)
        self.server_version = (parser.get(1), parser.get(1))
        certificateLength = parser.get(2)
        ciphersLength = parser.get(2)
        sessionIDLength = parser.get(2)
        parser.setLengthCheck(certificateLength +
                              ciphersLength +
                              sessionIDLength)
        self.certificate = parser.getFixBytes(certificateLength)
        self.ciphers = parser.getFixList(3, ciphersLength // 3)
        self.session_id = parser.getFixBytes(sessionIDLength)
        parser.stopLengthCheck()
        return self


class CertificateEntry(object):
    """
    Object storing a single certificate from TLS 1.3.

    Stores a certificate (or possibly a raw public key) together with
    associated extensions
    """

    def __init__(self, certificateType):
        """Initialise the object for given certificate type."""
        self.certificateType = certificateType
        self.certificate = None
        self.extensions = None

    def create(self, certificate, extensions):
        """Set all values of the certificate entry."""
        self.certificate = certificate
        self.extensions = extensions
        return self

    def write(self):
        """Serialise the object."""
        writer = Writer()
        if self.certificateType == CertificateType.x509:
            writer.addVarSeq(self.certificate.writeBytes(), 1, 3)
        else:
            raise ValueError("Set certificate type ({0}) unsupported"
                             .format(self.certificateType))

        if self.extensions is not None:
            writer2 = Writer()
            for ext in self.extensions:
                writer2.bytes += ext.write()
            writer.addVarSeq(writer2.bytes, 1, 2)

        return writer.bytes

    def parse(self, parser):
        """Deserialise the object from on the wire data."""
        if self.certificateType == CertificateType.x509:
            certBytes = parser.getVarBytes(3)
            x509 = X509()
            x509.parseBinary(certBytes)
            self.certificate = x509
        else:
            raise ValueError("Set certificate type ({0}) unsupported"
                             .format(self.certificateType))

        self.extensions = []
        parser.startLengthCheck(2)
        while not parser.atLengthCheck():
            ext = TLSExtension(cert=True).parse(parser)
            self.extensions.append(ext)
        parser.stopLengthCheck()
        return self

    def __repr__(self):
        return "CertificateEntry(certificate={0!r}, extensions={1!r})".format(
                self.certificate, self.extensions)


class Certificate(HandshakeMsg):
    def __init__(self, certificateType, version=(3, 2)):
        HandshakeMsg.__init__(self, HandshakeType.certificate)
        self.certificateType = certificateType
        self._certChain = None
        self.version = version
        self.certificate_list = None
        self.certificate_request_context = None

    @property
    def certChain(self):
        if self._certChain:
            return self._certChain
        elif self.certificate_list is None:
            return None
        else:
            return X509CertChain([i.certificate
                                  for i in self.certificate_list])

    def create(self, certChain, context=None):
        if isinstance(certChain, X509CertChain):
            self._certChain = certChain
            self.certificate_list = [CertificateEntry(self.certificateType)
                                     .create(i, []) for i
                                     in certChain.x509List]
        else:
            self.certificate_list = certChain
        self.certificate_request_context = context
        return self

    def _parse_certificate_list(self, parser):
        self.certificate_list = []
        while parser.getRemainingLength():
            entry = CertificateEntry(self.certificateType)
            self.certificate_list.append(entry.parse(parser))

    def _parse_tls13(self, parser):
        parser.startLengthCheck(3)
        self.certificate_request_context = parser.getVarBytes(1)
        self._parse_certificate_list(Parser(parser.getVarBytes(3)))
        parser.stopLengthCheck()
        return self

    def _parse_tls12(self, p):
        p.startLengthCheck(3)
        if self.certificateType == CertificateType.x509:
            chainLength = p.get(3)
            index = 0
            certificate_list = []
            while index != chainLength:
                certBytes = p.getVarBytes(3)
                x509 = X509()
                x509.parseBinary(certBytes)
                certificate_list.append(x509)
                index += len(certBytes)+3
            if certificate_list:
                self._certChain = X509CertChain(certificate_list)
        else:
            raise AssertionError()

        p.stopLengthCheck()
        return self

    def parse(self, p):
        if self.version <= (3, 3):
            return self._parse_tls12(p)
        else:
            return self._parse_tls13(p)

    def _write_tls13(self):
        w = Writer()
        w.addVarSeq(self.certificate_request_context, 1, 1)
        w2 = Writer()
        for entry in self.certificate_list:
            w2.bytes += entry.write()
        w.addVarSeq(w2.bytes, 1, 3)
        return w

    def _write_tls12(self):
        w = Writer()
        if self.certificateType == CertificateType.x509:
            chainLength = 0
            if self._certChain:
                certificate_list = self._certChain.x509List
            else:
                certificate_list = []
            # determine length
            for cert in certificate_list:
                bytes = cert.writeBytes()
                chainLength += len(bytes)+3
            # add bytes
            w.add(chainLength, 3)
            for cert in certificate_list:
                bytes = cert.writeBytes()
                w.addVarSeq(bytes, 1, 3)
        else:
            raise AssertionError()
        return w

    def write(self):
        if self.version <= (3, 3):
            writer = self._write_tls12()
        else:
            writer = self._write_tls13()
        return self.postWrite(writer)

    def __repr__(self):
        if self.version <= (3, 3):
            return "Certificate(certChain={0!r})".format(
                    self.certChain.x509List)
        else:
            return "Certificate(request_context={0!r}, "\
                   "certificate_list={1!r})"\
                    .format(self.certificate_request_context,
                            self.certificate_list)


class CertificateRequest(HandshakeMsg):
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.certificate_request)
        self.certificate_types = []
        self.certificate_authorities = []
        self.version = version
        self.supported_signature_algs = []

    def create(self, certificate_types, certificate_authorities, sig_algs=()):
        self.certificate_types = certificate_types
        self.certificate_authorities = certificate_authorities
        self.supported_signature_algs = sig_algs
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.certificate_types = p.getVarList(1, 1)
        if self.version >= (3, 3):
            self.supported_signature_algs = p.getVarTupleList(1, 2, 2)
        ca_list_length = p.get(2)
        index = 0
        self.certificate_authorities = []
        while index != ca_list_length:
            ca_bytes = p.getVarBytes(2)
            self.certificate_authorities.append(ca_bytes)
            index += len(ca_bytes)+2
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addVarSeq(self.certificate_types, 1, 1)
        if self.version >= (3, 3):
            w.addVarTupleSeq(self.supported_signature_algs, 1, 2)
        caLength = 0
        # determine length
        for ca_dn in self.certificate_authorities:
            caLength += len(ca_dn)+2
        w.add(caLength, 2)
        # add bytes
        for ca_dn in self.certificate_authorities:
            w.addVarSeq(ca_dn, 1, 2)
        return self.postWrite(w)


class ServerKeyExchange(HandshakeMsg):
    """
    Handling TLS Handshake protocol Server Key Exchange messages.

    :vartype cipherSuite: int
    :cvar cipherSuite: id of ciphersuite selected in Server Hello message
    :vartype srp_N: int
    :cvar srp_N: SRP protocol prime
    :vartype srp_N_len: int
    :cvar srp_N_len: length of srp_N in bytes
    :vartype srp_g: int
    :cvar srp_g: SRP protocol generator
    :vartype srp_g_len: int
    :cvar srp_g_len: length of srp_g in bytes
    :vartype srp_s: bytearray
    :cvar srp_s: SRP protocol salt value
    :vartype srp_B: int
    :cvar srp_B: SRP protocol server public value
    :vartype srp_B_len: int
    :cvar srp_B_len: length of srp_B in bytes
    :vartype dh_p: int
    :cvar dh_p: FFDHE protocol prime
    :vartype dh_p_len: int
    :cvar dh_p_len: length of dh_p in bytes
    :vartype dh_g: int
    :cvar dh_g: FFDHE protocol generator
    :vartype dh_g_len: int
    :cvar dh_g_len: length of dh_g in bytes
    :vartype dh_Ys: int
    :cvar dh_Ys: FFDH protocol server key share
    :vartype dh_Ys_len: int
    :cvar dh_Ys_len: length of dh_Ys in bytes
    :vartype curve_type: int
    :cvar curve_type: Type of curve used (explicit, named, etc.)
    :vartype named_curve: int
    :cvar named_curve: TLS ID of named curve
    :vartype ecdh_Ys: bytearray
    :cvar ecdh_Ys: ECDH protocol encoded point key share
    :vartype signature: bytearray
    :cvar signature: signature performed over the parameters by server
    :vartype hashAlg: int
    :cvar hashAlg: id of hash algorithm used for signature
    :vartype signAlg: int
    :cvar signAlg: id of signature algorithm used for signature
    """

    def __init__(self, cipherSuite, version):
        """
        Initialise Server Key Exchange for reading or writing.

        :type cipherSuite: int
        :param cipherSuite: id of ciphersuite selected by server
        """
        HandshakeMsg.__init__(self, HandshakeType.server_key_exchange)
        self.cipherSuite = cipherSuite
        self.version = version
        self.srp_N = 0
        self.srp_N_len = None
        self.srp_g = 0
        self.srp_g_len = None
        self.srp_s = bytearray(0)
        self.srp_B = 0
        self.srp_B_len = None
        # Anon DH params:
        self.dh_p = 0
        self.dh_p_len = None
        self.dh_g = 0
        self.dh_g_len = None
        self.dh_Ys = 0
        self.dh_Ys_len = None
        # EC settings
        self.curve_type = None
        self.named_curve = None
        self.ecdh_Ys = bytearray(0)
        # signature for certificate authenticated ciphersuites
        self.signature = bytearray(0)
        # signature hash algorithm and signing algorithm for TLSv1.2
        self.hashAlg = 0
        self.signAlg = 0

    def __repr__(self):
        ret = "ServerKeyExchange(cipherSuite=CipherSuite.{0}, version={1}"\
              "".format(CipherSuite.ietfNames[self.cipherSuite], self.version)

        if self.srp_N != 0:
            ret += ", srp_N={0}, srp_g={1}, srp_s={2!r}, srp_B={3}".format(
                self.srp_N, self.srp_g, self.srp_s, self.srp_B)
        if self.dh_p != 0:
            ret += ", dh_p={0}, dh_g={1}, dh_Ys={2}".format(
                self.dh_p, self.dh_g, self.dh_Ys)
        if self.signAlg != 0:
            ret += ", hashAlg={0}, signAlg={1}".format(
                self.hashAlg, self.signAlg)
        if self.signature != bytearray(0):
            ret += ", signature={0!r}".format(self.signature)
        ret += ")"

        return ret

    def createSRP(self, srp_N, srp_g, srp_s, srp_B):
        """Set SRP protocol parameters."""
        self.srp_N = srp_N
        self.srp_N_len = None
        self.srp_g = srp_g
        self.srp_g_len = None
        self.srp_s = srp_s
        self.srp_B = srp_B
        self.srp_B_len = None
        return self

    def createDH(self, dh_p, dh_g, dh_Ys):
        """Set FFDH protocol parameters."""
        self.dh_p = dh_p
        self.dh_p_len = None
        self.dh_g = dh_g
        self.dh_g_len = None
        self.dh_Ys = dh_Ys
        self.dh_Ys_len = None
        return self

    def createECDH(self, curve_type, named_curve=None, point=None):
        """Set ECDH protocol parameters."""
        self.curve_type = curve_type
        self.named_curve = named_curve
        self.ecdh_Ys = point

    def parse(self, parser):
        """
        Deserialise message from :py:class:`Parser`.

        :type parser: Parser
        :param parser: parser to read data from
        """
        parser.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_N_len = parser.get(2)
            self.srp_N = bytesToNumber(parser.getFixBytes(self.srp_N_len))
            self.srp_g_len = parser.get(2)
            self.srp_g = bytesToNumber(parser.getFixBytes(self.srp_g_len))
            self.srp_s = parser.getVarBytes(1)
            self.srp_B_len = parser.get(2)
            self.srp_B = bytesToNumber(parser.getFixBytes(self.srp_B_len))
        elif self.cipherSuite in CipherSuite.dhAllSuites:
            self.dh_p_len = parser.get(2)
            self.dh_p = bytesToNumber(parser.getFixBytes(self.dh_p_len))
            self.dh_g_len = parser.get(2)
            self.dh_g = bytesToNumber(parser.getFixBytes(self.dh_g_len))
            self.dh_Ys_len = parser.get(2)
            self.dh_Ys = bytesToNumber(parser.getFixBytes(self.dh_Ys_len))
        elif self.cipherSuite in CipherSuite.ecdhAllSuites:
            self.curve_type = parser.get(1)
            # only named curves supported
            assert self.curve_type == 3
            self.named_curve = parser.get(2)
            self.ecdh_Ys = parser.getVarBytes(1)
        else:
            raise AssertionError()

        if self.cipherSuite in CipherSuite.certAllSuites:
            if self.version == (3, 3):
                self.hashAlg = parser.get(1)
                self.signAlg = parser.get(1)
            self.signature = parser.getVarBytes(2)

        parser.stopLengthCheck()
        return self

    def writeParams(self):
        """
        Serialise the key exchange parameters.

        :rtype: bytearray
        """
        writer = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            writer.addVarSeq(numberToByteArray(self.srp_N, self.srp_N_len),
                             1, 2)
            writer.addVarSeq(numberToByteArray(self.srp_g, self.srp_g_len),
                             1, 2)
            writer.addVarSeq(self.srp_s, 1, 1)
            writer.addVarSeq(numberToByteArray(self.srp_B, self.srp_B_len),
                             1, 2)
        elif self.cipherSuite in CipherSuite.dhAllSuites:
            writer.addVarSeq(numberToByteArray(self.dh_p, self.dh_p_len),
                             1, 2)
            writer.addVarSeq(numberToByteArray(self.dh_g, self.dh_g_len),
                             1, 2)
            writer.addVarSeq(numberToByteArray(self.dh_Ys, self.dh_Ys_len),
                             1, 2)
        elif self.cipherSuite in CipherSuite.ecdhAllSuites:
            writer.add(self.curve_type, 1)
            assert self.curve_type == 3
            writer.add(self.named_curve, 2)
            writer.addVarSeq(self.ecdh_Ys, 1, 1)
        else:
            assert(False)
        return writer.bytes

    def write(self):
        """
        Serialise complete message.

        :rtype: bytearray
        """
        writer = Writer()
        writer.bytes += self.writeParams()
        if self.cipherSuite in CipherSuite.certAllSuites:
            if self.version >= (3, 3):
                assert self.hashAlg != 0 and self.signAlg != 0
                writer.add(self.hashAlg, 1)
                writer.add(self.signAlg, 1)
            writer.addVarSeq(self.signature, 1, 2)
        return self.postWrite(writer)

    def hash(self, clientRandom, serverRandom):
        """
        Calculate hash of parameters to sign.

        :rtype: bytearray
        """
        bytesToHash = clientRandom + serverRandom + self.writeParams()
        if self.version >= (3, 3):
            sigScheme = SignatureScheme.toRepr((self.hashAlg, self.signAlg))
            if sigScheme is None:
                hashAlg = HashAlgorithm.toRepr(self.hashAlg)
                if hashAlg is None:
                    raise AssertionError("Unknown hash algorithm: {0}".
                                         format(self.hashAlg))
            else:
                hashAlg = SignatureScheme.getHash(sigScheme)
            return secureHash(bytesToHash, hashAlg)
        return MD5(bytesToHash) + SHA1(bytesToHash)


class ServerHelloDone(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello_done)

    def create(self):
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        return self.postWrite(w)

    def __repr__(self):
        """Human readable representation of object."""
        return "ServerHelloDone()"


class ClientKeyExchange(HandshakeMsg):
    """
    Handling of TLS Handshake protocol ClientKeyExchange message.

    :vartype cipherSuite: int
    :ivar cipherSuite: the cipher suite id used for the connection
    :vartype version: tuple(int, int)
    :ivar version: TLS protocol version used for the connection
    :vartype srp_A: int
    :ivar srp_A: SRP protocol client answer value
    :vartype dh_Yc: int
    :ivar dh_Yc: client Finite Field Diffie-Hellman protocol key share
    :vartype ecdh_Yc: bytearray
    :ivar ecdh_Yc: encoded curve coordinates
    :vartype encryptedPreMasterSecret: bytearray
    :ivar encryptedPreMasterSecret: client selected PremMaster secret encrypted
        with server public key (from certificate)
    """

    def __init__(self, cipherSuite, version=None):
        """
        Initialise ClientKeyExchange for reading or writing.

        :type cipherSuite: int
        :param cipherSuite: id of the ciphersuite selected by server
        :type version: tuple(int, int)
        :param version: protocol version selected by server
        """
        HandshakeMsg.__init__(self, HandshakeType.client_key_exchange)
        self.cipherSuite = cipherSuite
        self.version = version
        self.srp_A = 0
        self.dh_Yc = 0
        self.ecdh_Yc = bytearray(0)
        self.encryptedPreMasterSecret = bytearray(0)

    def createSRP(self, srp_A):
        """
        Set the SRP client answer.

        returns self

        :type srp_A: int
        :param srp_A: client SRP answer
        :rtype: ClientKeyExchange
        """
        self.srp_A = srp_A
        return self

    def createRSA(self, encryptedPreMasterSecret):
        """
        Set the encrypted PreMaster Secret.

        returns self

        :type encryptedPreMasterSecret: bytearray
        :rtype: ClientKeyExchange
        """
        self.encryptedPreMasterSecret = encryptedPreMasterSecret
        return self

    def createDH(self, dh_Yc):
        """
        Set the client FFDH key share.

        returns self

        :type dh_Yc: int
        :rtype: ClientKeyExchange
        """
        self.dh_Yc = dh_Yc
        return self

    def createECDH(self, ecdh_Yc):
        """
        Set the client ECDH key share.

        returns self

        :type ecdh_Yc: bytearray
        :rtype: ClientKeyExchange
        """
        self.ecdh_Yc = ecdh_Yc
        return self

    def parse(self, parser):
        """
        Deserialise the message from :py:class:`Parser`,

        returns self

        :type parser: Parser
        :rtype: ClientKeyExchange
        """
        parser.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_A = bytesToNumber(parser.getVarBytes(2))
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3, 1), (3, 2), (3, 3)):
                self.encryptedPreMasterSecret = parser.getVarBytes(2)
            elif self.version == (3, 0):
                self.encryptedPreMasterSecret = \
                    parser.getFixBytes(parser.getRemainingLength())
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.dhAllSuites:
            self.dh_Yc = bytesToNumber(parser.getVarBytes(2))
        elif self.cipherSuite in CipherSuite.ecdhAllSuites:
            self.ecdh_Yc = parser.getVarBytes(1)
        else:
            raise AssertionError()
        parser.stopLengthCheck()
        return self

    def write(self):
        """
        Serialise the object.

        :rtype: bytearray
        """
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToByteArray(self.srp_A), 1, 2)
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3, 1), (3, 2), (3, 3)):
                w.addVarSeq(self.encryptedPreMasterSecret, 1, 2)
            elif self.version == (3, 0):
                w.bytes += self.encryptedPreMasterSecret
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.dhAllSuites:
            w.addVarSeq(numberToByteArray(self.dh_Yc), 1, 2)
        elif self.cipherSuite in CipherSuite.ecdhAllSuites:
            w.addVarSeq(self.ecdh_Yc, 1, 1)
        else:
            raise AssertionError()
        return self.postWrite(w)


class ClientMasterKey(HandshakeMsg):
    """
    Handling of SSLv2 CLIENT-MASTER-KEY message.

    :vartype cipher: int
    :ivar cipher: negotiated cipher

    :vartype clear_key: bytearray
    :ivar clear_key: the part of master secret key that is sent in clear for
        export cipher suites

    :vartype encrypted_key: bytearray
    :ivar encrypted_key: (part of) master secret encrypted using server key

    :vartype key_argument: bytearray
    :ivar key_argument: additional key argument for block ciphers
    """

    def __init__(self):
        super(ClientMasterKey,
              self).__init__(SSL2HandshakeType.client_master_key)
        self.cipher = 0
        self.clear_key = bytearray(0)
        self.encrypted_key = bytearray(0)
        self.key_argument = bytearray(0)

    def create(self, cipher, clear_key, encrypted_key, key_argument):
        """Set values of the CLIENT-MASTER-KEY object."""
        self.cipher = cipher
        self.clear_key = clear_key
        self.encrypted_key = encrypted_key
        self.key_argument = key_argument
        return self

    def write(self):
        """Serialise the object to on the wire data."""
        writer = Writer()
        writer.add(self.handshakeType, 1)
        writer.add(self.cipher, 3)
        writer.add(len(self.clear_key), 2)
        writer.add(len(self.encrypted_key), 2)
        writer.add(len(self.key_argument), 2)
        writer.bytes += self.clear_key
        writer.bytes += self.encrypted_key
        writer.bytes += self.key_argument
        return writer.bytes

    def parse(self, parser):
        """Deserialise object from on the wire data."""
        self.cipher = parser.get(3)
        clear_key_length = parser.get(2)
        encrypted_key_length = parser.get(2)
        key_argument_length = parser.get(2)
        parser.setLengthCheck(clear_key_length +
                              encrypted_key_length +
                              key_argument_length)
        self.clear_key = parser.getFixBytes(clear_key_length)
        self.encrypted_key = parser.getFixBytes(encrypted_key_length)
        self.key_argument = parser.getFixBytes(key_argument_length)
        parser.stopLengthCheck()
        return self


class CertificateVerify(HandshakeMsg):
    """Serializer for TLS handshake protocol Certificate Verify message."""

    def __init__(self, version):
        """
        Create message.

        :param version: TLS protocol version in use
        """
        HandshakeMsg.__init__(self, HandshakeType.certificate_verify)
        self.version = version
        self.signatureAlgorithm = None
        self.signature = bytearray(0)

    def create(self, signature, signatureAlgorithm=None):
        """
        Provide data for serialisation of message.

        :param signature: signature carried in the message
        :param signatureAlgorithm: signature algorithm used to make the
            signature (TLSv1.2 only)
        """
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
        return self

    def parse(self, parser):
        """
        Deserialize message from parser.

        :param parser: parser with data to read
        """
        parser.startLengthCheck(3)
        if self.version >= (3, 3):
            self.signatureAlgorithm = (parser.get(1), parser.get(1))
        self.signature = parser.getVarBytes(2)
        parser.stopLengthCheck()
        return self

    def write(self):
        """
        Serialize the data to bytearray.

        :rtype: bytearray
        """
        writer = Writer()
        if self.version >= (3, 3):
            writer.add(self.signatureAlgorithm[0], 1)
            writer.add(self.signatureAlgorithm[1], 1)
        writer.addVarSeq(self.signature, 1, 2)
        return self.postWrite(writer)


class ChangeCipherSpec(object):
    def __init__(self):
        self.contentType = ContentType.change_cipher_spec
        self.type = 1

    def create(self):
        self.type = 1
        return self

    def parse(self, p):
        p.setLengthCheck(1)
        self.type = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.type, 1)
        return w.bytes


class NextProtocol(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.next_protocol)
        self.next_proto = None

    def create(self, next_proto):
        self.next_proto = next_proto
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.next_proto = p.getVarBytes(1)
        _ = p.getVarBytes(1)
        p.stopLengthCheck()
        return self

    def write(self, trial=False):
        w = Writer()
        w.addVarSeq(self.next_proto, 1, 1)
        paddingLen = 32 - ((len(self.next_proto) + 2) % 32)
        w.addVarSeq(bytearray(paddingLen), 1, 1)
        return self.postWrite(w)


class Finished(HandshakeMsg):
    def __init__(self, version, hash_length=None):
        HandshakeMsg.__init__(self, HandshakeType.finished)
        self.version = version
        self.verify_data = bytearray(0)
        self.hash_length = hash_length

    def create(self, verify_data):
        self.verify_data = verify_data
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.version == (3, 0):
            self.verify_data = p.getFixBytes(36)
        elif self.version in ((3, 1), (3, 2), (3, 3)):
            self.verify_data = p.getFixBytes(12)
        elif self.version > (3, 3):
            self.verify_data = p.getFixBytes(self.hash_length)
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.bytes += self.verify_data
        return self.postWrite(w)


class EncryptedExtensions(HelloMessage):
    """Handling of the TLS1.3 Encrypted Extensions message."""

    def __init__(self):
        super(EncryptedExtensions, self).__init__(
                HandshakeType.encrypted_extensions)

    def create(self, extensions):
        """Set the extensions in the message."""
        self.extensions = extensions
        return self

    def parse(self, parser):
        """Parse the extensions from on the wire data."""
        parser.startLengthCheck(3)

        if not parser.getRemainingLength():
            raise SyntaxError("No list of extensions")
        else:
            self.extensions = []
            p2 = Parser(parser.getVarBytes(2))
            while p2.getRemainingLength():
                self.extensions.append(TLSExtension(encExt=True).parse(p2))

        parser.stopLengthCheck()
        return self

    def write(self):
        """
        Serialise the message to on the wire data.

        :rtype: bytearray
        """
        w = Writer()
        w2 = Writer()
        for ext in self.extensions:
            w2.bytes += ext.write()

        w.add(len(w2.bytes), 2)
        w.bytes += w2.bytes

        return self.postWrite(w)


class NewSessionTicket(HelloMessage):
    """Handling of the TLS1.3 New Session Ticket message."""

    def __init__(self):
        """Create New Session Ticket object."""
        super(NewSessionTicket, self).__init__(HandshakeType
                                               .new_session_ticket)
        self.ticket_lifetime = 0
        self.ticket_age_add = 0
        self.ticket_nonce = bytearray(0)
        self.ticket = bytearray(0)
        self.extensions = []

    def create(self, ticket_lifetime, ticket_age_add, ticket_nonce, ticket,
               extensions):
        """Initialise a New Session Ticket."""
        self.ticket_lifetime = ticket_lifetime
        self.ticket_age_add = ticket_age_add
        self.ticket_nonce = ticket_nonce
        self.ticket = ticket
        self.extensions = extensions
        return self

    def write(self):
        """
        Serialise the message to on the wire data.

        :rtype: bytearray
        """
        w = Writer()
        w.add(self.ticket_lifetime, 4)
        w.add(self.ticket_age_add, 4)
        w.addVarSeq(self.ticket_nonce, 1, 1)
        w.addVarSeq(self.ticket, 1, 2)
        w2 = Writer()
        for ext in self.extensions:
            w2.bytes += ext.write()
        w.add(len(w2.bytes), 2)
        w.bytes += w2.bytes

        return self.postWrite(w)

    def parse(self, parser):
        """Parse the object from on the wire data."""
        parser.startLengthCheck(3)

        self.ticket_lifetime = parser.get(4)
        self.ticket_age_add = parser.get(4)
        self.ticket_nonce = parser.getVarBytes(1)
        self.ticket = parser.getVarBytes(2)
        self.extensions = []
        ext_parser = Parser(parser.getVarBytes(2))
        while ext_parser.getRemainingLength():
            self.extensions.append(TLSExtension().parse(ext_parser))

        parser.stopLengthCheck()
        return self


class HelloRetryRequest(HelloMessage):
    """Handling of TLS 1.3 Hello Retry Request handshake message."""

    def __init__(self):
        """Create Hello Retry Request object."""
        super(HelloRetryRequest, self).__init__(HandshakeType
                                                .hello_retry_request)
        self.server_version = (0, 0)
        self.cipher_suite = 0
        self.extensions = []

    def create(self, server_version, cipher_suite, extensions):
        """Initialise a Hello Retry Request message."""
        self.server_version = server_version
        self.cipher_suite = cipher_suite
        self.extensions = extensions
        return self

    def write(self):
        """Serialise the object."""
        writer = Writer()
        writer.addFixSeq(self.server_version, 1)
        writer.add(self.cipher_suite, 2)
        w2 = Writer()
        for ext in self.extensions:
            w2.bytes += ext.write()
        writer.add(len(w2.bytes), 2)
        writer.bytes += w2.bytes

        return self.postWrite(writer)

    def parse(self, parser):
        """Deserialise the object from on the wire data."""
        parser.startLengthCheck(3)

        self.server_version = (parser.get(1), parser.get(1))
        self.cipher_suite = parser.get(2)
        self.extensions = []
        ext_parser = Parser(parser.getVarBytes(2))
        while ext_parser.getRemainingLength():
            self.extensions.append(TLSExtension(hrr=True).parse(ext_parser))
        parser.stopLengthCheck()
        return self


class SSL2Finished(HandshakeMsg):
    """Handling of the SSL2 FINISHED messages."""

    def __init__(self, msg_type):
        super(SSL2Finished, self).__init__(msg_type)
        self.verify_data = bytearray(0)

    def create(self, verify_data):
        """Set the message payload."""
        self.verify_data = verify_data
        return self

    def parse(self, parser):
        """Deserialise the message from on the wire data."""
        self.verify_data = parser.getFixBytes(parser.getRemainingLength())
        return self

    def write(self):
        """Serialise the message to on the wire data."""
        writer = Writer()
        writer.add(self.handshakeType, 1)
        writer.bytes += self.verify_data
        # does not use postWrite() as it's a SSLv2 message
        return writer.bytes


class ClientFinished(SSL2Finished):
    """
    Handling of SSLv2 CLIENT-FINISHED message.

    :vartype verify_data: bytearray
    :ivar verify_data: payload of the message, should be the CONNECTION-ID
    """

    def __init__(self):
        super(ClientFinished, self).__init__(SSL2HandshakeType.client_finished)


class ServerFinished(SSL2Finished):
    """
    Handling of SSLv2 SERVER-FINISHED message.

    :vartype verify_data: bytearray
    :ivar verify_data: payload of the message, should be SESSION-ID
    """

    def __init__(self):
        super(ServerFinished, self).__init__(SSL2HandshakeType.server_finished)


class CertificateStatus(HandshakeMsg):
    """
    Handling of the CertificateStatus message from RFC 6066.

    Handling of the handshake protocol message that includes the OCSP staple.

    :vartype status_type: int
    :ivar status_type: type of response returned

    :vartype ocsp: bytearray
    :ivar ocsp: OCSPResponse from RFC 2560
    """

    def __init__(self):
        """Create the objet, set its type."""
        super(CertificateStatus, self).__init__(
                HandshakeType.certificate_status)
        self.status_type = None
        self.ocsp = bytearray()

    def create(self, status_type, ocsp):
        """Set up message payload."""
        self.status_type = status_type
        self.ocsp = ocsp
        return self

    def parse(self, parser):
        """Deserialise the message from one the wire data."""
        parser.startLengthCheck(3)
        self.status_type = parser.get(1)
        self.ocsp = parser.getVarBytes(3)
        parser.stopLengthCheck()
        return self

    def write(self):
        """Serialise the message."""
        writer = Writer()
        writer.add(self.status_type, 1)
        writer.add(len(self.ocsp), 3)
        writer.bytes += self.ocsp
        return self.postWrite(writer)


class ApplicationData(object):
    def __init__(self):
        self.contentType = ContentType.application_data
        self.bytes = bytearray(0)

    def create(self, bytes):
        self.bytes = bytes
        return self

    def splitFirstByte(self):
        newMsg = ApplicationData().create(self.bytes[:1])
        self.bytes = self.bytes[1:]
        return newMsg

    def parse(self, p):
        self.bytes = p.bytes
        return self

    def write(self):
        return self.bytes
