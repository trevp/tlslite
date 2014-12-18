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
from .tlsextension import *

class RecordHeader3(object):
    def __init__(self):
        self.type = 0
        self.version = (0,0)
        self.length = 0
        self.ssl2 = False

    def create(self, version, type, length):
        self.type = type
        self.version = version
        self.length = length
        return self

    def write(self):
        w = Writer()
        w.add(self.type, 1)
        w.add(self.version[0], 1)
        w.add(self.version[1], 1)
        w.add(self.length, 2)
        return w.bytes

    def parse(self, p):
        self.type = p.get(1)
        self.version = (p.get(1), p.get(1))
        self.length = p.get(2)
        self.ssl2 = False
        return self

class RecordHeader2(object):
    def __init__(self):
        self.type = 0
        self.version = (0,0)
        self.length = 0
        self.ssl2 = True

    def parse(self, p):
        if p.get(1)!=128:
            raise SyntaxError()
        self.type = ContentType.handshake
        self.version = (2,0)
        #We don't support 2-byte-length-headers; could be a problem
        self.length = p.get(1)
        return self


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


class HandshakeMsg(object):
    def __init__(self, handshakeType):
        self.contentType = ContentType.handshake
        self.handshakeType = handshakeType
    
    def postWrite(self, w):
        headerWriter = Writer()
        headerWriter.add(self.handshakeType, 1)
        headerWriter.add(len(w.bytes), 3)
        return headerWriter.bytes + w.bytes

class ClientHello(HandshakeMsg):
    """
    Class for handling the ClientHello TLS message, supports both the SSLv2
    and SSLv3 style messages.

    @type certificate_types: list
    @ivar certificate_types: list of supported certificate types (deprecated)

    @type srp_username: bytearray
    @ivar srp_username: name of the user in SRP extension (deprecated)

    @type supports_npn: boolean
    @ivar supports_npn: NPN extension presence (deprecated)

    @type tack: boolean
    @ivar tack: TACK extension presence (deprecated)

    @type server_name: bytearray
    @ivar server_name: first host_name (type 0) present in SNI extension
        (deprecated)

    @type extensions: list of L{TLSExtension}
    @ivar extensions: list of TLS extensions parsed from wire or to send, see
        L{TLSExtension} and child classes for exact examples
    """
    def __init__(self, ssl2=False):
        HandshakeMsg.__init__(self, HandshakeType.client_hello)
        self.ssl2 = ssl2
        self.client_version = (0,0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []         # a list of 16-bit values
        self.compression_methods = []   # a list of 8-bit values
        self.extensions = None

    def get_extension(self, ext_type):
        """
        Returns extension of given type if present, None otherwise

        @rtype: L{tlslite.tlsextension.TLSExtension}
        @raise TLSInternalError: when there are multiple extensions of the
            same type
        """
        if self.extensions is None:
            return None

        exts = [x for x in self.extensions if x.ext_type == ext_type]
        if len(exts) > 1:
            raise TLSInternalError(
                    "Multiple extensions of the same type present")
        elif len(exts) == 1:
            return exts[0]
        else:
            return None

    @property
    def certificate_types(self):
        """
        Returns the list of certificate types supported.

        @deprecated: use extensions field to get the extension for inspection
        """
        cert_type = self.get_extension(ExtensionType.cert_type)
        if cert_type is None:
            # XXX backwards compatibility
            return [CertificateType.x509]
        else:
            return cert_type.cert_types

    @certificate_types.setter
    def certificate_types(self, val):
        """
        Sets the list of supported types to list given in L{val} if the
        cert_type extension is present. Creates the extension and places it
        last in the list otherwise.

        @type val: list
        @param val: list of supported certificate types by client encoded as
            single byte integers
        """
        cert_type = self.get_extension(ExtensionType.cert_type)

        if cert_type is None:
            ext = ClntCertTypeExtension().create(val)
            if self.extensions is None:
                self.extensions = []
            self.extensions += [ext]
        else:
            cert_type.cert_types = val

    @property
    def srp_username(self):
        """
        Returns username for the SRP.

        @deprecated: use extensions field to get the extension for inspection
        """
        srp_ext = self.get_extension(ExtensionType.srp)

        if srp_ext is None:
            return None
        else:
            return srp_ext.identity

    @srp_username.setter
    def srp_username(self, name):
        """
        Sets the username for SRP.

        @type name: bytearray
        @param name: UTF-8 encoded username
        """
        srp_ext = self.get_extension(ExtensionType.srp)

        if srp_ext is None:
            ext = SRPExtension().create(name)
            if self.extensions is None:
                self.extensions = []
            self.extensions += [ext]
        else:
            srp_ext.identity = name

    @property
    def tack(self):
        """
        Returns whatever the client supports TACK

        @rtype: boolean
        @deprecated: use extensions field to get the extension for inspection
        """
        tack_ext = self.get_extension(ExtensionType.tack)

        if tack_ext is None:
            return False
        else:
            return True

    @tack.setter
    def tack(self, present):
        """
        Creates or deletes the TACK extension.

        @type present: boolean
        @param present: True will create extension while False will remove
            extension from client hello
        """
        if present:
            tack_ext = self.get_extension(ExtensionType.tack)
            if tack_ext is None:
                if self.extensions is None:
                    self.extensions = []
                self.extensions += [TLSExtension().create(
                        ExtensionType.tack,
                        bytearray(0))]
            else:
                return
        else:
            if self.extensions is None:
                return
            # remove all extensions of this type without changing reference
            self.extensions[:] = [x for x in self.extensions if
                    x.ext_type != ExtensionType.tack]

    @property
    def supports_npn(self):
        """
        Returns whatever client supports NPN extension

        @rtype: boolean
        @deprecated: use extensions field to get the extension for inspection
        """
        npn_ext = self.get_extension(ExtensionType.supports_npn)

        if npn_ext is None:
            return False
        else:
            return True

    @supports_npn.setter
    def supports_npn(self, present):
        """
        Creates or deletes the NPN extension

        @type present: boolean
        @param present: selects whatever to create or remove the extension
            from list of supported ones
        """
        if present:
            npn_ext = self.get_extension(ExtensionType.supports_npn)
            if npn_ext is None:
                if self.extensions is None:
                    self.extensions = []
                self.extensions += [TLSExtension().create(
                        ExtensionType.supports_npn,
                        bytearray(0))]
            else:
                return
        else:
            if self.extensions is None:
                return
            #remove all extension of this type without changing reference
            self.extensions[:] = [x for x in self.extensions if
                    x.ext_type != ExtensionType.supports_npn]

    @property
    def server_name(self):
        """
        Returns first host_name present in SNI extension

        @rtype: bytearray
        @deprecated: use extensions field to get the extension for inspection
        """
        sni_ext = self.get_extension(ExtensionType.server_name)
        if sni_ext is None:
            return bytearray(0)
        else:
            if len(sni_ext.host_names) > 0:
                return sni_ext.host_names[0]
            else:
                return bytearray(0)

    @server_name.setter
    def server_name(self, hostname):
        """
        Sets the first host_name present in SNI extension

        @type hostname: bytearray
        @param hostname: name of the host_name to set
        """
        sni_ext = self.get_extension(ExtensionType.server_name)
        if sni_ext is None:
            sni_ext = SNIExtension().create(hostname)
            if self.extensions is None:
                self.extensions = []
            self.extensions += [sni_ext]
        else:
            names = sni_ext.host_names
            names[0] = hostname
            sni_ext.host_names = names

    def create(self, version, random, session_id, cipher_suites,
               certificate_types=None, srpUsername=None,
               tack=False, supports_npn=False, serverName=None,
               extensions=None):
        """
        Create a ClientHello message for sending.

        @type version: tuple
        @param version: the highest supported TLS version encoded as two int
            tuple

        @type random: bytearray
        @param random: client provided random value, in old versions of TLS
            (before 1.2) the first 32 bits should include system time

        @type session_id: bytearray
        @param session_id: ID of session, set when doing session resumption

        @type cipher_suites: list
        @param cipher_suites: list of ciphersuites adverties as supported

        @type certificate_types: list
        @param certificate_types: list of supported certificate types, uses
            TLS extension for signalling, as such requires TLS1.0 to work

        @type srpUsername: bytearray
        @param srpUsername: utf-8 encoded username for SRP, TLS extension

        @type tack: boolean
        @param tack: whatever to advertise support for TACK, TLS extension

        @type supports_npn: boolean
        @param supports_npn: whatever to advertise support for NPN, TLS
            extension

        @type serverName: bytearray
        @param serverName: the hostname to request in server name indication
            extension, TLS extension. Note that SNI allows to set multiple
            hostnames and values that are not hostnames, use L{SNIExtension}
            together with L{extensions} to use it.

        @type extensions: list of L{TLSExtension}
        @param extensions: list of extensions to advertise
        """
        self.client_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suites = cipher_suites
        self.compression_methods = [0]
        if not extensions is None:
            self.extensions = extensions
        if not certificate_types is None:
            self.certificate_types = certificate_types
        if not srpUsername is None:
            self.srp_username = bytearray(srpUsername, "utf-8")
        self.tack = tack
        self.supports_npn = supports_npn
        if not serverName is None:
            self.server_name = bytearray(serverName, "utf-8")
        return self

    def parse(self, p):
        if self.ssl2:
            self.client_version = (p.get(1), p.get(1))
            cipherSpecsLength = p.get(2)
            sessionIDLength = p.get(2)
            randomLength = p.get(2)
            self.cipher_suites = p.getFixList(3, cipherSpecsLength//3)
            self.session_id = p.getFixBytes(sessionIDLength)
            self.random = p.getFixBytes(randomLength)
            if len(self.random) < 32:
                zeroBytes = 32-len(self.random)
                self.random = bytearray(zeroBytes) + self.random
            self.compression_methods = [0]#Fake this value

            #We're not doing a stopLengthCheck() for SSLv2, oh well..
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
                while not p.atLengthCheck():
                    ext = TLSExtension().parse(p)
                    self.extensions += [ext]
            p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.client_version[0], 1)
        w.add(self.client_version[1], 1)
        w.addFixSeq(self.random, 1)
        w.addVarSeq(self.session_id, 1, 1)
        w.addVarSeq(self.cipher_suites, 2, 2)
        w.addVarSeq(self.compression_methods, 1, 1)

        if not self.extensions is None:
            w2 = Writer()
            for ext in self.extensions:
                w2.bytes += ext.write()

            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        return self.postWrite(w)

class BadNextProtos(Exception):
    def __init__(self, l):
        self.length = l

    def __str__(self):
        return 'Cannot encode a list of next protocols because it contains an element with invalid length %d. Element lengths must be 0 < x < 256' % self.length

class ServerHello(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello)
        self.server_version = (0,0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suite = 0
        self.certificate_type = CertificateType.x509
        self.compression_method = 0
        self.tackExt = None
        self.next_protos_advertised = None
        self.next_protos = None

    def create(self, version, random, session_id, cipher_suite,
               certificate_type, tackExt, next_protos_advertised):
        self.server_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.certificate_type = certificate_type
        self.compression_method = 0
        self.tackExt = tackExt
        self.next_protos_advertised = next_protos_advertised
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.server_version = (p.get(1), p.get(1))
        self.random = p.getFixBytes(32)
        self.session_id = p.getVarBytes(1)
        self.cipher_suite = p.get(2)
        self.compression_method = p.get(1)
        if not p.atLengthCheck():
            totalExtLength = p.get(2)
            soFar = 0
            while soFar != totalExtLength:
                extType = p.get(2)
                extLength = p.get(2)
                if extType == ExtensionType.cert_type:
                    if extLength != 1:
                        raise SyntaxError()
                    self.certificate_type = p.get(1)
                elif extType == ExtensionType.tack and tackpyLoaded:
                    self.tackExt = TackExtension(p.getFixBytes(extLength))
                elif extType == ExtensionType.supports_npn:
                    self.next_protos = self.__parse_next_protos(p.getFixBytes(extLength))
                else:
                    p.getFixBytes(extLength)
                soFar += 4 + extLength
        p.stopLengthCheck()
        return self

    def __parse_next_protos(self, b):
        protos = []
        while True:
            if len(b) == 0:
                break
            l = b[0]
            b = b[1:]
            if len(b) < l:
                raise BadNextProtos(len(b))
            protos.append(b[:l])
            b = b[l:]
        return protos

    def __next_protos_encoded(self):
        b = bytearray()
        for e in self.next_protos_advertised:
            if len(e) > 255 or len(e) == 0:
                raise BadNextProtos(len(e))
            b += bytearray( [len(e)] ) + bytearray(e)
        return b

    def write(self):
        w = Writer()
        w.add(self.server_version[0], 1)
        w.add(self.server_version[1], 1)
        w.addFixSeq(self.random, 1)
        w.addVarSeq(self.session_id, 1, 1)
        w.add(self.cipher_suite, 2)
        w.add(self.compression_method, 1)

        w2 = Writer() # For Extensions
        if self.certificate_type and self.certificate_type != \
                CertificateType.x509:
            w2.add(ExtensionType.cert_type, 2)
            w2.add(1, 2)
            w2.add(self.certificate_type, 1)
        if self.tackExt:
            b = self.tackExt.serialize()
            w2.add(ExtensionType.tack, 2)
            w2.add(len(b), 2)
            w2.bytes += b
        if self.next_protos_advertised is not None:
            encoded_next_protos_advertised = self.__next_protos_encoded()
            w2.add(ExtensionType.supports_npn, 2)
            w2.add(len(encoded_next_protos_advertised), 2)
            w2.addFixSeq(encoded_next_protos_advertised, 1)
        if len(w2.bytes):
            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes        
        return self.postWrite(w)


class Certificate(HandshakeMsg):
    def __init__(self, certificateType):
        HandshakeMsg.__init__(self, HandshakeType.certificate)
        self.certificateType = certificateType
        self.certChain = None

    def create(self, certChain):
        self.certChain = certChain
        return self

    def parse(self, p):
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
                self.certChain = X509CertChain(certificate_list)
        else:
            raise AssertionError()

        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.certificateType == CertificateType.x509:
            chainLength = 0
            if self.certChain:
                certificate_list = self.certChain.x509List
            else:
                certificate_list = []
            #determine length
            for cert in certificate_list:
                bytes = cert.writeBytes()
                chainLength += len(bytes)+3
            #add bytes
            w.add(chainLength, 3)
            for cert in certificate_list:
                bytes = cert.writeBytes()
                w.addVarSeq(bytes, 1, 3)
        else:
            raise AssertionError()
        return self.postWrite(w)

class CertificateRequest(HandshakeMsg):
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.certificate_request)
        #Apple's Secure Transport library rejects empty certificate_types, so
        #default to rsa_sign.
        self.certificate_types = [ClientCertificateType.rsa_sign]
        self.certificate_authorities = []
        self.version = version
        self.supported_signature_algs = []

    def create(self, certificate_types, certificate_authorities, sig_algs=(), version=(3,0)):
        self.certificate_types = certificate_types
        self.certificate_authorities = certificate_authorities
        self.version = version
        self.supported_signature_algs = sig_algs
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.certificate_types = p.getVarList(1, 1)
        if self.version >= (3,3):
            self.supported_signature_algs = p.getVarList(2, 2)
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
        if self.version >= (3,3):
            w.addVarSeq(self.supported_signature_algs, 2, 2)
        caLength = 0
        #determine length
        for ca_dn in self.certificate_authorities:
            caLength += len(ca_dn)+2
        w.add(caLength, 2)
        #add bytes
        for ca_dn in self.certificate_authorities:
            w.addVarSeq(ca_dn, 1, 2)
        return self.postWrite(w)

class ServerKeyExchange(HandshakeMsg):
    def __init__(self, cipherSuite):
        HandshakeMsg.__init__(self, HandshakeType.server_key_exchange)
        self.cipherSuite = cipherSuite
        self.srp_N = 0
        self.srp_g = 0
        self.srp_s = bytearray(0)
        self.srp_B = 0
        # Anon DH params:
        self.dh_p = 0
        self.dh_g = 0
        self.dh_Ys = 0
        self.signature = bytearray(0)

    def createSRP(self, srp_N, srp_g, srp_s, srp_B):
        self.srp_N = srp_N
        self.srp_g = srp_g
        self.srp_s = srp_s
        self.srp_B = srp_B
        return self
    
    def createDH(self, dh_p, dh_g, dh_Ys):
        self.dh_p = dh_p
        self.dh_g = dh_g
        self.dh_Ys = dh_Ys
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_N = bytesToNumber(p.getVarBytes(2))
            self.srp_g = bytesToNumber(p.getVarBytes(2))
            self.srp_s = p.getVarBytes(1)
            self.srp_B = bytesToNumber(p.getVarBytes(2))
            if self.cipherSuite in CipherSuite.srpCertSuites:
                self.signature = p.getVarBytes(2)
        elif self.cipherSuite in CipherSuite.anonSuites:
            self.dh_p = bytesToNumber(p.getVarBytes(2))
            self.dh_g = bytesToNumber(p.getVarBytes(2))
            self.dh_Ys = bytesToNumber(p.getVarBytes(2))
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToByteArray(self.srp_N), 1, 2)
            w.addVarSeq(numberToByteArray(self.srp_g), 1, 2)
            w.addVarSeq(self.srp_s, 1, 1)
            w.addVarSeq(numberToByteArray(self.srp_B), 1, 2)
            if self.cipherSuite in CipherSuite.srpCertSuites:
                w.addVarSeq(self.signature, 1, 2)
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToByteArray(self.dh_p), 1, 2)
            w.addVarSeq(numberToByteArray(self.dh_g), 1, 2)
            w.addVarSeq(numberToByteArray(self.dh_Ys), 1, 2)
            if self.cipherSuite in []: # TODO support for signed_params
                w.addVarSeq(self.signature, 1, 2)
        return self.postWrite(w)

    def hash(self, clientRandom, serverRandom):
        oldCipherSuite = self.cipherSuite
        self.cipherSuite = None
        try:
            bytes = clientRandom + serverRandom + self.write()[4:]
            return MD5(bytes) + SHA1(bytes)
        finally:
            self.cipherSuite = oldCipherSuite

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

class ClientKeyExchange(HandshakeMsg):
    def __init__(self, cipherSuite, version=None):
        HandshakeMsg.__init__(self, HandshakeType.client_key_exchange)
        self.cipherSuite = cipherSuite
        self.version = version
        self.srp_A = 0
        self.encryptedPreMasterSecret = bytearray(0)

    def createSRP(self, srp_A):
        self.srp_A = srp_A
        return self

    def createRSA(self, encryptedPreMasterSecret):
        self.encryptedPreMasterSecret = encryptedPreMasterSecret
        return self
    
    def createDH(self, dh_Yc):
        self.dh_Yc = dh_Yc
        return self
    
    def parse(self, p):
        p.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_A = bytesToNumber(p.getVarBytes(2))
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3,1), (3,2), (3,3)):
                self.encryptedPreMasterSecret = p.getVarBytes(2)
            elif self.version == (3,0):
                self.encryptedPreMasterSecret = \
                    p.getFixBytes(len(p.bytes)-p.index)
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.anonSuites:
            self.dh_Yc = bytesToNumber(p.getVarBytes(2))            
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToByteArray(self.srp_A), 1, 2)
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3,1), (3,2), (3,3)):
                w.addVarSeq(self.encryptedPreMasterSecret, 1, 2)
            elif self.version == (3,0):
                w.addFixSeq(self.encryptedPreMasterSecret, 1)
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToByteArray(self.dh_Yc), 1, 2)            
        else:
            raise AssertionError()
        return self.postWrite(w)

class CertificateVerify(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.certificate_verify)
        self.signature = bytearray(0)

    def create(self, signature):
        self.signature = signature
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.signature = p.getVarBytes(2)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addVarSeq(self.signature, 1, 2)
        return self.postWrite(w)

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
        w.add(self.type,1)
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
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.finished)
        self.version = version
        self.verify_data = bytearray(0)

    def create(self, verify_data):
        self.verify_data = verify_data
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.version == (3,0):
            self.verify_data = p.getFixBytes(36)
        elif self.version in ((3,1), (3,2), (3,3)):
            self.verify_data = p.getFixBytes(12)
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addFixSeq(self.verify_data, 1)
        return self.postWrite(w)

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
