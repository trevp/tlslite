# Authors: 
#   Trevor Perrin
#   Google - handling CertificateRequest.certificate_types
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

class RecordHeader3:
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

class RecordHeader2:
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


class Alert:
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


class HandshakeMsg:
    def __init__(self, handshakeType):
        self.contentType = ContentType.handshake
        self.handshakeType = handshakeType
    
    def postWrite(self, w):
        headerWriter = Writer()
        headerWriter.add(self.handshakeType, 1)
        headerWriter.add(len(w.bytes), 3)
        return headerWriter.bytes + w.bytes

class ClientHello(HandshakeMsg):
    def __init__(self, ssl2=False):
        HandshakeMsg.__init__(self, HandshakeType.client_hello)
        self.ssl2 = ssl2
        self.client_version = (0,0)
        self.random = createByteArrayZeros(32)
        self.session_id = createByteArraySequence([])
        self.cipher_suites = []         # a list of 16-bit values
        self.certificate_types = [CertificateType.x509]
        self.compression_methods = []   # a list of 8-bit values
        self.srp_username = None        # a string
        self.tack = False

    def create(self, version, random, session_id, cipher_suites,
               certificate_types=None, srp_username=None,
               tack=False):
        self.client_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suites = cipher_suites
        self.certificate_types = certificate_types
        self.compression_methods = [0]
        self.srp_username = srp_username
        self.tack = tack
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
                self.random = createByteArrayZeros(zeroBytes) + self.random
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
                totalExtLength = p.get(2)
                soFar = 0
                while soFar != totalExtLength:
                    extType = p.get(2)
                    extLength = p.get(2)
                    index1 = p.index
                    if extType == ExtensionType.srp:
                        self.srp_username = bytesToString(p.getVarBytes(1))
                    elif extType == ExtensionType.cert_type:
                        self.certificate_types = p.getVarList(1, 1)
                    elif extType == ExtensionType.tack:
                        self.tack = True
                    else:
                        p.getFixBytes(extLength)
                    index2 = p.index
                    if index2 - index1 != extLength:
                        raise SyntaxError("Bad length for extension_data")
                    soFar += 4 + extLength
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

        w2 = Writer() # For Extensions
        if self.certificate_types and self.certificate_types != \
                [CertificateType.x509]:
            w2.add(ExtensionType.cert_type, 2)
            w2.add(len(self.certificate_types)+1, 2)
            w2.addVarSeq(self.certificate_types, 1, 1)
        if self.srp_username:
            w2.add(ExtensionType.srp, 2)
            w2.add(len(self.srp_username)+1, 2)
            w2.addVarSeq(stringToBytes(self.srp_username), 1, 1)
        if self.tack:
            w2.add(ExtensionType.tack, 2)
            w2.add(0, 2)
        if len(w2.bytes):
            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        return self.postWrite(w)

class ServerHello(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello)
        self.server_version = (0,0)
        self.random = createByteArrayZeros(32)
        self.session_id = createByteArraySequence([])
        self.cipher_suite = 0
        self.certificate_type = CertificateType.x509
        self.compression_method = 0
        self.tackExt = None 

    def create(self, version, random, session_id, cipher_suite,
               certificate_type, tackExt):
        self.server_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.certificate_type = certificate_type
        self.compression_method = 0
        self.tackExt = tackExt
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
                    self.tackExt = TACK_Extension()
                    self.tackExt.parse(p.getFixBytes(extLength))
                else:
                    p.getFixBytes(extLength)
                soFar += 4 + extLength
        p.stopLengthCheck()
        return self

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
            b = self.tackExt.write()
            w2.add(ExtensionType.tack, 2)
            w2.add(len(b), 2)
            w2.bytes += b
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
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.certificate_request)
        #Apple's Secure Transport library rejects empty certificate_types, so
        #default to rsa_sign.
        self.certificate_types = [ClientCertificateType.rsa_sign]
        self.certificate_authorities = []

    def create(self, certificate_types, certificate_authorities):
        self.certificate_types = certificate_types
        self.certificate_authorities = certificate_authorities
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.certificate_types = p.getVarList(1, 1)
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
        self.srp_N = 0L
        self.srp_g = 0L
        self.srp_s = createByteArraySequence([])
        self.srp_B = 0L
        self.dh_p = 0L
        self.dh_g = 0L
        self.dh_Ys = 0L
        self.rsa_modulus = 0L
        self.rsa_exponent = 0L        
        self.signature = createByteArraySequence([])

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
        if self.cipherSuite in CipherSuite.srpSuites + \
                CipherSuite.srpCertSuites:
            self.srp_N = bytesToNumber(p.getVarBytes(2))
            self.srp_g = bytesToNumber(p.getVarBytes(2))
            self.srp_s = p.getVarBytes(1)
            self.srp_B = bytesToNumber(p.getVarBytes(2))
            if self.cipherSuite in CipherSuite.srpCertSuites:
                self.signature = p.getVarBytes(2)
        elif self.cipherSuite in CipherSuite.certSuites:
            self.rsa_modulus = bytesToNumber(p.getVarBytes(2))
            self.rsa_exponent = bytesToNumber(p.getVarBytes(2))
        elif self.cipherSuite in CipherSuite.anonSuites:
            self.dh_p = bytesToNumber(p.getVarBytes(2))
            self.dh_g = bytesToNumber(p.getVarBytes(2))
            self.dh_Ys = bytesToNumber(p.getVarBytes(2))
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToBytes(self.srp_N), 1, 2)
            w.addVarSeq(numberToBytes(self.srp_g), 1, 2)
            w.addVarSeq(self.srp_s, 1, 1)
            w.addVarSeq(numberToBytes(self.srp_B), 1, 2)
            if self.cipherSuite in CipherSuite.srpCertSuites:
                w.addVarSeq(self.signature, 1, 2)
        elif self.cipherSuite in CipherSuite.certSuites:
            w.addVarSeq(numberToBytes(self.rsa_modulus), 1, 2)
            w.addVarSeq(numberToBytes(self.rsa_exponent), 1, 2)
            if self.cipherSuite in []: # TODO support for signed_params
                w.addVarSeq(self.signature, 1, 2)
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToBytes(self.dh_p), 1, 2)
            w.addVarSeq(numberToBytes(self.dh_g), 1, 2)
            w.addVarSeq(numberToBytes(self.dh_Ys), 1, 2)
            if self.cipherSuite in []: # TODO support for signed_params
                w.addVarSeq(self.signature, 1, 2)
        return self.postWrite(w)

    def hash(self, clientRandom, serverRandom):
        oldCipherSuite = self.cipherSuite
        self.cipherSuite = None
        try:
            bytes = clientRandom + serverRandom + self.write()[4:]
            s = bytesToString(bytes)
            return stringToBytes(md5(s).digest() + sha1(s).digest())
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
        self.encryptedPreMasterSecret = createByteArraySequence([])

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
            if self.version in ((3,1), (3,2)):
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
            w.addVarSeq(numberToBytes(self.srp_A), 1, 2)
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3,1), (3,2)):
                w.addVarSeq(self.encryptedPreMasterSecret, 1, 2)
            elif self.version == (3,0):
                w.addFixSeq(self.encryptedPreMasterSecret, 1)
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToBytes(self.dh_Yc), 1, 2)            
        else:
            raise AssertionError()
        return self.postWrite(w)

class CertificateVerify(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.certificate_verify)
        self.signature = createByteArraySequence([])

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

class ChangeCipherSpec:
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


class Finished(HandshakeMsg):
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.finished)
        self.version = version
        self.verify_data = createByteArraySequence([])

    def create(self, verify_data):
        self.verify_data = verify_data
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.version == (3,0):
            self.verify_data = p.getFixBytes(36)
        elif self.version in ((3,1), (3,2)):
            self.verify_data = p.getFixBytes(12)
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addFixSeq(self.verify_data, 1)
        return self.postWrite(w)

class ApplicationData:
    def __init__(self):
        self.contentType = ContentType.application_data
        self.bytes = createByteArraySequence([])

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