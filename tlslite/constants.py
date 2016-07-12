# Authors: 
#   Trevor Perrin
#   Google - defining ClientCertificateType
#   Google (adapted by Sam Rushing) - NPN support
#   Dimitris Moraitis - Anon ciphersuites
#   Dave Baggett (Arcode Corporation) - canonicalCipherName
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#
# See the LICENSE file for legal information regarding use of this file.

"""Constants used in various places."""

class TLSEnum(object):
    """Base class for different enums of TLS IDs"""

    @classmethod
    def _recursiveVars(cls, klass):
        """Call vars recursively on base classes"""
        fields = dict()
        for basecls in klass.__bases__:
            fields.update(cls._recursiveVars(basecls))
        fields.update(dict(vars(klass)))
        return fields

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """
        Convert numeric type to string representation

        name if found, None otherwise
        """
        fields = cls._recursiveVars(cls)
        if blacklist is None:
            blacklist = []
        return next((key for key, val in fields.items() \
                    if key not in ('__weakref__', '__dict__', '__doc__',
                                   '__module__') and \
                       key not in blacklist and \
                        val == value), None)

    @classmethod
    def toStr(cls, value, blacklist=None):
        """Convert numeric type to human-readable string if possible"""
        ret = cls.toRepr(value, blacklist)
        if ret is not None:
            return ret
        else:
            return '{0}'.format(value)

class CertificateType:
    x509 = 0
    openpgp = 1

class ClientCertificateType:
    rsa_sign = 1
    dss_sign = 2
    rsa_fixed_dh = 3
    dss_fixed_dh = 4

class SSL2HandshakeType(TLSEnum):
    """SSL2 Handshake Protocol message types"""
    error = 0
    client_hello = 1
    client_master_key = 2
    client_finished = 3
    server_hello = 4
    server_verify = 5
    server_finished = 6
    request_certificate = 7
    client_certificate = 8


class SSL2ErrorDescription(TLSEnum):
    """SSL2 Handshake protocol error message descriptions"""

    no_cipher = 0x0001
    no_certificate = 0x0002
    bad_certificate = 0x0004
    unsupported_certificate_type = 0x0006


class HandshakeType(TLSEnum):
    """Message types in TLS Handshake protocol"""

    hello_request = 0
    client_hello = 1
    server_hello = 2
    certificate = 11
    server_key_exchange = 12
    certificate_request = 13
    server_hello_done = 14
    certificate_verify = 15
    client_key_exchange = 16
    finished = 20
    next_protocol = 67

class ContentType(TLSEnum):
    """TLS record layer content types of payloads"""

    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    all = (20, 21, 22, 23)

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """Convert numeric type to name representation"""
        if blacklist is None:
            blacklist = []
        blacklist.append('all')
        return super(ContentType, cls).toRepr(value, blacklist)

class ExtensionType:    # RFC 6066 / 4366
    server_name = 0     # RFC 6066 / 4366
    cert_type = 9       # RFC 6091
    supported_groups = 10 # RFC 4492, RFC-ietf-tls-negotiated-ff-dhe-10
    ec_point_formats = 11 # RFC 4492
    srp = 12            # RFC 5054
    signature_algorithms = 13 # RFC 5246
    client_hello_padding = 21 # RFC 7685
    encrypt_then_mac = 22 # RFC 7366
    extended_master_secret = 23 # RFC 7627
    tack = 0xF300
    supports_npn = 13172
    renegotiation_info = 0xff01

class HashAlgorithm(TLSEnum):
    """Hash algorithm IDs used in TLSv1.2"""

    none = 0
    md5 = 1
    sha1 = 2
    sha224 = 3
    sha256 = 4
    sha384 = 5
    sha512 = 6

class SignatureAlgorithm(TLSEnum):
    """Signing algorithms used in TLSv1.2"""

    anonymous = 0
    rsa = 1
    dsa = 2
    ecdsa = 3

class GroupName(TLSEnum):
    """Name of groups supported for (EC)DH key exchange"""

    # RFC4492
    sect163k1 = 1
    sect163r1 = 2
    sect163r2 = 3
    sect193r1 = 4
    sect193r2 = 5
    sect233k1 = 6
    sect233r1 = 7
    sect239k1 = 8
    sect283k1 = 9
    sect283r1 = 10
    sect409k1 = 11
    sect409r1 = 12
    sect571k1 = 13
    sect571r1 = 14
    secp160k1 = 15
    secp160r1 = 16
    secp160r2 = 17
    secp192k1 = 18
    secp192r1 = 19
    secp224k1 = 20
    secp224r1 = 21
    secp256k1 = 22
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    allEC = list(range(1, 26))

    # RFC7027
    brainpoolP256r1 = 26
    brainpoolP384r1 = 27
    brainpoolP512r1 = 28
    allEC.extend(list(range(26, 29)))

    # RFC-ietf-tls-negotiated-ff-dhe-10
    ffdhe2048 = 256
    ffdhe3072 = 257
    ffdhe4096 = 258
    ffdhe6144 = 259
    ffdhe8192 = 260
    allFF = list(range(256, 261))

    all = allEC + allFF

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """Convert numeric type to name representation"""
        if blacklist is None:
            blacklist = []
        blacklist += ['all', 'allEC', 'allFF']
        return super(GroupName, cls).toRepr(value, blacklist)

class ECPointFormat(object):

    """Names and ID's of supported EC point formats"""

    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2

    all = [uncompressed,
           ansiX962_compressed_prime,
           ansiX962_compressed_char2]

class ECCurveType(TLSEnum):
    """Types of ECC curves supported in TLS from RFC4492"""

    explicit_prime = 1
    explicit_char2 = 2
    named_curve = 3

class NameType:
    host_name = 0

class AlertLevel(TLSEnum):
    """Enumeration of TLS Alert protocol levels"""

    warning = 1
    fatal = 2

class AlertDescription(TLSEnum):
    """
    @cvar bad_record_mac: A TLS record failed to decrypt properly.

    If this occurs during a SRP handshake it most likely
    indicates a bad password.  It may also indicate an implementation
    error, or some tampering with the data in transit.

    This alert will be signalled by the server if the SRP password is bad.  It
    may also be signalled by the server if the SRP username is unknown to the
    server, but it doesn't wish to reveal that fact.


    @cvar handshake_failure: A problem occurred while handshaking.

    This typically indicates a lack of common ciphersuites between client and
    server, or some other disagreement (about SRP parameters or key sizes,
    for example).

    @cvar protocol_version: The other party's SSL/TLS version was unacceptable.

    This indicates that the client and server couldn't agree on which version
    of SSL or TLS to use.

    @cvar user_canceled: The handshake is being cancelled for some reason.

    """

    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    decryption_failed = 21
    record_overflow = 22
    decompression_failure = 30
    handshake_failure = 40
    no_certificate = 41 #SSLv3
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    export_restriction = 60
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    no_renegotiation = 100
    unsupported_extension = 110  # RFC 5246
    unrecognized_name = 112  # RFC 6066
    unknown_psk_identity = 115


class CipherSuite:

    """
    Numeric values of ciphersuites and ciphersuite types

    @cvar tripleDESSuites: ciphersuties which use 3DES symmetric cipher in CBC
    mode
    @cvar aes128Suites: ciphersuites which use AES symmetric cipher in CBC mode
    with 128 bit key
    @cvar aes256Suites: ciphersuites which use AES symmetric cipher in CBC mode
    with 128 bit key
    @cvar rc4Suites: ciphersuites which use RC4 symmetric cipher with 128 bit
    key
    @cvar shaSuites: ciphersuites which use SHA-1 HMAC integrity mechanism
    and protocol default Pseudo Random Function
    @cvar sha256Suites: ciphersuites which use SHA-256 HMAC integrity mechanism
    and SHA-256 Pseudo Random Function
    @cvar md5Suites: ciphersuites which use MD-5 HMAC integrity mechanism and
    protocol default Pseudo Random Function
    @cvar srpSuites: ciphersuites which use Secure Remote Password (SRP) key
    exchange protocol
    @cvar srpCertSuites: ciphersuites which use Secure Remote Password (SRP)
    key exchange protocol with RSA server authentication
    @cvar srpAllSuites: all SRP ciphersuites, pure SRP and with RSA based
    server authentication
    @cvar certSuites: ciphersuites which use RSA key exchange with RSA server
    authentication
    @cvar certAllSuites: ciphersuites which use RSA server authentication
    @cvar anonSuites: ciphersuites which use anonymous Finite Field
    Diffie-Hellman key exchange
    @cvar ietfNames: dictionary with string names of the ciphersuites
    """

    ietfNames = {}

# the ciphesuite names come from IETF, we want to keep them
#pylint: disable = invalid-name

    # SSLv2 from draft-hickman-netscape-ssl-00.txt
    SSL_CK_RC4_128_WITH_MD5 = 0x010080
    ietfNames[0x010080] = 'SSL_CK_RC4_128_WITH_MD5'
    SSL_CK_RC4_128_EXPORT40_WITH_MD5 = 0x020080
    ietfNames[0x020080] = 'SSL_CK_RC4_128_EXPORT40_WITH_MD5'
    SSL_CK_RC2_128_CBC_WITH_MD5 = 0x030080
    ietfNames[0x030080] = 'SSL_CK_RC2_128_CBC_WITH_MD5'
    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080
    ietfNames[0x040080] = 'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5'
    SSL_CK_IDEA_128_CBC_WITH_MD5 = 0x050080
    ietfNames[0x050080] = 'SSL_CK_IDEA_128_CBC_WITH_MD5'
    SSL_CK_DES_64_CBC_WITH_MD5 = 0x060040
    ietfNames[0x060040] = 'SSL_CK_DES_64_CBC_WITH_MD5'
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5 = 0x0700C0
    ietfNames[0x0700C0] = 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5'

    # SSL2 ciphersuites which use RC4 symmetric cipher
    ssl2rc4 = []
    ssl2rc4.append(SSL_CK_RC4_128_WITH_MD5)
    ssl2rc4.append(SSL_CK_RC4_128_EXPORT40_WITH_MD5)

    # SSL2 ciphersuites which use RC2 symmetric cipher
    ssl2rc2 = []
    ssl2rc2.append(SSL_CK_RC2_128_CBC_WITH_MD5)
    ssl2rc2.append(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)

    # SSL2 ciphersuites which use IDEA symmetric cipher
    ssl2idea = [SSL_CK_IDEA_128_CBC_WITH_MD5]

    # SSL2 ciphersuites which use (single) DES symmetric cipher
    ssl2des = [SSL_CK_DES_64_CBC_WITH_MD5]

    # SSL2 ciphersuites which use 3DES symmetric cipher
    ssl2_3des = [SSL_CK_DES_192_EDE3_CBC_WITH_MD5]

    # SSL2 ciphersuites which encrypt only part (40 bits) of the key
    ssl2export = []
    ssl2export.append(SSL_CK_RC4_128_EXPORT40_WITH_MD5)
    ssl2export.append(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)

    # SSL2 ciphersuties which use 128 bit key
    ssl2_128Key = []
    ssl2_128Key.append(SSL_CK_RC4_128_WITH_MD5)
    ssl2_128Key.append(SSL_CK_RC4_128_EXPORT40_WITH_MD5)
    ssl2_128Key.append(SSL_CK_RC2_128_CBC_WITH_MD5)
    ssl2_128Key.append(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)
    ssl2_128Key.append(SSL_CK_IDEA_128_CBC_WITH_MD5)

    # SSL2 ciphersuites which use 64 bit key
    ssl2_64Key = [SSL_CK_DES_64_CBC_WITH_MD5]

    # SSL2 ciphersuites which use 192 bit key
    ssl2_192Key = [SSL_CK_DES_192_EDE3_CBC_WITH_MD5]

    # Weird pseudo-ciphersuite from RFC 5746
    # Signals that "secure renegotiation" is supported
    # We actually don't do any renegotiation, but this
    # prevents renegotiation attacks
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
    ietfNames[0x00FF] = 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'

    # RFC 7507 - Fallback Signaling Cipher Suite Value for Preventing Protocol
    # Downgrade Attacks
    TLS_FALLBACK_SCSV = 0x5600
    ietfNames[0x5600] = 'TLS_FALLBACK_SCSV'

    # RFC 5054 - Secure Remote Password (SRP) Protocol for TLS Authentication
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA  = 0xC01A
    ietfNames[0xC01A] = 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA'
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D
    ietfNames[0xC01D] = 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA'
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020
    ietfNames[0xC020] = 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA'

    # RFC 5054 - Secure Remote Password (SRP) Protocol for TLS Authentication
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B
    ietfNames[0xC01B] = 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E
    ietfNames[0xC01E] = 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021
    ietfNames[0xC021] = 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'

    # RFC 5246 - TLS v1.2 Protocol
    TLS_RSA_WITH_NULL_MD5 = 0x0001
    ietfNames[0x0001] = 'TLS_RSA_WITH_NULL_MD5'
    TLS_RSA_WITH_NULL_SHA = 0x0002
    ietfNames[0x0002] = 'TLS_RSA_WITH_NULL_SHA'
    TLS_RSA_WITH_NULL_SHA256 = 0x003B
    ietfNames[0x003B] = 'TLS_RSA_WITH_NULL_SHA256'

    # RFC 5246 - TLS v1.2 Protocol
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
    ietfNames[0x000A] = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    ietfNames[0x002F] = 'TLS_RSA_WITH_AES_128_CBC_SHA'
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    ietfNames[0x0035] = 'TLS_RSA_WITH_AES_256_CBC_SHA'
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    ietfNames[0x0005] = 'TLS_RSA_WITH_RC4_128_SHA'

    # RFC 5246 - TLS v1.2 Protocol
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004
    ietfNames[0x0004] = 'TLS_RSA_WITH_RC4_128_MD5'

    # RFC 5246 - TLS v1.2 Protocol
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    ietfNames[0x0016] = 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    ietfNames[0x0033] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    ietfNames[0x0039] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'

    # RFC 5246 - TLS v1.2 Protocol
    TLS_DH_ANON_WITH_RC4_128_MD5 = 0x0018
    ietfNames[0x0018] = 'TLS_DH_ANON_WITH_RC4_128_MD5'
    TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA = 0x001B
    ietfNames[0x001B] = 'TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA'
    TLS_DH_ANON_WITH_AES_128_CBC_SHA = 0x0034
    ietfNames[0x0034] = 'TLS_DH_ANON_WITH_AES_128_CBC_SHA'
    TLS_DH_ANON_WITH_AES_256_CBC_SHA = 0x003A
    ietfNames[0x003A] = 'TLS_DH_ANON_WITH_AES_256_CBC_SHA'
    TLS_DH_ANON_WITH_AES_128_CBC_SHA256 = 0x006C
    ietfNames[0x006C] = 'TLS_DH_ANON_WITH_AES_128_CBC_SHA256'
    TLS_DH_ANON_WITH_AES_256_CBC_SHA256 = 0x006D
    ietfNames[0x006D] = 'TLS_DH_ANON_WITH_AES_256_CBC_SHA256'
    TLS_DH_ANON_WITH_AES_128_GCM_SHA256 = 0x00A6
    ietfNames[0x00A6] = 'TLS_DH_ANON_WITH_AES_128_GCM_SHA256'
    TLS_DH_ANON_WITH_AES_256_GCM_SHA384 = 0x00A7
    ietfNames[0x00A7] = 'TLS_DH_ANON_WITH_AES_256_GCM_SHA384'

    # RFC 5246 - TLS v1.2 Protocol
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
    ietfNames[0x003C] = 'TLS_RSA_WITH_AES_128_CBC_SHA256'
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D
    ietfNames[0x003D] = 'TLS_RSA_WITH_AES_256_CBC_SHA256'

    # RFC 5246 - TLS v1.2
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    ietfNames[0x0067] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B
    ietfNames[0x006B] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'

    # RFC 5288 - AES-GCM ciphers for TLSv1.2
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    ietfNames[0x009C] = 'TLS_RSA_WITH_AES_128_GCM_SHA256'
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E
    ietfNames[0x009E] = 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
    ietfNames[0x009D] = 'TLS_RSA_WITH_AES_256_GCM_SHA384'
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F
    ietfNames[0x009F] = 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'

    # RFC 4492 - ECC Cipher Suites for TLS
    TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010
    ietfNames[0xC010] = 'TLS_ECDHE_RSA_WITH_NULL_SHA'
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
    ietfNames[0xC013] = 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
    ietfNames[0xC014] = 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    TLS_ECDH_ANON_WITH_NULL_SHA = 0xC015
    ietfNames[0xC015] = 'TLS_ECDH_ANON_WITH_NULL_SHA'
    TLS_ECDH_ANON_WITH_RC4_128_SHA = 0xC016
    ietfNames[0xC016] = 'TLS_ECDH_ANON_WITH_RC4_128_SHA'
    TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA = 0xC017
    ietfNames[0xC017] = 'TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA'
    TLS_ECDH_ANON_WITH_AES_128_CBC_SHA = 0xC018
    ietfNames[0xC018] = 'TLS_ECDH_ANON_WITH_AES_128_CBC_SHA'
    TLS_ECDH_ANON_WITH_AES_256_CBC_SHA = 0xC019
    ietfNames[0xC019] = 'TLS_ECDH_ANON_WITH_AES_256_CBC_SHA'

    # draft-ietf-tls-chacha20-poly1305-00
    # ChaCha20/Poly1305 based Cipher Suites for TLS1.2
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305 = 0xcca3
    ietfNames[0xcca3] = 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305'


    # RFC 5289 - ECC Ciphers with SHA-256/SHA284 HMAC and AES-GCM
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
    ietfNames[0xC027] = 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
    ietfNames[0xC028] = 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
    ietfNames[0xC02F] = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
    ietfNames[0xC030] = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'

#pylint: enable = invalid-name
    #
    # Define cipher suite families below
    #

    # 3DES CBC ciphers
    tripleDESSuites = []
    tripleDESSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA)

    # AES-128 CBC ciphers
    aes128Suites = []
    aes128Suites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_ECDH_ANON_WITH_AES_128_CBC_SHA)

    # AES-256 CBC ciphers
    aes256Suites = []
    aes256Suites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
    aes256Suites.append(TLS_ECDH_ANON_WITH_AES_256_CBC_SHA)

    # AES-128 GCM ciphers
    aes128GcmSuites = []
    aes128GcmSuites.append(TLS_RSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_DH_ANON_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

    # AES-256-GCM ciphers (implicit SHA384, see sha384PrfSuites)
    aes256GcmSuites = []
    aes256GcmSuites.append(TLS_RSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_DH_ANON_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)

    # CHACHA20 cipher (implicit POLY1305 authenticator)
    chacha20Suites = []
    chacha20Suites.append(TLS_DHE_RSA_WITH_CHACHA20_POLY1305)

    # RC4 128 stream cipher
    rc4Suites = []
    rc4Suites.append(TLS_DH_ANON_WITH_RC4_128_MD5)
    rc4Suites.append(TLS_RSA_WITH_RC4_128_SHA)
    rc4Suites.append(TLS_RSA_WITH_RC4_128_MD5)
    rc4Suites.append(TLS_ECDH_ANON_WITH_RC4_128_SHA)

    # no encryption
    nullSuites = []
    nullSuites.append(TLS_RSA_WITH_NULL_MD5)
    nullSuites.append(TLS_RSA_WITH_NULL_SHA)
    nullSuites.append(TLS_RSA_WITH_NULL_SHA256)
    nullSuites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)
    nullSuites.append(TLS_ECDH_ANON_WITH_NULL_SHA)

    # SHA-1 HMAC, protocol default PRF
    shaSuites = []
    shaSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_RC4_128_SHA)
    shaSuites.append(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_NULL_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_RC4_128_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_NULL_SHA)

    # SHA-256 HMAC, SHA-256 PRF
    sha256Suites = []
    sha256Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    sha256Suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    sha256Suites.append(TLS_RSA_WITH_NULL_SHA256)
    sha256Suites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA256)
    sha256Suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)

    # SHA-384 HMAC, SHA-384 PRF
    sha384Suites = []
    sha384Suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)

    # stream cipher construction
    streamSuites = []
    streamSuites.extend(rc4Suites)
    streamSuites.extend(nullSuites)

    # AEAD integrity, any PRF
    aeadSuites = []
    aeadSuites.extend(aes128GcmSuites)
    aeadSuites.extend(aes256GcmSuites)
    aeadSuites.extend(chacha20Suites)

    # TLS1.2 with SHA384 PRF
    sha384PrfSuites = []
    sha384PrfSuites.extend(sha384Suites)
    sha384PrfSuites.extend(aes256GcmSuites)

    # MD-5 HMAC, protocol default PRF
    md5Suites = []
    md5Suites.append(TLS_DH_ANON_WITH_RC4_128_MD5)
    md5Suites.append(TLS_RSA_WITH_RC4_128_MD5)
    md5Suites.append(TLS_RSA_WITH_NULL_MD5)

    # SSL3, TLS1.0, TLS1.1 and TLS1.2 compatible ciphers
    ssl3Suites = []
    ssl3Suites.extend(shaSuites)
    ssl3Suites.extend(md5Suites)

    # TLS1.2 specific ciphersuites
    tls12Suites = []
    tls12Suites.extend(sha256Suites)
    tls12Suites.extend(sha384Suites)
    tls12Suites.extend(aeadSuites)

    @staticmethod
    def filterForVersion(suites, minVersion, maxVersion):
        """Return a copy of suites without ciphers incompatible with version"""
        includeSuites = set([])
        if (3, 0) <= minVersion <= (3, 3):
            includeSuites.update(CipherSuite.ssl3Suites)
        if maxVersion == (3, 3):
            includeSuites.update(CipherSuite.tls12Suites)
        return [s for s in suites if s in includeSuites]

    @staticmethod
    def _filterSuites(suites, settings, version=None):
        if version is None:
            version = settings.maxVersion
        macNames = settings.macNames
        cipherNames = settings.cipherNames
        keyExchangeNames = settings.keyExchangeNames
        macSuites = []
        if "sha" in macNames:
            macSuites += CipherSuite.shaSuites
        if "sha256" in macNames and version >= (3, 3):
            macSuites += CipherSuite.sha256Suites
        if "sha384" in macNames and version >= (3, 3):
            macSuites += CipherSuite.sha384Suites
        if "md5" in macNames:
            macSuites += CipherSuite.md5Suites
        if "aead" in macNames and version >= (3, 3):
            macSuites += CipherSuite.aeadSuites

        cipherSuites = []
        if "chacha20-poly1305" in cipherNames and version >= (3, 3):
            cipherSuites += CipherSuite.chacha20Suites
        if "aes128gcm" in cipherNames and version >= (3, 3):
            cipherSuites += CipherSuite.aes128GcmSuites
        if "aes256gcm" in cipherNames and version >= (3, 3):
            cipherSuites += CipherSuite.aes256GcmSuites
        if "aes128" in cipherNames:
            cipherSuites += CipherSuite.aes128Suites
        if "aes256" in cipherNames:
            cipherSuites += CipherSuite.aes256Suites
        if "3des" in cipherNames:
            cipherSuites += CipherSuite.tripleDESSuites
        if "rc4" in cipherNames:
            cipherSuites += CipherSuite.rc4Suites
        if "null" in cipherNames:
            cipherSuites += CipherSuite.nullSuites

        keyExchangeSuites = []
        if "rsa" in keyExchangeNames:
            keyExchangeSuites += CipherSuite.certSuites
        if "dhe_rsa" in keyExchangeNames:
            keyExchangeSuites += CipherSuite.dheCertSuites
        if "ecdhe_rsa" in keyExchangeNames:
            keyExchangeSuites += CipherSuite.ecdheCertSuites
        if "srp_sha" in keyExchangeNames:
            keyExchangeSuites += CipherSuite.srpSuites
        if "srp_sha_rsa" in keyExchangeNames:
            keyExchangeSuites += CipherSuite.srpCertSuites
        if "dh_anon" in keyExchangeNames:
            keyExchangeSuites += CipherSuite.anonSuites
        if "ecdh_anon" in keyExchangeNames:
            keyExchangeSuites += CipherSuite.ecdhAnonSuites

        return [s for s in suites if s in macSuites and
                s in cipherSuites and s in keyExchangeSuites]

    # SRP key exchange
    srpSuites = []
    srpSuites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    srpSuites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    srpSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)

    @classmethod
    def getSrpSuites(cls, settings, version=None):
        """Return SRP cipher suites matching settings"""
        return cls._filterSuites(CipherSuite.srpSuites, settings, version)

    # SRP key exchange, RSA authentication
    srpCertSuites = []
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)

    @classmethod
    def getSrpCertSuites(cls, settings, version=None):
        """Return SRP cipher suites that use server certificates"""
        return cls._filterSuites(CipherSuite.srpCertSuites, settings, version)

    srpAllSuites = srpSuites + srpCertSuites

    @classmethod
    def getSrpAllSuites(cls, settings, version=None):
        """Return all SRP cipher suites matching settings"""
        return cls._filterSuites(CipherSuite.srpAllSuites, settings, version)

    # RSA key exchange, RSA authentication
    certSuites = []
    certSuites.append(TLS_RSA_WITH_AES_256_GCM_SHA384)
    certSuites.append(TLS_RSA_WITH_AES_128_GCM_SHA256)
    certSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    certSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    certSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_RC4_128_SHA)
    certSuites.append(TLS_RSA_WITH_RC4_128_MD5)
    certSuites.append(TLS_RSA_WITH_NULL_MD5)
    certSuites.append(TLS_RSA_WITH_NULL_SHA)
    certSuites.append(TLS_RSA_WITH_NULL_SHA256)

    @classmethod
    def getCertSuites(cls, settings, version=None):
        """Return ciphers with RSA authentication matching settings"""
        return cls._filterSuites(CipherSuite.certSuites, settings, version)

    # FFDHE key exchange, RSA authentication
    dheCertSuites = []
    dheCertSuites.append(TLS_DHE_RSA_WITH_CHACHA20_POLY1305)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    dheCertSuites.append(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)

    @classmethod
    def getDheCertSuites(cls, settings, version=None):
        """Provide authenticated DHE ciphersuites matching settings"""
        return cls._filterSuites(CipherSuite.dheCertSuites, settings, version)

    # ECDHE key exchange, RSA authentication
    ecdheCertSuites = []
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)

    @classmethod
    def getEcdheCertSuites(cls, settings, version=None):
        """Provide authenticated ECDHE ciphersuites matching settings"""
        return cls._filterSuites(CipherSuite.ecdheCertSuites, settings, version)

    # RSA authentication
    certAllSuites = srpCertSuites + certSuites + dheCertSuites + ecdheCertSuites

    # anon FFDHE key exchange
    anonSuites = []
    anonSuites.append(TLS_DH_ANON_WITH_AES_256_GCM_SHA384)
    anonSuites.append(TLS_DH_ANON_WITH_AES_128_GCM_SHA256)
    anonSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA256)
    anonSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)
    anonSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA256)
    anonSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    anonSuites.append(TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA)
    anonSuites.append(TLS_DH_ANON_WITH_RC4_128_MD5)

    @classmethod
    def getAnonSuites(cls, settings, version=None):
        """Provide anonymous DH ciphersuites matching settings"""
        return cls._filterSuites(CipherSuite.anonSuites, settings, version)

    dhAllSuites = dheCertSuites + anonSuites

    # anon ECDHE key exchange
    ecdhAnonSuites = []
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_AES_256_CBC_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_AES_128_CBC_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_RC4_128_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_NULL_SHA)

    @classmethod
    def getEcdhAnonSuites(cls, settings, version=None):
        """Provide anonymous ECDH ciphersuites matching settings"""
        return cls._filterSuites(CipherSuite.ecdhAnonSuites, settings, version)

    ecdhAllSuites = ecdheCertSuites + ecdhAnonSuites

    @staticmethod
    def canonicalCipherName(ciphersuite):
        """Return the canonical name of the cipher whose number is provided."""
        if ciphersuite in CipherSuite.aes128GcmSuites:
            return "aes128gcm"
        elif ciphersuite in CipherSuite.aes256GcmSuites:
            return "aes256gcm"
        elif ciphersuite in CipherSuite.aes128Suites:
            return "aes128"
        elif ciphersuite in CipherSuite.aes256Suites:
            return "aes256"
        elif ciphersuite in CipherSuite.rc4Suites:
            return "rc4"
        elif ciphersuite in CipherSuite.tripleDESSuites:
            return "3des"
        elif ciphersuite in CipherSuite.nullSuites:
            return "null"
        elif ciphersuite in CipherSuite.chacha20Suites:
            return "chacha20-poly1305"
        else:
            return None

    @staticmethod
    def canonicalMacName(ciphersuite):
        """Return the canonical name of the MAC whose number is provided."""
        if ciphersuite in CipherSuite.sha384Suites:
            return "sha384"
        elif ciphersuite in CipherSuite.sha256Suites:
            return "sha256"
        elif ciphersuite in CipherSuite.shaSuites:
            return "sha"
        elif ciphersuite in CipherSuite.md5Suites:
            return "md5"
        else:
            return None


# The following faults are induced as part of testing.  The faultAlerts
# dictionary describes the allowed alerts that may be triggered by these
# faults.
class Fault:
    badUsername = 101
    badPassword = 102
    badA = 103
    clientSrpFaults = list(range(101,104))

    badVerifyMessage = 601
    clientCertFaults = list(range(601,602))

    badPremasterPadding = 501
    shortPremasterSecret = 502
    clientNoAuthFaults = list(range(501,503))

    badB = 201
    serverFaults = list(range(201,202))

    badFinished = 300
    badMAC = 301
    badPadding = 302
    genericFaults = list(range(300,303))

    faultAlerts = {\
        badUsername: (AlertDescription.unknown_psk_identity, \
                      AlertDescription.bad_record_mac),\
        badPassword: (AlertDescription.bad_record_mac,),\
        badA: (AlertDescription.illegal_parameter,),\
        badPremasterPadding: (AlertDescription.bad_record_mac,),\
        shortPremasterSecret: (AlertDescription.bad_record_mac,),\
        badVerifyMessage: (AlertDescription.decrypt_error,),\
        badFinished: (AlertDescription.decrypt_error,),\
        badMAC: (AlertDescription.bad_record_mac,),\
        badPadding: (AlertDescription.bad_record_mac,)
        }

    faultNames = {\
        badUsername: "bad username",\
        badPassword: "bad password",\
        badA: "bad A",\
        badPremasterPadding: "bad premaster padding",\
        shortPremasterSecret: "short premaster secret",\
        badVerifyMessage: "bad verify message",\
        badFinished: "bad finished message",\
        badMAC: "bad MAC",\
        badPadding: "bad padding"
        }
