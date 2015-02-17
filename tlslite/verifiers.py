# Authors:
#   Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

from .constants import CipherSuite, ExtensionType
from .handshakesettings import HandshakeSettings
from .errors import TLSIllegalParameterException

class ServerHelloVerifier(object):
    """
    Class for checking the sanity of received ServerHello message given
    specific settings and clientHello
    """
    def __init__(self, clientHello, settings=None):
        """
        Set the client hello that was used to request the server hello that
        will be tested

        @type clientHello: ClientHello
        @param clientHello: client hello that was sent to server and will be
            base of verification
        @type settings: HandshakeSettings
        @param settings: the security settings to be used for verifying the
            server, will use defaults if not specified
        """
        if settings is None:
            settings = HandshakeSettings()
        self.settings = settings
        self.clientHello = clientHello

    def verify(self, serverHello):
        """
        Check if server hello matches the client hello and is ok for given
        security parameters.

        @type serverHello: ServerHello
        @param serverHello: server hello to test
        @rtype: boolean
        @return: True, exception in case the server hello doesn't pass
            verification
        """
        clientHelloExtensions = self.clientHello.getExtensionsIDs()
        serverHelloExtensions = serverHello.getExtensionsIDs()

        # tlslite doesn't sent the renegotiation info as an extension
        # but as a signaling cipher suite value, so expect a renegotiation
        # info extension even if we didn't send it as an extension
        if CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV in \
                self.clientHello.cipher_suites:
            clientHelloExtensions.append(ExtensionType.renegotiation_info)

        # check if server hello contains only extensions we advertised
        for serverExtID in serverHelloExtensions:
            if serverExtID not in clientHelloExtensions:
                raise TLSIllegalParameterException(\
                        "Extension ID {0} not present in client hello but "
                        "provided by server".format(\
                        serverExtID))

        # check if the server doesn't have duplicate extensions
        if len(serverHelloExtensions) != len(set(serverHelloExtensions)):
            raise TLSIllegalParameterException(\
                    "Duplicate extensions present in server hello")

        return True
