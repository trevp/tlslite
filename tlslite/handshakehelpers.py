# Authors:
#   Karel Srot
#
# See the LICENSE file for legal information regarding use of this file.

"""Class with various handshake helpers."""

from .extensions import PaddingExtension


class HandshakeHelpers(object):
    """
    This class encapsulates helper functions to be used with a TLS handshake.
    """

    @staticmethod
    def alignClientHelloPadding(clientHello):
        """
        Align ClientHello using the Padding extension to 512 bytes at least.

        :param ClientHello clientHello: ClientHello to be aligned
        """
        # Check clientHello size if padding extension should be added
        # we want to add the extension even when using just SSLv3
        # cut-off 4 bytes with the Hello header (ClientHello type + Length)
        clientHelloLength = len(clientHello.write()) - 4
        if 256 <= clientHelloLength <= 511:
            if clientHello.extensions is None:
                clientHello.extensions = []
                # we need to recalculate the size after extension list addition
                # results in extra 2 bytes, equals to
                # clientHelloLength = len(clientHello.write()) - 4
                clientHelloLength += 2
            # we want to get 512 bytes in total, including the padding
            # extension header (4B)
            paddingExtensionInstance = PaddingExtension().create(
                max(512 - clientHelloLength - 4, 0))
            clientHello.extensions.append(paddingExtensionInstance)
