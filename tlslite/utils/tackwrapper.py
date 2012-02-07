# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

try:
    import TACKpy # for accessing, say, SSL_Cert
    from TACKpy import TACK, TACK_Break_Sig, TACK_Extension
    tackpyLoaded = True
except ImportError:
    tackpyLoaded = False